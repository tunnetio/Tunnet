import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import threading
import time
import urllib.request


def sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def command(argv, timeout=30):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as error:
        decode = lambda value: value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        return {"argv": argv, "exit_code": -1, "stdout": decode(error.stdout),
                "stderr": decode(error.stderr), "timed_out_seconds": timeout}
    return {"argv": argv, "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def service():
    if os.name == "nt":
        script = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $s=Get-CimInstance Win32_Service -Filter \"Name='tunnet'\"; if($s.State -ne 'Running'){throw 'Tunnet service is not running'}; $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$s.ProcessId); @{pid=$s.ProcessId;executable=$p.ExecutablePath;service_command=$s.PathName}|ConvertTo-Json -Compress"
        result = command(["powershell", "-NoProfile", "-Command", script])
        if result["exit_code"]:
            raise RuntimeError(result["stderr"])
        return json.loads(result["stdout"])
    result = command(["systemctl", "show", "tunnet.service", "-p", "MainPID", "-p", "ActiveState"])
    fields = dict(line.split("=", 1) for line in result["stdout"].splitlines() if "=" in line)
    if result["exit_code"] or fields.get("ActiveState") != "active" or fields.get("MainPID") == "0":
        raise RuntimeError("Tunnet service is not active")
    pid = int(fields["MainPID"])
    return {"pid": pid, "executable": str(Path(f"/proc/{pid}/exe").resolve(strict=True))}


def metrics(url):
    request = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with request.open(url, timeout=5) as response:
        return response.read().decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", required=True)
    parser.add_argument("--local", required=True)
    parser.add_argument("--role", choices=["windows", "linux"], required=True)
    parser.add_argument("--iperf", default="iperf3")
    parser.add_argument("--cli", required=True)
    parser.add_argument("--expected-daemon-sha256", required=True)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--source-verification", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seconds", default=30, type=int)
    parser.add_argument("--repeats", default=3, type=int)
    parser.add_argument("--port", default=5201, type=int)
    parser.add_argument("--metrics-port", default=9100, type=int)
    args = parser.parse_args()
    for address in [args.peer, args.local]:
        if ipaddress.ip_address(address).version != 4:
            parser.error("the current matrix requires IPv4 overlay addresses")
    if not 10 <= args.seconds <= 300 or not 1 <= args.repeats <= 10:
        parser.error("seconds must be 10..300 and repeats 1..10")
    if not 1 <= args.port <= 65535 or not 1 <= args.metrics_port <= 65535:
        parser.error("invalid port")
    if (args.role == "windows") != (os.name == "nt"):
        parser.error("role must match the operating system")
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(args.source_manifest.read_text())
    verified = json.loads(args.source_verification.read_text())
    if verified["mismatches"] or verified["undeleted_sources"] or verified["verified_files"] != len(manifest):
        raise RuntimeError("source synchronization did not pass")
    for name, expected in manifest.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or sha256(path) != expected:
            raise RuntimeError(f"source changed after verification: {name}")
    before = service()
    before["sha256"] = sha256(before["executable"])
    if before["sha256"].lower() != args.expected_daemon_sha256.lower():
        raise RuntimeError("running service does not match the checked release daemon")
    args.output.mkdir(parents=True, exist_ok=False)

    def save(name, value):
        (args.output / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    save("provenance.json", {"schema_version": 1, "platform": platform.platform(),
         "local_overlay": args.local, "peer_overlay": args.peer, "service": before,
         "source_manifest_sha256": sha256(args.source_manifest), "source_verification": verified,
         "iperf_version": command([args.iperf, "--version"]),
         "cli_status": command([args.cli, "status", "--peers", "--json"]),
         "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    route_command = ["powershell", "-NoProfile", "-Command",
                     f"Find-NetRoute -RemoteIPAddress '{args.peer}' | Format-List *; Get-NetIPInterface | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,NlMtu | Format-Table"] if os.name == "nt" else ["ip", "route", "get", args.peer]
    save("overlay-route.json", command(route_command))
    save("diag-initial.json", command([args.cli, "diag", "--json"]))
    urls = {"local": f"http://127.0.0.1:{args.metrics_port}/metrics",
            "peer": f"http://{args.peer}:{args.metrics_port}/metrics"}
    for side, url in urls.items():
        (args.output / f"{side}-metrics-initial.txt").write_text(metrics(url))
    ping_args = ["ping", "-n", "1", "-w", "2000"] if os.name == "nt" else ["ping", "-n", "-c", "1", "-W", "2"]
    save("idle-ping.json", [command([*ping_args, args.peer], timeout=5) for _ in range(10)])
    rows = []
    for repeat in range(1, args.repeats + 1):
        for reverse in [False, True]:
            source = "linux" if args.role == "windows" and reverse else "windows" if args.role == "linux" and reverse else args.role
            destination = "linux" if source == "windows" else "windows"
            direction = f"{source}_to_{destination}"
            for kind, value in [("tcp", 1), ("tcp", 8), ("udp", 20), ("udp", 50)]:
                label = f"r{repeat}-{direction}-{kind}-{value}"
                argv = [args.iperf, "-c", args.peer, "-B", args.local, "-p", str(args.port),
                        "-t", str(args.seconds), "-O", "3", "-i", "1", "--json", "--get-server-output"]
                argv += ["-P", str(value)] if kind == "tcp" else ["-u", "-b", f"{value}M", "-l", "1100"]
                if reverse:
                    argv.append("-R")
                for side, url in urls.items():
                    (args.output / f"{label}-{side}-before.txt").write_text(metrics(url))
                ping_samples = []
                transport_samples = []
                stop = threading.Event()

                def sample():
                    while not stop.is_set():
                        ping_samples.append({"elapsed_seconds": time.monotonic() - started,
                                             **command([*ping_args, args.peer], timeout=5)})
                        transport_samples.append({"elapsed_seconds": time.monotonic() - started,
                                                  **command([args.cli, "diag", "--json"], timeout=5)})
                        if os.name != "nt":
                            transport_samples.append({"elapsed_seconds": time.monotonic() - started,
                                **command(["ss", "-tin", f"( sport = :{args.port} or dport = :{args.port} )"], timeout=5)})
                        stop.wait(1)

                started = time.monotonic()
                observer = threading.Thread(target=sample)
                observer.start()
                try:
                    result = command(argv, timeout=args.seconds + 45)
                finally:
                    stop.set()
                    observer.join()
                    save(f"{label}-ping.json", ping_samples)
                    save(f"{label}-transport.json", transport_samples)
                save(f"{label}-process.json", result)
                (args.output / f"{label}.json").write_text(result["stdout"], encoding="utf-8")
                document = json.loads(result["stdout"])
                if result["exit_code"] or document.get("error"):
                    raise RuntimeError(f"{label} failed; inspect saved process output")
                receiver = document["end"].get("sum_received", document["end"].get("sum", {}))
                row = {"direction": direction, "protocol": kind, "streams_or_mbps": value,
                       "repeat": repeat, "receiver_mbps": receiver["bits_per_second"] / 1e6,
                       "retransmits": document["end"].get("sum_sent", {}).get("retransmits"),
                       "loss_percent": receiver.get("lost_percent"), "jitter_ms": receiver.get("jitter_ms")}
                rows.append(row)
                save("results.json", rows)
                for side, url in urls.items():
                    (args.output / f"{label}-{side}-after.txt").write_text(metrics(url))
                if service() != {key: value for key, value in before.items() if key != "sha256"}:
                    raise RuntimeError("service process changed during measurement")
                print(json.dumps(row), flush=True)
    after = service()
    after["sha256"] = sha256(after["executable"])
    save("service-after.json", after)
    if after != before:
        raise RuntimeError("running daemon changed during measurement")
    if any(sha256(root / name) != expected for name, expected in manifest.items()):
        raise RuntimeError("source changed during measurement")
    save("medians.json", [{"direction": direction, "protocol": kind, "streams_or_mbps": value,
          "receiver_mbps": statistics.median(row["receiver_mbps"] for row in rows
              if (row["direction"], row["protocol"], row["streams_or_mbps"]) == (direction, kind, value))}
          for direction, kind, value in sorted({(row["direction"], row["protocol"], row["streams_or_mbps"]) for row in rows})])


if __name__ == "__main__":
    main()
