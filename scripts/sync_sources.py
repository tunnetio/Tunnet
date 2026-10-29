import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import uuid


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=Path(__file__).resolve().parents[1]).decode().split("\0")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--deleted-source", action="append", default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=root, check=True, stdout=subprocess.DEVNULL)
    names = set(git("ls-files", "-z")) | set(git("ls-files", "--others", "--exclude-standard", "-z"))
    protected = {".git", "target", "node_modules", ".audit", ".secrets", "bench-results", "__pycache__"}
    files = sorted(name for name in names if name and not (set(Path(name).parts) & protected)
                   and Path(name).name not in {".env", ".env.local"} and (root / name).is_file())
    deleted = sorted(set(name for name in git("diff", "HEAD", "--name-only", "--diff-filter=D", "-z") if name)
                     | set(args.deleted_source))
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}
    audit = root / ".audit"
    audit.mkdir(exist_ok=True)
    (audit / "source-manifest.json").write_text(json.dumps(hashes, indent=2) + "\n")
    remote_archive = f"/tmp/tunnet-source-{uuid.uuid4().hex}.tar"
    if not args.verify_only:
        archive = audit / "source.tar"
        with tarfile.open(archive, "w") as output:
            for name in files:
                output.add(root / name, arcname=name, recursive=False)
        subprocess.run(["scp", str(archive), f"{args.host}:{remote_archive}"], check=True)
    remote = r'''
import hashlib, json, pathlib, sys, tarfile
request = json.load(sys.stdin)
root = (pathlib.Path.home() / 'projects' / 'Tunnet').resolve()
if not (root / '.git').exists():
    raise SystemExit('remote project is not a checkout')
def target(name):
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts or set(relative.parts) & {'.git', 'target', '.secrets', 'node_modules'}:
        raise SystemExit('unsafe source path')
    destination = root.joinpath(*relative.parts)
    if not destination.resolve().is_relative_to(root):
        raise SystemExit('source path escapes project')
    return destination
if request['archive']:
    with tarfile.open(request['archive']) as archive:
        for member in archive.getmembers():
            target(member.name)
            if not member.isfile():
                raise SystemExit('non-regular source archive entry')
        archive.extractall(root, filter='data')
    for name in request['deleted']:
        path = target(name)
        if path.is_file():
            path.unlink()
    pathlib.Path(request['archive']).unlink()
different = []
for name, expected in request['hashes'].items():
    path = target(name)
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    if actual != expected:
        different.append(name)
remaining_deleted = [name for name in request['deleted'] if target(name).exists()]
result = {'root': str(root), 'verified_files': len(request['hashes']), 'mismatches': different, 'undeleted_sources': remaining_deleted}
print(json.dumps(result))
if different or remaining_deleted:
    raise SystemExit(1)
'''
    payload = {"archive": None if args.verify_only else remote_archive, "hashes": hashes, "deleted": deleted}
    result = subprocess.run(["ssh", args.host, "python3 -c " + shlex.quote(remote)], input=json.dumps(payload),
                            text=True, capture_output=True)
    print(result.stdout, end="")
    if result.returncode:
        print(result.stderr, file=__import__("sys").stderr, end="")
    result.check_returncode()
    (audit / "source-verification.json").write_text(result.stdout)


if __name__ == "__main__":
    main()
