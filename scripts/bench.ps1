param(
    [string]$Peer = "10.7.0.2",
    [int]$Duration = 10,
    [string]$Product = "tunnet",
    [string]$TunnetApi = "http://127.0.0.1:8899",
    [int]$Repeats = 2,
    [int]$Mtu = 0,
    # Independent iperf3 server ports per direction: two simultaneous
    # clients against one default port conflict (single active test per
    # listener). The server side must listen on both ports.
    [int]$ServerPortUp = 5201,
    [int]$ServerPortDown = 5202,
    # Local agent metrics endpoint for per-scenario software-drop deltas
    # (only queried when Product=tunnet; empty otherwise).
    [string]$MetricsUrl = "http://127.0.0.1:9100/metrics"
)

# Tunnet Benchmark v3 — structured, repeatable, hard to lie with.
# Schema (shared with bench.sh): every scenario appends one JSON object per
# line to results.jsonl with fields:
#   {ts, product, scenario, direction, fraction, offered_mbps, actual_mbps,
#    loss_pct, retransmits, latency:{n,p50,p95,p99,p999,max}, path:{...},
#    meta:{...}, note, valid, sw_drops}
# Throughput matrix (TCP 1/4, up/down/bidir with explicit JSON parse),
# loaded-latency sweeps per direction plus full-duplex bidir at fractions
# of independently measured directional capacity (download load uses -R),
# UDP rate x size sweep, warmup + repeats, path-state capture before/after
# every scenario (results flagged on migration). p99.9 only with >=1000
# samples, else null. Latency probes are asynchronous/staggered via a
# runspace pool so every sample window lies inside its load interval (200
# samples: p50/p95/p99 meaningful, p999 null BY DESIGN; idle uses 1200).
# Capacity is the MEDIAN of valid P4 repeats per direction (never a lucky
# maximum); a failed matrix stops the run instead of inventing 50 Mbps.
# "server is busy" listener contention retries boundedly (infrastructure,
# never Tunnet loss). One shared UDP parser (Parse-UdpSummary) reports
# receiver-delivered throughput everywhere; downloads offer against CAP_DOWN.
# Every row carries sw_drops (local scheduler/TUN software-drop deltas, tunnet
# runs only), so one benchmark is self-diagnosing without manual A/B runs.

$ErrorActionPreference = "Continue"

$iperf3 = "$env:USERPROFILE\bin\iperf3\iperf3.exe"
if (-not (Test-Path $iperf3)) {
    $iperf3 = (Get-Command iperf3.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
}
if (-not $iperf3) {
    Write-Host "iperf3.exe not found. Download from: https://github.com/ar51an/iperf3-win-builds/releases" -ForegroundColor Red
    exit 1
}

$ResultsDir = ".\bench-results\$(Get-Date -Format 'yyyyMMdd-HHmmss')-$Product"
New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
$Jsonl = "$ResultsDir\results.jsonl"

function Get-Meta {
    $sha = ""
    try { $sha = (git rev-parse --short HEAD 2>$null).Trim() } catch {}
    $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    return [ordered]@{
        commit = $sha; mtu = $Mtu; os = (Get-CimInstance Win32_OperatingSystem).Caption
        cpu = $cpu; peer = $Peer; duration_s = $Duration
    }
}
$META = Get-Meta
$META_JSON = $META | ConvertTo-Json -Compress

function Get-PathState {
    $state = [ordered]@{ product = $Product; mode = "unknown"; detail = "" }
    if ($Product -eq "tunnet") {
        try {
            $status = Invoke-RestMethod -Uri "$TunnetApi/api/status" -TimeoutSec 5
            $state.mode = "$($status.path_state)"; $state.detail = "$($status.selected_path)"
        } catch { $state.detail = "tunnet api unreachable" }
    } else {
        try {
            $peers = zerotier-cli peers 2>$null
            $state.detail = (($peers | Select-Object -First 6) -join " | ")
            if ($peers -match "DIRECT") { $state.mode = "direct" } elseif ($peers -match "RELAY") { $state.mode = "relay" }
        } catch { $state.detail = "zerotier-cli unavailable" }
    }
    return $state
}

function Write-Row([hashtable]$row) {
    $row["ts"] = (Get-Date -Format o); $row["product"] = $Product; $row["meta"] = $META
    ($row | ConvertTo-Json -Depth 6 -Compress) | Out-File $Jsonl -Append -Encoding utf8
}

function Get-Percentiles([double[]]$Samples) {
    if ($Samples.Count -eq 0) { return $null }
    $s = $Samples | Sort-Object
    function pct([double]$p) { $s[[math]::Min($s.Count - 1, [math]::Floor($p * $s.Count))] }
    $o = [ordered]@{ count = $s.Count; min = [math]::Round($s[0], 2); p50 = [math]::Round((pct 0.50), 2); p95 = [math]::Round((pct 0.95), 2); p99 = [math]::Round((pct 0.99), 2); max = [math]::Round($s[-1], 2) }
    # p99.9 needs >=1000 samples to mean anything.
    if ($s.Count -ge 1000) { $o["p999"] = [math]::Round((pct 0.999), 2) } else { $o["p999"] = $null }
    return $o
}

function Invoke-IperfJson {
    param(
        [string[]]$IperfArgs,
        [string]$OutFile
    )

    # Every invocation captures command + exit code + stdout + stderr +
    # JSON parse status. No generic ERROR: failures carry their cause.
    # Infrastructure condition: a persistent iperf3 listener briefly
    # reports "the server is busy running a test" between scenarios.
    # That is NOT Tunnet packet loss: retry boundedly with a settle delay
    # (serialized per call; callers already run one client per port).
    $errFile = "$OutFile.stderr.txt"
    $argv = @($IperfArgs) + "--json"
    $attempt = 0
    $out = $null
    $exitCode = -1
    $busyRetries = 0
    while ($true) {
        $attempt++
        $out = & $iperf3 @argv 2> $errFile
        $exitCode = $LASTEXITCODE
        $probe = (($out | Out-String) + "`n" + (Get-Content $errFile -Raw -ErrorAction SilentlyContinue))
        if ($probe -match "(?i)server is busy" -and $attempt -le 3) {
            $busyRetries++
            Start-Sleep -Seconds 5
            continue
        }
        break
    }
    $stdout = ($out | Out-String)
    $stdout | Out-File $OutFile -Encoding utf8
    $stderr = ""
    try { $stderr = Get-Content $errFile -Raw -ErrorAction SilentlyContinue } catch {}
    $busyNote = ""
    if ($busyRetries -gt 0) { $busyNote = " (server-busy retried x$busyRetries)" }
    if ([string]::IsNullOrWhiteSpace($stdout)) {
        return [ordered]@{ ok = $false; json = $null; exitCode = $exitCode; error = "empty stdout (exit=$exitCode) stderr=$($stderr.Trim())$busyNote" }
    }
    try {
        $j = $stdout | ConvertFrom-Json
        if ($j.error) {
            return [ordered]@{ ok = $false; json = $j; exitCode = $exitCode; error = "iperf error: $($j.error)$busyNote" }
        }
        return [ordered]@{ ok = $true; json = $j; exitCode = $exitCode; error = "" }
    } catch {
        return [ordered]@{ ok = $false; json = $null; exitCode = $exitCode; error = "JSON parse failed (exit=$exitCode): $($_.Exception.Message) stderr=$($stderr.Trim())$busyNote" }
    }
}

# ONE shared UDP/load summary parser for every scenario (throughput bidir,
# loaded-latency loads, UDP sweep): receiver-delivered throughput is
# `sum_received` (never the sender-side `sum`); loss/jitter/pps come from
# the receiver; a missing receiver summary invalidates the row instead of
# promoting the offer. Returns @{ok, actual, sent, loss, jitter, pps_sent,
# pps_received, error}.
function Parse-UdpSummary($j) {
    try {
        if ($j.error) { return @{ ok = $false; error = "iperf error: $($j.error)" } }
        $recv = $j.end.sum_received
        if ($null -eq $recv) { return @{ ok = $false; error = "no sum_received in iperf JSON" } }
        $send = $j.end.sum
        $sent = $null
        try { $sent = [math]::Round($send.bits_per_second / 1e6, 1) } catch {}
        $actual = [math]::Round($recv.bits_per_second / 1e6, 1)
        $loss = -1; $jitter = $null; $ppsSent = $null; $ppsRecv = $null
        try { $loss = [math]::Round($recv.lost_percent, 2) } catch {}
        try { $jitter = [math]::Round($recv.jitter_ms, 3) } catch {}
        try { $ppsSent = [math]::Round($send.packets / $Duration, 0) } catch {}
        try { $ppsRecv = [math]::Round($recv.packets_received / $Duration, 0) } catch {}
        if ($null -eq $ppsRecv) { try { $ppsRecv = [math]::Round($recv.packets / $Duration, 0) } catch {} }
        return @{ ok = $true; actual = $actual; sent = $sent; loss = $loss; jitter = $jitter
            pps_sent = $ppsSent; pps_received = $ppsRecv; error = "" }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}

# Scenario telemetry: low-cardinality software-drop counters scraped from
# the local agent before/after each scenario (Product=tunnet only). The
# delta rides the result row, so one benchmark is self-diagnosing: any
# internal Tunnet drop during a scenario shows up without manual A/B runs.
# True network/outer-QUIC loss stays distinguishable (no counter moves).
function Get-SwDrops {
    $zero = [ordered]@{ sched = 0.0; dropped = 0.0; tun_write_drop = 0.0 }
    if ($Product -ne "tunnet") { return $zero }
    try {
        $text = Invoke-RestMethod -Uri $MetricsUrl -TimeoutSec 5
        if ($text -isnot [string]) { return $zero }
        $out = [ordered]@{ sched = 0.0; dropped = 0.0; tun_write_drop = 0.0 }
        foreach ($line in ($text -split "`n")) {
            if ($line -match "^tunnet_sched_drops_total\{[^}]*\}\s+([0-9.eE+-]+)") { $out.sched += [double]$Matches[1] }
            elseif ($line -match "^tunnet_dropped_packets_total\{[^}]*\}\s+([0-9.eE+-]+)") { $out.dropped += [double]$Matches[1] }
            elseif ($line -match "^tunnet_tun_write_queue_drop_total\s+([0-9.eE+-]+)") { $out.tun_write_drop += [double]$Matches[1] }
        }
        return $out
    } catch { return $zero }
}

function Diff-SwDrops($Before, $After) {
    return [ordered]@{
        sched = [math]::Round($After.sched - $Before.sched, 0)
        dropped = [math]::Round($After.dropped - $Before.dropped, 0)
        tun_write_drop = [math]::Round($After.tun_write_drop - $Before.tun_write_drop, 0)
    }
}

# High-frequency latency probe: asynchronous/staggered ICMP via a runspace
# pool so the COMPLETE sample window lies inside the load interval.
# Sequential Test-Connection (200 x ~85ms RTT ≈ 17s) outlasts a 10s load —
# most samples would land after iperf stopped. Here $Count probes start
# staggered $GapMs apart across at most 32 concurrent runspaces; each single
# echo takes ~one RTT, so the window spans Count*GapMs + RTT.
function Measure-Latency([int]$Count, [int]$GapMs) {
    $pool = [runspacefactory]::CreateRunspacePool(1, 32)
    $pool.Open()
    try {
        $handles = @()
        for ($i = 0; $i -lt $Count; $i++) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($Target)
                try {
                    $r = Test-Connection -ComputerName $Target -Count 1 -ErrorAction SilentlyContinue
                    if ($r) { return [double]$r.Latency }
                } catch {}
                return $null
            }).AddArgument($Peer)
            $handles += [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
            if ($GapMs -gt 0 -and $i -lt $Count - 1) { Start-Sleep -Milliseconds $GapMs }
        }
        $samples = @()
        foreach ($h in $handles) {
            try {
                $res = $h.PS.EndInvoke($h.Handle)
                foreach ($v in $res) { if ($null -ne $v) { $samples += [double]$v } }
            } catch {}
            $h.PS.Dispose()
        }
        return Get-Percentiles $samples
    } finally {
        $pool.Close()
        $pool.Dispose()
    }
}

Write-Host "=== Tunnet Benchmark v3 ($Product) ===" -ForegroundColor Cyan
Write-Host "Peer: $Peer | Duration: ${Duration}s | Repeats: $Repeats | Results: $ResultsDir"

# --- connectivity + warmup ---
Write-Host "[0] Connectivity + warmup..." -ForegroundColor Yellow
$ping = Test-Connection -ComputerName $Peer -Count 4 -ErrorAction SilentlyContinue
if (-not $ping) { Write-Host "  FAIL: $Peer unreachable" -ForegroundColor Red; exit 1 }
& $iperf3 -c $Peer -p $ServerPortUp -t 5 -P 2 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAIL: warmup iperf3 exited $LASTEXITCODE (is the server listening on port $ServerPortUp?)" -ForegroundColor Red
    exit 1
}
Write-Host "  OK, warmed up"

# --- idle latency: 1200 samples for real p99.9 ---
Write-Host "[1] Idle latency (1200 samples)..." -ForegroundColor Yellow
$idle = Measure-Latency 1200 5
Write-Host "  idle: p50=$($idle.p50)ms p95=$($idle.p95)ms p99=$($idle.p99)ms p999=$($idle.p999)ms max=$($idle.max)ms"
Write-Row @{ scenario = "idle"; direction = "none"; path = (Get-PathState); latency = $idle }

# --- throughput matrix with repeats; explicit bidir parse ---
Write-Host "[2] Throughput matrix..." -ForegroundColor Yellow
$tpCases = @(
    @{ name = "tcp-up-1"; args = @("-c", $Peer, "-p", "$ServerPortUp", "-t", "$Duration", "-P", "1"); dir = "up" },
    @{ name = "tcp-up-4"; args = @("-c", $Peer, "-p", "$ServerPortUp", "-t", "$Duration", "-P", "4"); dir = "up" },
    @{ name = "tcp-down-1"; args = @("-c", $Peer, "-p", "$ServerPortDown", "-t", "$Duration", "-P", "1", "-R"); dir = "down" },
    @{ name = "tcp-down-4"; args = @("-c", $Peer, "-p", "$ServerPortDown", "-t", "$Duration", "-P", "4", "-R"); dir = "down" }
)
$cap = @{ up = 0.0; down = 0.0 }
$capVals = @{ up = @(); down = @() }
foreach ($rep in 1..$Repeats) {
    foreach ($c in $tpCases) {
        $pathBefore = Get-PathState
        $sw0 = Get-SwDrops
        $r = Invoke-IperfJson -IperfArgs $c.args -OutFile "$ResultsDir\$($c.name)-r$rep.json"
        if ($r.ok) {
            $j = $r.json
            $mbps = [math]::Round($j.end.sum_received.bits_per_second / 1e6, 1)
            $retr = 0; try { $retr = [int]$j.end.sum_sent.retransmits } catch {}
            $sentMbps = 0; try { $sentMbps = [math]::Round($j.end.sum_sent.bits_per_second / 1e6, 1) } catch {}
            Write-Host "  $($c.name) r$rep : $mbps Mbps (retr=$retr)"
            if ($c.name -like "*-4") {
                $capVals[$c.dir] += $mbps
            }
            Write-Row @{ scenario = $c.name; direction = $c.dir; repeat = $rep; offered_mbps = $null
                actual_mbps = $mbps; sent_mbps = $sentMbps; retransmits = $retr; path = $pathBefore; valid = $true
                sw_drops = (Diff-SwDrops $sw0 (Get-SwDrops)) }
        } else {
            Write-Host "  $($c.name) r$rep : FAILED: $($r.error)" -ForegroundColor Red
            Write-Row @{ scenario = $c.name; direction = $c.dir; repeat = $rep; offered_mbps = $null
                actual_mbps = -1; sent_mbps = -1; retransmits = -1; path = $pathBefore
                note = "TCP FAILED: $($r.error)"; valid = $false
                sw_drops = (Diff-SwDrops $sw0 (Get-SwDrops)) }
        }
    }
    # Bidirectional: parse both directions explicitly (v2 bug: bidir was unread).
    $pathBefore = Get-PathState
    $sw0 = Get-SwDrops
    $r = Invoke-IperfJson -IperfArgs @(
        "-c", $Peer,
        "-p", "$ServerPortUp",
        "-t", "$Duration",
        "-P", "4",
        "--bidir"
    ) -OutFile "$ResultsDir\tcp-bidir-r$rep.json"
    if ($r.ok) {
        $j = $r.json
        # iperf3 --bidir JSON: sum_sent/sum_received cover the client direction;
        # server-side streams appear under server_output_text; parse both.
        $upMbps = 0; $downMbps = 0; $retr = 0
        try { $upMbps = [math]::Round($j.end.sum_sent.bits_per_second / 1e6, 1) } catch {}
        try { $downMbps = [math]::Round($j.end.sum_received.bits_per_second / 1e6, 1) } catch {}
        try { $retr = [int]$j.end.sum_sent.retransmits } catch {}
        try {
            foreach ($s in $j.server_output_text -split "`n") {
                if ($s -match "receiver" -and $s -match "([0-9.]+)\s+Mbits/sec") {
                    $downMbps = [math]::Round([double]$Matches[1], 1)
                }
            }
        } catch {}
        Write-Host "  tcp-bidir r$rep : up=${upMbps}Mbps down=${downMbps}Mbps (retr=$retr)"
        Write-Row @{ scenario = "tcp-bidir"; direction = "bidir"; repeat = $rep
            actual_mbps = $upMbps; down_mbps = $downMbps; retransmits = $retr; path = $pathBefore; valid = $true
            sw_drops = (Diff-SwDrops $sw0 (Get-SwDrops)) }
    } else {
        Write-Host "  tcp-bidir r$rep : FAILED: $($r.error)" -ForegroundColor Red
        Write-Row @{ scenario = "tcp-bidir"; direction = "bidir"; repeat = $rep
            actual_mbps = -1; down_mbps = -1; retransmits = -1; path = $pathBefore
            note = "TCP FAILED: $($r.error)"; valid = $false
            sw_drops = (Diff-SwDrops $sw0 (Get-SwDrops)) }
    }
}
# No invented capacity: if the TCP matrix failed, every capacity-dependent
# sweep would be built on fiction. Stop loudly instead. Capacity is the
# MEDIAN of the valid P4 repeats per direction (never one lucky maximum),
# and all requested repeats must complete (server-busy retries excepted —
# those are infrastructure, retried inside the runner).
function Get-Median([double[]]$Values) {
    if ($Values.Count -eq 0) { return 0.0 }
    $s = $Values | Sort-Object
    $n = $s.Count
    if ($n % 2 -eq 1) { return $s[[math]::Floor($n / 2)] }
    return ($s[$n / 2 - 1] + $s[$n / 2]) / 2.0
}
$cap.up = [math]::Round((Get-Median $capVals.up), 1)
$cap.down = [math]::Round((Get-Median $capVals.down), 1)
if ($cap.up -eq 0 -or $cap.down -eq 0) {
    Write-Host "  FATAL: TCP capacity measurement failed (up=$($cap.up) down=$($cap.down)). Refusing to invent 50 Mbps; fix the TCP path first." -ForegroundColor Red
    Write-Host "Results so far: $Jsonl" -ForegroundColor Yellow
    exit 1
}
Write-Host "  measured capacity: up=$($cap.up)Mbps down=$($cap.down)Mbps"

# --- loaded latency per direction at fractions of directional capacity ---
# Staggered parallel probes: 200 samples across ~80% of the load window so
# every sample lands while iperf runs (see Measure-Latency). p50/p95/p99 are
# meaningful; p999 stays null by design. Bash uses 1000 fast pings.
Write-Host "[3] Loaded-latency sweeps (200 samples/dir: p99 max, p999 null)..." -ForegroundColor Yellow
$latGapMs = [math]::Max(1, [int]($Duration * 800 / 200))
$fractions = @(0.25, 0.50, 0.75, 0.90, 1.00, 1.10)
$dirs = @(
    @{ name = "upload"; cap = $cap.up; port = $ServerPortUp },
    @{ name = "download"; cap = $cap.down; port = $ServerPortDown }
)
foreach ($d in $dirs) {
    foreach ($f in $fractions) {
        $rate = [math]::Round($d.cap * $f, 1)
        $pct = [int]($f * 100)
        $pathBefore = Get-PathState
        $sw0 = Get-SwDrops
        # Direction-specific load: download MUST use -R (server sends), or
        # the "download" test silently measures upload load.
        $isDown = ($d.name -eq "download")
        $port = $d.port
        $loadFile = "$ResultsDir\load-$($d.name)-$F.json"
        $job = Start-Job -ScriptBlock {
            param($exe, $p, $dd, $r, $rev, $pp, $out)
            # Same server-busy retry as Invoke-IperfJson (infrastructure, not loss).
            $attempt = 0
            while ($true) {
                $attempt++
                if ($rev) { & $exe -c $p -p $pp -t $dd -u -b "${r}M" -R --json 2>&1 | Out-File $out -Encoding utf8 }
                else { & $exe -c $p -p $pp -t $dd -u -b "${r}M" --json 2>&1 | Out-File $out -Encoding utf8 }
                $combined = Get-Content $out -Raw -ErrorAction SilentlyContinue
                if ($combined -match "(?i)server is busy" -and $attempt -le 3) { Start-Sleep -Seconds 5; continue }
                break
            }
            if ($LASTEXITCODE -ne 0) { "EXIT:$LASTEXITCODE" | Out-File "$out.exit" -Encoding utf8 }
        } -ArgumentList $iperf3, $Peer, $Duration, $rate, $isDown, $port, $loadFile
        Start-Sleep 2
        $lat = Measure-Latency 200 $latGapMs
        $null = Receive-Job $job -Wait -AutoRemoveJob
        $loadJson = ""
        $jobExit = $null
        if (Test-Path $loadFile) { $loadJson = Get-Content $loadFile -Raw }
        if (Test-Path "$loadFile.exit") { $jobExit = (Get-Content "$loadFile.exit" -Raw).Trim() }
        $valid = $true
        $loadErr = ""
        if ([string]::IsNullOrWhiteSpace($loadJson)) { $valid = $false; $loadErr = "no load output (job crashed?)" }
        if ($jobExit) { $valid = $false; $loadErr = "load client $jobExit" }
        try {
            if ([string]::IsNullOrWhiteSpace($loadJson)) { throw "empty load output" }
            $lj = $loadJson | ConvertFrom-Json
            # Shared parser: receiver-delivered, never end.sum.
            $ps = Parse-UdpSummary $lj
            if (-not $ps.ok) { throw $ps.error }
            $actual = $ps.actual; $loss = $ps.loss
        } catch { $actual = -1; $loss = -1; $valid = $false; if (-not $loadErr) { $loadErr = $_.Exception.Message } }
        $pathAfter = Get-PathState
        $note = ""
        if ($pathBefore.mode -ne $pathAfter.mode) { $note = "PATH CHANGED mid-run; result flagged" }
        if ($actual -gt 0 -and $actual -lt $rate * 0.7 -and $f -le 1.0) { $note += " under-delivered load" }
        if (-not $valid) { $note += " LOAD FAILED ($loadErr): row invalid, values are placeholders" }
        Write-Host "  $($d.name) ${pct}%: actual=${actual}Mbps loss=${loss}% p50=$($lat.p50) p95=$($lat.p95) p99=$($lat.p99) max=$($lat.max) valid=$valid $note"
        Write-Row @{ scenario = "loaded-latency"; direction = $d.name; fraction = $f
            offered_mbps = $rate; actual_mbps = $actual; loss_pct = $loss
            latency = $lat; path = $pathBefore; path_after = $pathAfter; note = $note.Trim(); valid = $valid
            sw_drops = (Diff-SwDrops $sw0 (Get-SwDrops)) }
    }
}

# --- bidirectional loaded latency: full-duplex UDP at fractions ---
# Up and down loads run on SEPARATE server ports: two clients against one
# listener conflict on a normal iperf3 server. A bidir row is only valid
# when BOTH directions ran; failures mark valid=false explicitly.
Write-Host "  bidir (full duplex, 200 samples: p99 max, p999 null)..." -ForegroundColor Yellow
foreach ($f in @(0.25, 0.50, 0.75, 0.90, 1.00)) {
    $rateUp = [math]::Round($cap.up * $f, 1)
    $rateDown = [math]::Round($cap.down * $f, 1)
    $pct = [int]($f * 100)
    $pathBefore = Get-PathState
    $sw0 = Get-SwDrops
    $upFile = "$ResultsDir\load-bidi-$f-up.json"
    $downFile = "$ResultsDir\load-bidi-$f-down.json"
    $jobUp = Start-Job -ScriptBlock {
        param($exe, $p, $dd, $r, $pp, $out)
        $attempt = 0
        while ($true) {
            $attempt++
            & $exe -c $p -p $pp -t $dd -u -b "${r}M" --json 2>&1 | Out-File $out -Encoding utf8
            $combined = Get-Content $out -Raw -ErrorAction SilentlyContinue
            if ($combined -match "(?i)server is busy" -and $attempt -le 3) { Start-Sleep -Seconds 5; continue }
            break
        }
        if ($LASTEXITCODE -ne 0) { "EXIT:$LASTEXITCODE" | Out-File "$out.exit" -Encoding utf8 }
    } -ArgumentList $iperf3, $Peer, $Duration, $rateUp, $ServerPortUp, $upFile
    $jobDown = Start-Job -ScriptBlock {
        param($exe, $p, $dd, $r, $pp, $out)
        $attempt = 0
        while ($true) {
            $attempt++
            & $exe -c $p -p $pp -t $dd -u -b "${r}M" -R --json 2>&1 | Out-File $out -Encoding utf8
            $combined = Get-Content $out -Raw -ErrorAction SilentlyContinue
            if ($combined -match "(?i)server is busy" -and $attempt -le 3) { Start-Sleep -Seconds 5; continue }
            break
        }
        if ($LASTEXITCODE -ne 0) { "EXIT:$LASTEXITCODE" | Out-File "$out.exit" -Encoding utf8 }
    } -ArgumentList $iperf3, $Peer, $Duration, $rateDown, $ServerPortDown, $downFile
    Start-Sleep 2
    $lat = Measure-Latency 200 $latGapMs
    $null = Receive-Job $jobUp -Wait -AutoRemoveJob
    $null = Receive-Job $jobDown -Wait -AutoRemoveJob
    $upJson = ""; $downJson = ""
    if (Test-Path $upFile) { $upJson = Get-Content $upFile -Raw }
    if (Test-Path $downFile) { $downJson = Get-Content $downFile -Raw }
    $exitUp = $null; $exitDown = $null
    if (Test-Path "$upFile.exit") { $exitUp = (Get-Content "$upFile.exit" -Raw).Trim() }
    if (Test-Path "$downFile.exit") { $exitDown = (Get-Content "$downFile.exit" -Raw).Trim() }
    $actualUp = -1; $lossUp = -1; $actualDown = -1; $lossDown = -1
    $errUp = $null; $errDown = $null
    if ([string]::IsNullOrWhiteSpace($upJson)) { $errUp = "no up-load output (job crashed?)" }
    if ($exitUp) { $errUp = "up-load client $exitUp" }
    if ([string]::IsNullOrWhiteSpace($downJson)) { $errDown = "no down-load output (job crashed?)" }
    if ($exitDown) { $errDown = "down-load client $exitDown" }
    if (-not $errUp) {
        try {
            $uj = $upJson | ConvertFrom-Json
            $ps = Parse-UdpSummary $uj
            if (-not $ps.ok) { throw $ps.error }
            $actualUp = $ps.actual; $lossUp = $ps.loss
        } catch { $errUp = $_.Exception.Message }
    }
    if (-not $errDown) {
        try {
            $dj = $downJson | ConvertFrom-Json
            $ps = Parse-UdpSummary $dj
            if (-not $ps.ok) { throw $ps.error }
            $actualDown = $ps.actual; $lossDown = $ps.loss
        } catch { $errDown = $_.Exception.Message }
    }
    $pathAfter = Get-PathState
    $note = ""
    if ($pathBefore.mode -ne $pathAfter.mode) { $note = "PATH CHANGED mid-run; result flagged" }
    if ($actualUp -gt 0 -and $actualUp -lt $rateUp * 0.7 -and $f -le 1.0) { $note += " under-delivered up load" }
    if ($actualDown -gt 0 -and $actualDown -lt $rateDown * 0.7 -and $f -le 1.0) { $note += " under-delivered down load" }
    $valid = ($null -eq $errUp) -and ($null -eq $errDown)
    if ($errUp) { $note += " BIDIR INVALID: up load failed ($errUp)" }
    if ($errDown) { $note += " BIDIR INVALID: down load failed ($errDown)" }
    Write-Host "  bidir ${pct}%: up=${actualUp}Mbps loss=${lossUp}% down=${actualDown}Mbps loss=${lossDown}% p50=$($lat.p50) p95=$($lat.p95) p99=$($lat.p99) valid=$valid $note"
    Write-Row @{ scenario = "loaded-latency"; direction = "bidir"; fraction = $f
        offered_up_mbps = $rateUp; offered_down_mbps = $rateDown
        actual_up_mbps = $actualUp; actual_down_mbps = $actualDown
        loss_up_pct = $lossUp; loss_down_pct = $lossDown
        latency = $lat; path = $pathBefore; path_after = $pathAfter; note = $note.Trim(); valid = $valid
        sw_drops = (Diff-SwDrops $sw0 (Get-SwDrops)) }
}

# --- UDP sweep: rates x sizes x directions, sender vs receiver split ---
# Sizes span single-frame (512, 900) and segmented (1200, 1460, 2700)
# dataplane behavior; both directions run so upload/download asymmetries
# (like the Linux→Windows collapse) show up with numbers, not vibes.
# `actual_mbps` is RECEIVER-side delivered throughput (sum_received), never
# the sender offer: iperf3 UDP `sum` can be sender-side, and misreading it
# once reported "actual=50Mbps loss=92%" for ~3.8 Mbps delivered.
Write-Host "[4] UDP sweep (sizes x directions)..." -ForegroundColor Yellow
$udpDirs = @(
    @{ name = "up"; port = $ServerPortUp; extra = @() },
    @{ name = "down"; port = $ServerPortDown; extra = @("-R") }
)
foreach ($ud in $udpDirs) {
    # Directional capacity: downloads offer against CAP_DOWN, uploads
    # against CAP_UP (offering down at the up rate over- or under-drives).
    $dirCap = $cap.up
    if ($ud.name -eq "down") { $dirCap = $cap.down }
    foreach ($f in @(0.25, 0.50, 1.00)) {
        $rate = [math]::Round($dirCap * $f, 1)
        foreach ($len in @(512, 900, 1200, 1460, 2700)) {
            $udpArgs = @(
                "-c", $Peer,
                "-p", "$($ud.port)",
                "-u",
                "-b", "${rate}M",
                "-l", "$len",
                "-t", "$Duration"
            ) + $ud.extra
            $sw0 = Get-SwDrops
            $r = Invoke-IperfJson -IperfArgs $udpArgs -OutFile "$ResultsDir\udp-$($ud.name)-${rate}M-${len}B.json"
            if ($r.ok) {
                $j = $r.json
                # Shared parser: sender offer vs receiver delivered, split
                # explicitly; a missing receiver summary invalidates the row.
                $ps = Parse-UdpSummary $j
                if (-not $ps.ok) { throw $ps.error }
                $sentMbps = $ps.sent
                $del = $ps.actual
                $ppsSent = $ps.pps_sent; $ppsRecv = $ps.pps_received
                $loss = $ps.loss
                $jitter = $ps.jitter
                Write-Host ("  $($ud.name) offered={0}Mbps sent={1}Mbps delivered={2}Mbps pps_sent={3} pps_recv={4} loss={5}% jitter={6}ms len={7}B" -f $rate, $sentMbps, $del, $ppsSent, $ppsRecv, $loss, $jitter, $len)
                Write-Row @{ scenario = "udp"; direction = $ud.name; offered_mbps = $rate; packet_len = $len
                    sent_mbps = $sentMbps; actual_mbps = $del; pps_sent = $ppsSent; pps_received = $ppsRecv
                    loss_pct = $loss; jitter_ms = $jitter; path = (Get-PathState); valid = $true
                    sw_drops = (Diff-SwDrops $sw0 (Get-SwDrops)) }
            } else {
                Write-Host "  $($ud.name) offered=${rate}Mbps len=${len}B : FAILED: $($r.error)" -ForegroundColor Red
                Write-Row @{ scenario = "udp"; direction = $ud.name; offered_mbps = $rate; packet_len = $len
                    sent_mbps = -1; actual_mbps = -1; pps_sent = $null; pps_received = $null
                    loss_pct = -1; jitter_ms = $null; path = (Get-PathState)
                    note = "UDP FAILED: $($r.error)"; valid = $false
                    sw_drops = (Diff-SwDrops $sw0 (Get-SwDrops)) }
            }
        }
    }
}

Write-Host "`nResults: $ResultsDir\results.jsonl (shared schema)" -ForegroundColor Green
