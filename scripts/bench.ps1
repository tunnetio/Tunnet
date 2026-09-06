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
    [int]$ServerPortDown = 5202
)

# Tunnet Benchmark v3 — structured, repeatable, hard to lie with.
# Schema (shared with bench.sh): every scenario appends one JSON object per
# line to results.jsonl with fields:
#   {ts, product, scenario, direction, fraction, offered_mbps, actual_mbps,
#    loss_pct, retransmits, latency:{n,p50,p95,p99,p999,max}, path:{...},
#    meta:{...}, note, valid}
# Throughput matrix (TCP 1/4, up/down/bidir with explicit JSON parse),
# loaded-latency sweeps per direction plus full-duplex bidir at fractions
# of independently measured directional capacity (download load uses -R),
# UDP rate x size sweep, warmup + repeats, path-state capture before/after
# every scenario (results flagged on migration). p99.9 only with >=1000
# samples, else null. Loaded scenarios use 200 Test-Connection samples:
# p50/p95/p99 are meaningful, p999 is null BY DESIGN (1000+ ICMP echoes per
# fraction via Test-Connection would take minutes; Bash uses 1000 fast
# pings for real p99.9 — see bench.sh). Failed loads mark valid=false.

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

function Invoke-IperfJson([string]$Args, [string]$OutFile) {
    # Every invocation captures command + exit code + stdout + stderr +
    # JSON parse status. No generic ERROR: failures carry their cause.
    $errFile = "$OutFile.stderr.txt"
    $out = & $iperf3 ($Args.Split(" ") + "--json") 2> $errFile
    $exitCode = $LASTEXITCODE
    $stdout = ($out | Out-String)
    $stdout | Out-File $OutFile -Encoding utf8
    $stderr = ""
    try { $stderr = Get-Content $errFile -Raw -ErrorAction SilentlyContinue } catch {}
    if ([string]::IsNullOrWhiteSpace($stdout)) {
        return [ordered]@{ ok = $false; json = $null; exitCode = $exitCode; error = "empty stdout (exit=$exitCode) stderr=$($stderr.Trim())" }
    }
    try {
        $j = $stdout | ConvertFrom-Json
        if ($j.error) {
            return [ordered]@{ ok = $false; json = $j; exitCode = $exitCode; error = "iperf error: $($j.error)" }
        }
        return [ordered]@{ ok = $true; json = $j; exitCode = $exitCode; error = "" }
    } catch {
        return [ordered]@{ ok = $false; json = $null; exitCode = $exitCode; error = "JSON parse failed (exit=$exitCode): $($_.Exception.Message) stderr=$($stderr.Trim())" }
    }
}

# High-frequency latency probe: rapid ping for p99.9-grade sample counts.
function Measure-Latency([int]$Count, [int]$GapMs) {
    $samples = @()
    for ($i = 0; $i -lt $Count; $i++) {
        $r = Test-Connection -ComputerName $Peer -Count 1 -ErrorAction SilentlyContinue
        if ($r) { $samples += [double]$r.Latency }
        if ($GapMs -gt 0) { Start-Sleep -Milliseconds $GapMs }
    }
    return Get-Percentiles $samples
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
    @{ name = "tcp-up-1"; args = "-c $Peer -p $ServerPortUp -t $Duration -P 1"; dir = "up" },
    @{ name = "tcp-up-4"; args = "-c $Peer -p $ServerPortUp -t $Duration -P 4"; dir = "up" },
    @{ name = "tcp-down-1"; args = "-c $Peer -p $ServerPortDown -t $Duration -P 1 -R"; dir = "down" },
    @{ name = "tcp-down-4"; args = "-c $Peer -p $ServerPortDown -t $Duration -P 4 -R"; dir = "down" }
)
$cap = @{ up = 0.0; down = 0.0 }
foreach ($rep in 1..$Repeats) {
    foreach ($c in $tpCases) {
        $pathBefore = Get-PathState
        $r = Invoke-IperfJson $c.args "$ResultsDir\$($c.name)-r$rep.json"
        if ($r.ok) {
            $j = $r.json
            $mbps = [math]::Round($j.end.sum_received.bits_per_second / 1e6, 1)
            $retr = 0; try { $retr = [int]$j.end.sum_sent.retransmits } catch {}
            $sentMbps = 0; try { $sentMbps = [math]::Round($j.end.sum_sent.bits_per_second / 1e6, 1) } catch {}
            Write-Host "  $($c.name) r$rep : $mbps Mbps (retr=$retr)"
            if ($c.name -like "*-4") {
                if ($mbps -gt $cap[$c.dir]) { $cap[$c.dir] = $mbps }
            }
            Write-Row @{ scenario = $c.name; direction = $c.dir; repeat = $rep; offered_mbps = $null
                actual_mbps = $mbps; sent_mbps = $sentMbps; retransmits = $retr; path = $pathBefore; valid = $true }
        } else {
            Write-Host "  $($c.name) r$rep : FAILED: $($r.error)" -ForegroundColor Red
            Write-Row @{ scenario = $c.name; direction = $c.dir; repeat = $rep; offered_mbps = $null
                actual_mbps = -1; sent_mbps = -1; retransmits = -1; path = $pathBefore
                note = "TCP FAILED: $($r.error)"; valid = $false }
        }
    }
    # Bidirectional: parse both directions explicitly (v2 bug: bidir was unread).
    $pathBefore = Get-PathState
    $r = Invoke-IperfJson "-c $Peer -p $ServerPortUp -t $Duration -P 4 --bidir" "$ResultsDir\tcp-bidir-r$rep.json"
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
            actual_mbps = $upMbps; down_mbps = $downMbps; retransmits = $retr; path = $pathBefore; valid = $true }
    } else {
        Write-Host "  tcp-bidir r$rep : FAILED: $($r.error)" -ForegroundColor Red
        Write-Row @{ scenario = "tcp-bidir"; direction = "bidir"; repeat = $rep
            actual_mbps = -1; down_mbps = -1; retransmits = -1; path = $pathBefore
            note = "TCP FAILED: $($r.error)"; valid = $false }
    }
}
# No invented capacity: if the TCP matrix failed, every capacity-dependent
# sweep would be built on fiction. Stop loudly instead.
if ($cap.up -eq 0 -or $cap.down -eq 0) {
    Write-Host "  FATAL: TCP capacity measurement failed (up=$($cap.up) down=$($cap.down)). Refusing to invent 50 Mbps; fix the TCP path first." -ForegroundColor Red
    Write-Host "Results so far: $Jsonl" -ForegroundColor Yellow
    exit 1
}
Write-Host "  measured capacity: up=$($cap.up)Mbps down=$($cap.down)Mbps"

# --- loaded latency per direction at fractions of directional capacity ---
# NOTE on samples: Measure-Latency 200 gives meaningful p50/p95/p99;
# p999 stays null by design (see header). Bash uses 1000 fast pings.
Write-Host "[3] Loaded-latency sweeps (200 samples/dir: p99 max, p999 null)..." -ForegroundColor Yellow
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
        # Direction-specific load: download MUST use -R (server sends), or
        # the "download" test silently measures upload load.
        $isDown = ($d.name -eq "download")
        $port = $d.port
        $loadFile = "$ResultsDir\load-$($d.name)-$F.json"
        $job = Start-Job -ScriptBlock {
            param($exe, $p, $dd, $r, $rev, $pp, $out)
            if ($rev) { & $exe -c $p -p $pp -t $dd -u -b "${r}M" -R --json 2>&1 | Out-File $out -Encoding utf8 }
            else { & $exe -c $p -p $pp -t $dd -u -b "${r}M" --json 2>&1 | Out-File $out -Encoding utf8 }
            if ($LASTEXITCODE -ne 0) { "EXIT:$LASTEXITCODE" | Out-File "$out.exit" -Encoding utf8 }
        } -ArgumentList $iperf3, $Peer, $Duration, $rate, $isDown, $port, $loadFile
        Start-Sleep 2
        $lat = Measure-Latency 200 5
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
            if ($lj.error) { throw "iperf error: $($lj.error)" }
            $actual = [math]::Round($lj.end.sum.bits_per_second / 1e6, 1)
            $loss = [math]::Round($lj.end.sum.lost_percent, 2)
        } catch { $actual = -1; $loss = -1; $valid = $false; if (-not $loadErr) { $loadErr = $_.Exception.Message } }
        $pathAfter = Get-PathState
        $note = ""
        if ($pathBefore.mode -ne $pathAfter.mode) { $note = "PATH CHANGED mid-run; result flagged" }
        if ($actual -gt 0 -and $actual -lt $rate * 0.7 -and $f -le 1.0) { $note += " under-delivered load" }
        if (-not $valid) { $note += " LOAD FAILED ($loadErr): row invalid, values are placeholders" }
        Write-Host "  $($d.name) ${pct}%: actual=${actual}Mbps loss=${loss}% p50=$($lat.p50) p95=$($lat.p95) p99=$($lat.p99) max=$($lat.max) valid=$valid $note"
        Write-Row @{ scenario = "loaded-latency"; direction = $d.name; fraction = $f
            offered_mbps = $rate; actual_mbps = $actual; loss_pct = $loss
            latency = $lat; path = $pathBefore; path_after = $pathAfter; note = $note.Trim(); valid = $valid }
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
    $upFile = "$ResultsDir\load-bidi-$f-up.json"
    $downFile = "$ResultsDir\load-bidi-$f-down.json"
    $jobUp = Start-Job -ScriptBlock {
        param($exe, $p, $dd, $r, $pp, $out) & $exe -c $p -p $pp -t $dd -u -b "${r}M" --json 2>&1 | Out-File $out -Encoding utf8
        if ($LASTEXITCODE -ne 0) { "EXIT:$LASTEXITCODE" | Out-File "$out.exit" -Encoding utf8 }
    } -ArgumentList $iperf3, $Peer, $Duration, $rateUp, $ServerPortUp, $upFile
    $jobDown = Start-Job -ScriptBlock {
        param($exe, $p, $dd, $r, $pp, $out) & $exe -c $p -p $pp -t $dd -u -b "${r}M" -R --json 2>&1 | Out-File $out -Encoding utf8
        if ($LASTEXITCODE -ne 0) { "EXIT:$LASTEXITCODE" | Out-File "$out.exit" -Encoding utf8 }
    } -ArgumentList $iperf3, $Peer, $Duration, $rateDown, $ServerPortDown, $downFile
    Start-Sleep 2
    $lat = Measure-Latency 200 5
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
            if ($uj.error) { throw "iperf error: $($uj.error)" }
            $actualUp = [math]::Round($uj.end.sum.bits_per_second / 1e6, 1)
            $lossUp = [math]::Round($uj.end.sum.lost_percent, 2)
        } catch { $errUp = $_.Exception.Message }
    }
    if (-not $errDown) {
        try {
            $dj = $downJson | ConvertFrom-Json
            if ($dj.error) { throw "iperf error: $($dj.error)" }
            $actualDown = [math]::Round($dj.end.sum.bits_per_second / 1e6, 1)
            $lossDown = [math]::Round($dj.end.sum.lost_percent, 2)
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
        latency = $lat; path = $pathBefore; path_after = $pathAfter; note = $note.Trim(); valid = $valid }
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
    @{ name = "up"; port = $ServerPortUp; extra = "" },
    @{ name = "down"; port = $ServerPortDown; extra = "-R" }
)
foreach ($ud in $udpDirs) {
    foreach ($f in @(0.25, 0.50, 1.00)) {
        $rate = [math]::Round($cap.up * $f, 1)
        foreach ($len in @(512, 900, 1200, 1460, 2700)) {
            $args = "-c $Peer -p $($ud.port) -u -b ${rate}M -l $len -t $Duration $($ud.extra)".Trim()
            $r = Invoke-IperfJson $args "$ResultsDir\udp-$($ud.name)-${rate}M-${len}B.json"
            if ($r.ok) {
                $j = $r.json
                # Sender side (offer) vs receiver side (delivered): read
                # both explicitly; a missing receiver summary invalidates
                # the row instead of masquerading the offer as delivered.
                $send = $null; $recv = $null
                try { $send = $j.end.sum } catch {}
                try { $recv = $j.end.sum_received } catch {}
                if ($null -eq $recv) { throw "no sum_received in iperf JSON" }
                $sentMbps = [math]::Round($send.bits_per_second / 1e6, 1)
                $del = [math]::Round($recv.bits_per_second / 1e6, 1)
                $ppsSent = $null; $ppsRecv = $null
                try { $ppsSent = [math]::Round($send.packets / $Duration, 0) } catch {}
                try { $ppsRecv = [math]::Round($recv.packets_received / $Duration, 0) } catch {}
                if ($null -eq $ppsRecv) { try { $ppsRecv = [math]::Round($recv.packets / $Duration, 0) } catch {} }
                $loss = -1; $jitter = $null
                try { $loss = [math]::Round($recv.lost_percent, 2) } catch {}
                try { $jitter = [math]::Round($recv.jitter_ms, 3) } catch {}
                Write-Host ("  $($ud.name) offered={0}Mbps sent={1}Mbps delivered={2}Mbps pps_sent={3} pps_recv={4} loss={5}% jitter={6}ms len={7}B" -f $rate, $sentMbps, $del, $ppsSent, $ppsRecv, $loss, $jitter, $len)
                Write-Row @{ scenario = "udp"; direction = $ud.name; offered_mbps = $rate; packet_len = $len
                    sent_mbps = $sentMbps; actual_mbps = $del; pps_sent = $ppsSent; pps_received = $ppsRecv
                    loss_pct = $loss; jitter_ms = $jitter; path = (Get-PathState); valid = $true }
            } else {
                Write-Host "  $($ud.name) offered=${rate}Mbps len=${len}B : FAILED: $($r.error)" -ForegroundColor Red
                Write-Row @{ scenario = "udp"; direction = $ud.name; offered_mbps = $rate; packet_len = $len
                    sent_mbps = -1; actual_mbps = -1; pps_sent = $null; pps_received = $null
                    loss_pct = -1; jitter_ms = $null; path = (Get-PathState)
                    note = "UDP FAILED: $($r.error)"; valid = $false }
            }
        }
    }
}

Write-Host "`nResults: $ResultsDir\results.jsonl (shared schema)" -ForegroundColor Green
