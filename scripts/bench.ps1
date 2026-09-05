param(
    [string]$Peer = "10.7.0.2",
    [int]$Duration = 10,
    [string]$Product = "tunnet",
    [string]$TunnetApi = "http://127.0.0.1:8899",
    [int]$Repeats = 3,
    [int]$Mtu = 0,
    # Independent iperf3 server ports per direction: two simultaneous
    # clients against one default port conflict (single active test per
    # listener). The server side must listen on both ports.
    [int]$ServerPortUp = 5201,
    [int]$ServerPortDown = 5202,
    # Local agent metrics endpoint for per-scenario software-drop deltas
    # (only queried when Product=tunnet; unavailable reads as unavailable,
    # never as zero).
    [string]$MetricsUrl = "http://127.0.0.1:9100/metrics",
    # Peer agent metrics endpoint (the SENDER side for downloads). Defaults
    # to the peer's overlay metrics listener when Product=tunnet.
    [string]$PeerMetricsUrl = ""
)

# Tunnet Benchmark v3 — structured, repeatable, hard to lie with.
# Schema (shared with bench.sh): every scenario appends one JSON object per
# line to results.jsonl with fields:
#   {ts, product, scenario, direction, fraction, offered_mbps, actual_mbps,
#    loss_pct, retransmits, latency:{n,p50,p95,p99,p999,max}, path:{...},
#    meta:{...}, note, valid, load_met, delivery_ratio, undelivered_pct,
#    *_bytes, *_packets, local_sw_drops, peer_sw_drops,
#    local_session_before/after/changed, peer_session_before/after/changed}
# Throughput matrix (TCP 1/4, up/down/bidir with explicit JSON parse),
# loaded-latency sweeps per direction plus full-duplex bidir at fractions
# of independently measured directional capacity (download load uses -R),
# UDP rate x size sweep, warmup + repeats, path-state capture before/after
# every scenario (results flagged on migration). p99.9 only with >=1000
# samples, else null. Latency probes are asynchronous/staggered via a
# runspace pool so every sample window lies inside its load interval (200
# samples: p50/p95/p99 meaningful, p999 null BY DESIGN; idle uses 1200).
# Capacity is the MEDIAN of at least 3 valid P4 repeats per direction
# (never a lucky maximum); min/max/spread ride explicit capacity rows and
# a >25% spread is flagged UNSTABLE. A failed matrix stops the run instead
# of inventing 50 Mbps.
# "server is busy" listener contention retries boundedly (infrastructure,
# never Tunnet loss). One shared UDP parser (Parse-UdpSummary) reports
# receiver-delivered throughput everywhere, PLUS independent
# delivery_ratio/undelivered_pct and byte/packet counts; downloads offer
# against CAP_DOWN; loaded rows carry load_met (valid stays true on
# catastrophic under-delivery).
# Path/session state comes from the metrics endpoint (local + peer):
# every row carries software-drop deltas AND session before/after/change,
# so one-way session poisoning shows immediately without manual A/B runs.

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
        # Session/vitals come from the metrics endpoint (the legacy
        # /api/status HTTP endpoint does not exist; the Local API is a
        # local socket). Detail carries generation + session count.
        $snap = Get-SessionSnapshot $MetricsUrl
        if ($snap.available) {
            $state.mode = "tunnet"
            $state.detail = "gen=$($snap.generation) restarts=$($snap.restart_count) sessions=$($snap.sessions.Count)"
        } else {
            $state.detail = "tunnet metrics unreachable"
        }
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
# Property existence is checked explicitly ($Obj.PSObject.Properties):
# a missing `packets_received` must fall back to `packets`, never
# silently become pps_recv=0 on a successful non-zero run. Same for
# sender counts.
function Get-JsonProp($Obj, [string[]]$Names) {
    if ($null -eq $Obj) { return $null }
    foreach ($n in $Names) {
        if ($Obj.PSObject.Properties.Name -contains $n -and $null -ne $Obj.$n) {
            return $Obj.$n
        }
    }
    return $null
}

function Parse-UdpSummary($j) {
    try {
        if ($j.error) { return @{ ok = $false; error = "iperf error: $($j.error)" } }
        $recv = $j.end.sum_received
        if ($null -eq $recv) { return @{ ok = $false; error = "no sum_received in iperf JSON" } }
        $send = $j.end.sum
        $sbps = Get-JsonProp $send @("bits_per_second")
        $sent = $null
        if ($null -ne $sbps) { $sent = [math]::Round($sbps / 1e6, 1) }
        $actual = [math]::Round($recv.bits_per_second / 1e6, 1)
        $loss = -1; $jitter = $null; $ppsSent = $null; $ppsRecv = $null
        $lp = Get-JsonProp $recv @("lost_percent")
        if ($null -ne $lp) { $loss = [math]::Round($lp, 2) }
        $jm = Get-JsonProp $recv @("jitter_ms")
        if ($null -ne $jm) { $jitter = [math]::Round($jm, 3) }
        $sp = Get-JsonProp $send @("packets")
        if ($null -ne $sp) { $ppsSent = [math]::Round($sp / $Duration, 0) }
        $rp = Get-JsonProp $recv @("packets_received", "packets")
        if ($null -ne $rp) { $ppsRecv = [math]::Round($rp / $Duration, 0) }
        # Independent delivery accounting: receiver vs sender, so
        # sent=32/delivered=0/loss=0.2% still reads ~100% undelivered.
        $sBytes = Get-JsonProp $send @("bytes")
        $rBytes = Get-JsonProp $recv @("bytes")
        $sPkts = Get-JsonProp $send @("packets")
        $rPkts = Get-JsonProp $recv @("packets_received", "packets")
        $ratio = $null; $undel = $null
        if ($null -ne $sbps -and $sbps -gt 0) {
            $ratio = [math]::Round($recv.bits_per_second / $sbps, 4)
            $undel = [math]::Round(100.0 * (1.0 - $recv.bits_per_second / $sbps), 2)
        }
        return @{ ok = $true; actual = $actual; sent = $sent; loss = $loss; jitter = $jitter
            pps_sent = $ppsSent; pps_received = $ppsRecv; error = ""
            delivery_ratio = $ratio; undelivered_pct = $undel
            sender_bytes = $sBytes; receiver_bytes = $rBytes
            sender_packets = $sPkts; receiver_packets = $rPkts }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}

if ([string]::IsNullOrWhiteSpace($PeerMetricsUrl) -and $Product -eq "tunnet") {
    # The agent listens on localhost AND its overlay IP: the peer's
    # sender-side drops are observable over the tunnel itself.
    $PeerMetricsUrl = "http://${Peer}:9100/metrics"
}

# Scenario telemetry: low-cardinality software-drop counters scraped from
# the LOCAL agent and the PEER agent before/after each scenario (tunnet
# runs only). Uploads drop on the local sender; downloads drop on the
# remote sender — one side alone cannot see both. Availability is explicit:
# @{available=$false} when an endpoint is unreachable; zero is reported
# only after a successful scrape, never as a substitute for "unknown".
# Canonical session + dataplane vitals snapshot (item 14): generation,
# restarts, liveness, and per-peer (canonical, reader, orientation,
# alive). Unavailable reads as unavailable, never as healthy/zero.
function Get-SessionSnapshot([string]$Url) {
    $s = [ordered]@{ available = $false; sessions = @() }
    if ($Product -ne "tunnet" -or [string]::IsNullOrWhiteSpace($Url)) { return $s }
    try {
        $text = Invoke-RestMethod -Uri $Url -TimeoutSec 5
        if ($text -isnot [string]) { return $s }
        $s.available = $true
        foreach ($line in ($text -split "`n")) {
            if ($line -match "^tunnet_dataplane_(generation|restart_count|up|outbound_alive|writer_alive)\s+([0-9.eE+-]+)") {
                $s[$Matches[1]] = [double]$Matches[2]
            }
            elseif ($line -match '^tunnet_session_info\{([^}]*)\}\s+([0-9.eE+-]+)') {
                $labels = @{}
                foreach ($kv in ($Matches[1] -split ",")) {
                    $k, $v = $kv -split "=", 2
                    $labels[$k.Trim()] = $v.Trim().Trim('"')
                }
                $s.sessions += [ordered]@{
                    peer = $labels["peer"]; generation = $labels["generation"]
                    canonical = $labels["canonical"]; reader = $labels["reader"]
                    orientation = $labels["orientation"]; alive = ([double]$Matches[2] -gt 0)
                }
            }
        }
        return $s
    } catch { return [ordered]@{ available = $false; sessions = @() } }
}

function Get-SwSnapshot([string]$Url) {
    if ($Product -ne "tunnet" -or [string]::IsNullOrWhiteSpace($Url)) {
        return [ordered]@{ available = $false }
    }
    try {
        $text = Invoke-RestMethod -Uri $Url -TimeoutSec 5
        if ($text -isnot [string]) { return [ordered]@{ available = $false } }
        $out = [ordered]@{ available = $true; sched = 0.0; dropped = 0.0; tun_write_drop = 0.0 }
        foreach ($line in ($text -split "`n")) {
            if ($line -match "^tunnet_sched_drops_total\{[^}]*\}\s+([0-9.eE+-]+)") { $out.sched += [double]$Matches[1] }
            elseif ($line -match "^tunnet_dropped_packets_total\{[^}]*\}\s+([0-9.eE+-]+)") { $out.dropped += [double]$Matches[1] }
            elseif ($line -match "^tunnet_tun_write_queue_drop_total\s+([0-9.eE+-]+)") { $out.tun_write_drop += [double]$Matches[1] }
        }
        $out.session = (Get-SessionSnapshot $Url)
        return $out
    } catch { return [ordered]@{ available = $false } }
}

function Get-ScenarioSw {
    return [ordered]@{
        local = (Get-SwSnapshot $MetricsUrl)
        peer = (Get-SwSnapshot $PeerMetricsUrl)
    }
}

function Diff-Sw($Before, $After) {
    if (-not $Before.available -or -not $After.available) {
        return [ordered]@{ available = $false }
    }
    return [ordered]@{
        available = $true
        sched = [math]::Round($After.sched - $Before.sched, 0)
        dropped = [math]::Round($After.dropped - $Before.dropped, 0)
        tun_write_drop = [math]::Round($After.tun_write_drop - $Before.tun_write_drop, 0)
    }
}

function Sessions-Equal($A, $B) {
    if (($null -eq $A) -ne ($null -eq $B)) { return $false }
    if ($null -eq $A) { return $true }
    foreach ($k in @("generation", "restart_count", "up", "outbound_alive", "writer_alive")) {
        if ($A[$k] -ne $B[$k]) { return $false }
    }
    $sa = @($A.sessions | ForEach-Object { "$($_.peer)|$($_.generation)|$($_.canonical)|$($_.reader)|$($_.orientation)|$($_.alive)" } | Sort-Object)
    $sb = @($B.sessions | ForEach-Object { "$($_.peer)|$($_.generation)|$($_.canonical)|$($_.reader)|$($_.orientation)|$($_.alive)" } | Sort-Object)
    if ($sa.Count -ne $sb.Count) { return $false }
    for ($i = 0; $i -lt $sa.Count; $i++) { if ($sa[$i] -ne $sb[$i]) { return $false } }
    return $true
}

# Capture the "after" side and return deltas + session before/after/change
# for the row (session poisoning detection, both sides).
function SwDelta($Before) {
    $after = Get-ScenarioSw
    $out = [ordered]@{
        local_sw_drops = (Diff-Sw $Before.local $after.local)
        peer_sw_drops = (Diff-Sw $Before.peer $after.peer)
    }
    foreach ($side in @("local", "peer")) {
        $s0 = $Before[$side].session
        $s1 = $after[$side].session
        $out["${side}_session_before"] = $s0
        $out["${side}_session_after"] = $s1
        $out["${side}_session_changed"] = -not (Sessions-Equal $s0 $s1)
    }
    return $out
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
        $sw0 = Get-ScenarioSw
        $r = Invoke-IperfJson -IperfArgs $c.args -OutFile "$ResultsDir\$($c.name)-r$rep.json"
        if ($r.ok) {
            $j = $r.json
            $mbps = [math]::Round($j.end.sum_received.bits_per_second / 1e6, 1)
            $retr = 0; try { $retr = [int]$j.end.sum_sent.retransmits } catch {}
            $sentMbps = 0; try { $sentMbps = [math]::Round($j.end.sum_sent.bits_per_second / 1e6, 1) } catch {}
            Write-Host "  $($c.name) r$rep : $mbps Mbps (retr=$retr)"
            if ($c.name -like "*-4") {
                # A capacity repeat is valid only with measured throughput
                # > 0 (iperf exit ok + receiver bytes > 0). Zeros are not
                # measurements: they are excluded, and the repeat-count
                # gate below fails the matrix instead of median-ing them.
                if ($mbps -gt 0) { $capVals[$c.dir] += $mbps }
                else { Write-Host "  $($c.name) r$rep : ZERO throughput — excluded from capacity" -ForegroundColor Red }
            }
            $sw = SwDelta $sw0
            Write-Row @{ scenario = $c.name; direction = $c.dir; repeat = $rep; offered_mbps = $null
                actual_mbps = $mbps; sent_mbps = $sentMbps; retransmits = $retr; path = $pathBefore; valid = $true
                local_sw_drops = $sw.local_sw_drops
                peer_sw_drops = $sw.peer_sw_drops }
        } else {
            Write-Host "  $($c.name) r$rep : FAILED: $($r.error)" -ForegroundColor Red
            $sw = SwDelta $sw0
            Write-Row @{ scenario = $c.name; direction = $c.dir; repeat = $rep; offered_mbps = $null
                actual_mbps = -1; sent_mbps = -1; retransmits = -1; path = $pathBefore
                note = "TCP FAILED: $($r.error)"; valid = $false
                local_sw_drops = $sw.local_sw_drops
                peer_sw_drops = $sw.peer_sw_drops }
        }
    }
    # Bidirectional: parse both directions explicitly (v2 bug: bidir was unread).
    $pathBefore = Get-PathState
    $sw0 = Get-ScenarioSw
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
        $sw = SwDelta $sw0
        Write-Row @{ scenario = "tcp-bidir"; direction = "bidir"; repeat = $rep
            actual_mbps = $upMbps; down_mbps = $downMbps; retransmits = $retr; path = $pathBefore; valid = $true
            local_sw_drops = $sw.local_sw_drops
            peer_sw_drops = $sw.peer_sw_drops }
    } else {
        Write-Host "  tcp-bidir r$rep : FAILED: $($r.error)" -ForegroundColor Red
        $sw = SwDelta $sw0
        Write-Row @{ scenario = "tcp-bidir"; direction = "bidir"; repeat = $rep
            actual_mbps = -1; down_mbps = -1; retransmits = -1; path = $pathBefore
            note = "TCP FAILED: $($r.error)"; valid = $false
            local_sw_drops = $sw.local_sw_drops
            peer_sw_drops = $sw.peer_sw_drops }
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
# Matrix validity: ALL requested P4 repeats per direction must be valid.
# One zero/invalid repeat (e.g. down r1=0, r2=104.1) must not median into
# a false 52 Mbps capacity — the sweeps would test against fiction.
if ($capVals.up.Count -lt $Repeats -or $capVals.down.Count -lt $Repeats) {
    Write-Host "  FATAL: TCP capacity repeats incomplete (up valid $($capVals.up.Count)/$Repeats, down valid $($capVals.down.Count)/$Repeats). Matrix invalid; refusing capacity-relative sweeps." -ForegroundColor Red
    Write-Host "Results so far: $Jsonl" -ForegroundColor Yellow
    exit 1
}
if ($cap.up -eq 0 -or $cap.down -eq 0) {
    Write-Host "  FATAL: TCP capacity measurement failed (up=$($cap.up) down=$($cap.down)). Refusing to invent 50 Mbps; fix the TCP path first." -ForegroundColor Red
    Write-Host "Results so far: $Jsonl" -ForegroundColor Yellow
    exit 1
}
# Capacity summary rows: median/min/max/spread per direction. A large
# spread is flagged UNSTABLE (real signal about path variance), never
# hidden inside the median.
foreach ($dir in @("up", "down")) {
    $vals = $capVals[$dir]
    $med = $cap[$dir]
    $mn = ($vals | Measure-Object -Minimum).Minimum
    $mx = ($vals | Measure-Object -Maximum).Maximum
    $spread = [math]::Round($mx - $mn, 1)
    $spreadPct = 0.0
    if ($med -gt 0) { $spreadPct = [math]::Round($spread / $med, 3) }
    $note = ""
    if ($spreadPct -gt 0.25) {
        $note = "UNSTABLE capacity spread (max-min/median > 25%): treat sweeps against this capacity with suspicion"
        Write-Host "  WARNING: $dir capacity unstable (median=${med} min=${mn} max=${mx})" -ForegroundColor Yellow
    }
    Write-Row @{ scenario = "capacity"; direction = $dir
        median_mbps = $med; min_mbps = $mn; max_mbps = $mx
        spread_mbps = $spread; spread_pct = $spreadPct; repeats = $vals.Count
        path = (Get-PathState); note = $note; valid = $true }
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
        $sw0 = Get-ScenarioSw
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
        } catch { $actual = -1; $loss = -1; $valid = $false; $ps = $null; if (-not $loadErr) { $loadErr = $_.Exception.Message } }
        $pathAfter = Get-PathState
        $sw = SwDelta $sw0
        $note = ""
        if ($pathBefore.mode -ne $pathAfter.mode) { $note = "PATH CHANGED mid-run; result flagged" }
        if ($sw.local_session_changed -or $sw.peer_session_changed) { $note += " SESSION CHANGED mid-run (generation/stable/reader moved); result flagged" }
        # actual==0 MUST count: a successfully executed but fully
        # undelivered load is catastrophic under-delivery (valid stays
        # true, load_met goes false), not a parser failure.
        $under = $valid -and ($actual -lt $rate * 0.7) -and ($f -le 1.0)
        if ($under) { $note += " under-delivered load" }
        if (-not $valid) { $note += " LOAD FAILED ($loadErr): row invalid, values are placeholders" }
        $dr = $null; $udpct = $null
        if ($null -ne $ps) { $dr = $ps.delivery_ratio; $udpct = $ps.undelivered_pct }
        Write-Host "  $($d.name) ${pct}%: actual=${actual}Mbps loss=${loss}% delivered=${dr} undelivered=${udpct}% p50=$($lat.p50) p95=$($lat.p95) p99=$($lat.p99) max=$($lat.max) valid=$valid $note"
        Write-Row @{ scenario = "loaded-latency"; direction = $d.name; fraction = $f
            offered_mbps = $rate; actual_mbps = $actual; loss_pct = $loss
            delivery_ratio = $dr; undelivered_pct = $udpct
            sender_bytes = $(if ($null -ne $ps) { $ps.sender_bytes } else { $null })
            receiver_bytes = $(if ($null -ne $ps) { $ps.receiver_bytes } else { $null })
            sender_packets = $(if ($null -ne $ps) { $ps.sender_packets } else { $null })
            receiver_packets = $(if ($null -ne $ps) { $ps.receiver_packets } else { $null })
            latency = $lat; path = $pathBefore; path_after = $pathAfter; note = $note.Trim(); valid = $valid
            load_met = ($valid -and (-not $under))
            local_sw_drops = $sw.local_sw_drops
            peer_sw_drops = $sw.peer_sw_drops
            local_session_before = $sw.local_session_before
            local_session_after = $sw.local_session_after
            local_session_changed = $sw.local_session_changed
            peer_session_before = $sw.peer_session_before
            peer_session_after = $sw.peer_session_after
            peer_session_changed = $sw.peer_session_changed }
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
    $sw0 = Get-ScenarioSw
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
            $psUp = $ps
        } catch { $errUp = $_.Exception.Message; $psUp = $null }
    }
    if (-not $errDown) {
        try {
            $dj = $downJson | ConvertFrom-Json
            $ps = Parse-UdpSummary $dj
            if (-not $ps.ok) { throw $ps.error }
            $actualDown = $ps.actual; $lossDown = $ps.loss
            $psDown = $ps
        } catch { $errDown = $_.Exception.Message; $psDown = $null }
    }
    $pathAfter = Get-PathState
    $sw = SwDelta $sw0
    $note = ""
    if ($pathBefore.mode -ne $pathAfter.mode) { $note = "PATH CHANGED mid-run; result flagged" }
    if ($sw.local_session_changed -or $sw.peer_session_changed) { $note += " SESSION CHANGED mid-run (generation/stable/reader moved); result flagged" }
    $underUp = ($null -eq $errUp) -and ($actualUp -lt $rateUp * 0.7) -and ($f -le 1.0)
    $underDown = ($null -eq $errDown) -and ($actualDown -lt $rateDown * 0.7) -and ($f -le 1.0)
    if ($underUp) { $note += " under-delivered up load" }
    if ($underDown) { $note += " under-delivered down load" }
    $valid = ($null -eq $errUp) -and ($null -eq $errDown)
    if ($errUp) { $note += " BIDIR INVALID: up load failed ($errUp)" }
    if ($errDown) { $note += " BIDIR INVALID: down load failed ($errDown)" }
    $duUp = $null; $duDown = $null
    if ($null -ne $psUp) { $duUp = $psUp.undelivered_pct }
    if ($null -ne $psDown) { $duDown = $psDown.undelivered_pct }
    Write-Host "  bidir ${pct}%: up=${actualUp}Mbps loss=${lossUp}% down=${actualDown}Mbps loss=${lossDown}% p50=$($lat.p50) p95=$($lat.p95) p99=$($lat.p99) valid=$valid $note"
    Write-Row @{ scenario = "loaded-latency"; direction = "bidir"; fraction = $f
        offered_up_mbps = $rateUp; offered_down_mbps = $rateDown
        actual_up_mbps = $actualUp; actual_down_mbps = $actualDown
        loss_up_pct = $lossUp; loss_down_pct = $lossDown
        delivery_ratio_up = $(if ($null -ne $psUp) { $psUp.delivery_ratio } else { $null })
        undelivered_up_pct = $duUp
        delivery_ratio_down = $(if ($null -ne $psDown) { $psDown.delivery_ratio } else { $null })
        undelivered_down_pct = $duDown
        latency = $lat; path = $pathBefore; path_after = $pathAfter; note = $note.Trim(); valid = $valid
        load_met = ($valid -and (-not $underUp) -and (-not $underDown))
        local_sw_drops = $sw.local_sw_drops
        peer_sw_drops = $sw.peer_sw_drops
        local_session_before = $sw.local_session_before
        local_session_after = $sw.local_session_after
        local_session_changed = $sw.local_session_changed
        peer_session_before = $sw.peer_session_before
        peer_session_after = $sw.peer_session_after
        peer_session_changed = $sw.peer_session_changed }
}

# --- UDP sweep: rates x sizes x directions, sender vs receiver split ---
# -l is the iperf PAYLOAD size; the IPv4 packet on the TUN is ~28 B larger.
# With TUN MTU 1280: -l 512/900/1200 stay whole inner packets (single
# overlay frames), while -l 1460 (~1488 B) and -l 2700 (~2728 B) exceed the
# inner MTU and arrive as IPv4 FRAGMENTS — those two sizes are
# inner-fragmentation stress tests (fragment identity + deferred policy),
# NOT direct overlay-segmentation tests.
# Both directions run so upload/download asymmetries show up with numbers.
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
            $sw0 = Get-ScenarioSw
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
                $note = ""
                $sw = SwDelta $sw0
                if ($sw.local_session_changed -or $sw.peer_session_changed) { $note = "SESSION CHANGED mid-run (generation/stable/reader moved); result flagged" }
                Write-Host ("  $($ud.name) offered={0}Mbps sent={1}Mbps delivered={2}Mbps undelivered={3}% pps_sent={4} pps_recv={5} loss={6}% jitter={7}ms len={8}B" -f $rate, $sentMbps, $del, $ps.undelivered_pct, $ppsSent, $ppsRecv, $loss, $jitter, $len)
                Write-Row @{ scenario = "udp"; direction = $ud.name; offered_mbps = $rate; packet_len = $len
                    sent_mbps = $sentMbps; actual_mbps = $del; pps_sent = $ppsSent; pps_received = $ppsRecv
                    loss_pct = $loss; jitter_ms = $jitter
                    delivery_ratio = $ps.delivery_ratio; undelivered_pct = $ps.undelivered_pct
                    sender_bytes = $ps.sender_bytes; receiver_bytes = $ps.receiver_bytes
                    sender_packets = $ps.sender_packets; receiver_packets = $ps.receiver_packets
                    path = (Get-PathState); note = $note; valid = $true
                    local_sw_drops = $sw.local_sw_drops
                    peer_sw_drops = $sw.peer_sw_drops
                    local_session_before = $sw.local_session_before
                    local_session_after = $sw.local_session_after
                    local_session_changed = $sw.local_session_changed
                    peer_session_before = $sw.peer_session_before
                    peer_session_after = $sw.peer_session_after
                    peer_session_changed = $sw.peer_session_changed }
            } else {
                Write-Host "  $($ud.name) offered=${rate}Mbps len=${len}B : FAILED: $($r.error)" -ForegroundColor Red
                $sw = SwDelta $sw0
                Write-Row @{ scenario = "udp"; direction = $ud.name; offered_mbps = $rate; packet_len = $len
                    sent_mbps = -1; actual_mbps = -1; pps_sent = $null; pps_received = $null
                    loss_pct = -1; jitter_ms = $null; path = (Get-PathState)
                    note = "UDP FAILED: $($r.error)"; valid = $false
                    local_sw_drops = $sw.local_sw_drops
                    peer_sw_drops = $sw.peer_sw_drops
                    local_session_before = $sw.local_session_before
                    local_session_after = $sw.local_session_after
                    local_session_changed = $sw.local_session_changed
                    peer_session_before = $sw.peer_session_before
                    peer_session_after = $sw.peer_session_after
                    peer_session_changed = $sw.peer_session_changed }
            }
        }
    }
}

Write-Host "`nResults: $ResultsDir\results.jsonl (shared schema)" -ForegroundColor Green
