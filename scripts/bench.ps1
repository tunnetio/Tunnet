# bench-tunnet.ps1
param(
    [string]$Peer = "10.7.0.2",
    [int]$Duration = 30
)

$iperf3 = "$env:USERPROFILE\bin\iperf3\iperf3.exe"

# fallback — check common locations
if (-not (Test-Path $iperf3)) {
    $iperf3 = Get-Command iperf3.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}
if (-not $iperf3) {
    Write-Host "iperf3.exe not found. Download from: https://github.com/ar51an/iperf3-win-builds/releases" -ForegroundColor Red
    exit 1
}

$ResultsDir = ".\bench-results\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null

Write-Host "=== Tunnet Mesh Benchmark ===" -ForegroundColor Cyan
Write-Host "Peer: $Peer | Duration: ${Duration}s | iperf3: $iperf3"
Write-Host "Results: $ResultsDir"
Write-Host ""

# -------------------------------------------------------
# 0. Connectivity
# -------------------------------------------------------
Write-Host "[0/5] Connectivity..." -ForegroundColor Yellow
$ping = Test-Connection -ComputerName $Peer -Count 4 -ErrorAction SilentlyContinue
if (-not $ping) {
    Write-Host "  FAIL: $Peer unreachable" -ForegroundColor Red
    exit 1
}
Write-Host "  OK" -ForegroundColor Green
Write-Host ""

# -------------------------------------------------------
# 1. ICMP Ping — 100 packets
# -------------------------------------------------------
Write-Host "[1/5] ICMP Ping (100 packets)..." -ForegroundColor Yellow
$pingAll = Test-Connection -ComputerName $Peer -Count 100 -ErrorAction SilentlyContinue
$s = $pingAll | ForEach-Object { $_.Latency } | Measure-Object -Minimum -Maximum -Average -StandardDeviation
Write-Host "  Min: $($s.Minimum)ms | Avg: $([math]::Round($s.Average,2))ms | Max: $($s.Maximum)ms | StdDev: $([math]::Round($s.StandardDeviation,2))ms"
$pingAll | Export-Csv "$ResultsDir\ping.csv" -NoTypeInformation
Write-Host ""

# -------------------------------------------------------
# 2. TCP Upload — single stream
# -------------------------------------------------------
Write-Host "[2/5] TCP Upload (single stream, ${Duration}s)..." -ForegroundColor Yellow
& $iperf3 -c $Peer -t $Duration --json | Out-File "$ResultsDir\tcp-upload.json"
$up = Get-Content "$ResultsDir\tcp-upload.json" | ConvertFrom-Json
if ($up.error) {
    Write-Host "  ERROR: $($up.error)" -ForegroundColor Red
    Write-Host "  Is iperf3 -s running on the peer?" -ForegroundColor Red
} else {
    $sent = $up.end.sum_sent
    $recv = $up.end.sum_received
    Write-Host "  Send: $([math]::Round($sent.bits_per_second / 1e6, 1)) Mbps | Recv: $([math]::Round($recv.bits_per_second / 1e6, 1)) Mbps"
}
Write-Host ""

# -------------------------------------------------------
# 3. TCP Download — reverse
# -------------------------------------------------------
Write-Host "[3/5] TCP Download (reverse, ${Duration}s)..." -ForegroundColor Yellow
& $iperf3 -c $Peer -t $Duration -R --json | Out-File "$ResultsDir\tcp-download.json"
$dl = Get-Content "$ResultsDir\tcp-download.json" | ConvertFrom-Json
if ($dl.error) {
    Write-Host "  ERROR: $($dl.error)" -ForegroundColor Red
} else {
    $dlRecv = $dl.end.sum_received
    Write-Host "  Download: $([math]::Round($dlRecv.bits_per_second / 1e6, 1)) Mbps"
}
Write-Host ""

# -------------------------------------------------------
# 4. UDP — jitter + packet loss
# -------------------------------------------------------
Write-Host "[4/5] UDP (500M target, ${Duration}s)..." -ForegroundColor Yellow
& $iperf3 -c $Peer -u -b 500M -t $Duration --json | Out-File "$ResultsDir\udp.json"
$udp = Get-Content "$ResultsDir\udp.json" | ConvertFrom-Json
if ($udp.error) {
    Write-Host "  ERROR: $($udp.error)" -ForegroundColor Red
} else {
    $us = $udp.end.sum
    Write-Host "  Bitrate: $([math]::Round($us.bits_per_second / 1e6, 1)) Mbps"
    Write-Host "  Jitter:  $([math]::Round($us.jitter_ms, 3)) ms"
    Write-Host "  Lost:    $([math]::Round($us.lost_percent, 2))%"
}
Write-Host ""

# -------------------------------------------------------
# 5. Latency under load
# -------------------------------------------------------
Write-Host "[5/5] Latency under load (${Duration}s)..." -ForegroundColor Yellow
$job = Start-Job -ScriptBlock {
    param($exe, $p, $d)
    & $exe -c $p -t $d -P 4 2>&1
} -ArgumentList $iperf3, $Peer, $Duration

Start-Sleep 3

$loadPing = Test-Connection -ComputerName $Peer -Count ([math]::Min($Duration - 6, 50)) -ErrorAction SilentlyContinue
$ls = $loadPing | ForEach-Object { $_.Latency } | Measure-Object -Minimum -Maximum -Average -StandardDeviation

Wait-Job $job | Out-Null
Remove-Job $job

Write-Host "  Min: $($ls.Minimum)ms | Avg: $([math]::Round($ls.Average,2))ms | Max: $($ls.Maximum)ms | StdDev: $([math]::Round($ls.StandardDeviation,2))ms"
$loadPing | Export-Csv "$ResultsDir\ping-under-load.csv" -NoTypeInformation
Write-Host ""

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ICMP (idle):    $([math]::Round($s.Average,2)) ms avg" 
Write-Host "  ICMP (load):    $([math]::Round($ls.Average,2)) ms avg"
if (-not $udp.error) {
    Write-Host "  UDP Jitter:     $([math]::Round($us.jitter_ms,3)) ms"
}
if (-not $up.error) {
    Write-Host "  Upload:         $([math]::Round($sent.bits_per_second / 1e6, 1)) Mbps"
}
if (-not $dl.error) {
    Write-Host "  Download:       $([math]::Round($dlRecv.bits_per_second / 1e6, 1)) Mbps"
}
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Results saved: $ResultsDir" -ForegroundColor Green
