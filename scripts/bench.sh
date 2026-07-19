#!/bin/bash
PEER="10.7.0.2"
DURATION=30
RESULTS_DIR="./bench-results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== Tunnet Mesh Benchmark ==="
echo "Peer: $PEER | Duration: ${DURATION}s per test"
echo "Results: $RESULTS_DIR"
echo ""

# 1. Baseline ping
echo "[1/5] Baseline ping..."
ping -c 100 -i 0.01 "$PEER" > "$RESULTS_DIR/ping.txt" 2>&1
tail -3 "$RESULTS_DIR/ping.txt"
echo ""

# 2. Latency - TCP RR
echo "[2/5] Latency (TCP_RR)..."
netperf -H "$PEER" -t TCP_RR -l "$DURATION" -- \
  -o min_latency,mean_latency,max_latency,p99_latency,stddev_latency \
  > "$RESULTS_DIR/latency-tcp.txt" 2>&1
cat "$RESULTS_DIR/latency-tcp.txt"
echo ""

# 3. Latency - UDP RR
echo "[3/5] Latency (UDP_RR)..."
netperf -H "$PEER" -t UDP_RR -l "$DURATION" -- \
  -o min_latency,mean_latency,max_latency,p99_latency,stddev_latency \
  > "$RESULTS_DIR/latency-udp.txt" 2>&1
cat "$RESULTS_DIR/latency-udp.txt"
echo ""

# 4. Throughput - TCP
echo "[4/5] Throughput (TCP, 4 streams)..."
iperf3 -c "$PEER" -t "$DURATION" -P 4 --json \
  > "$RESULTS_DIR/throughput-tcp.json" 2>&1
# Extract summary
python3 -c "
import json, sys
d = json.load(open('$RESULTS_DIR/throughput-tcp.json'))
e = d['end']['sum_sent']
print(f\"  Sent: {e['bits_per_second']/1e6:.1f} Mbps\")
e = d['end']['sum_received']
print(f\"  Recv: {e['bits_per_second']/1e6:.1f} Mbps\")
" 2>/dev/null || grep -A2 "sender" "$RESULTS_DIR/throughput-tcp.json"
echo ""

# 5. Throughput - UDP
echo "[5/5] Throughput (UDP, 500M target)..."
iperf3 -c "$PEER" -u -b 500M -t "$DURATION" --json \
  > "$RESULTS_DIR/throughput-udp.json" 2>&1
python3 -c "
import json
d = json.load(open('$RESULTS_DIR/throughput-udp.json'))
e = d['end']['sum']
print(f\"  Bitrate: {e['bits_per_second']/1e6:.1f} Mbps\")
print(f\"  Jitter: {e['jitter_ms']:.3f} ms\")
print(f\"  Lost: {e['lost_percent']:.2f}%\")
" 2>/dev/null
echo ""

# 6. Latency under load (bonus)
echo "[BONUS] Latency under load (30s)..."
iperf3 -c "$PEER" -t "$DURATION" -P 4 > /dev/null 2>&1 &
IPERF_PID=$!
sleep 2  # let throughput stabilize
netperf -H "$PEER" -t TCP_RR -l $((DURATION - 4)) -- \
  -o min_latency,mean_latency,max_latency,p99_latency,stddev_latency \
  > "$RESULTS_DIR/latency-under-load.txt" 2>&1
wait $IPERF_PID 2>/dev/null
echo "  Latency under load:"
cat "$RESULTS_DIR/latency-under-load.txt"
echo ""

echo "=== Done. Results in $RESULTS_DIR ==="
