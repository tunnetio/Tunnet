#!/bin/bash
# Tunnet Benchmark v3 — structured, repeatable, hard to lie with.
# Shared schema with bench.ps1: one JSON object per line in results.jsonl:
#   {ts, product, scenario, direction, fraction, offered_mbps, actual_mbps,
#    loss_pct, retransmits, latency:{n,p50,p95,p99,p999,max}, path:{...},
#    meta:{...}, note}
# Throughput matrix with explicit JSON fields (no regexed human output),
# loaded-latency sweeps per direction plus full-duplex bidir at fractions
# of independently measured directional capacity, UDP rate x size sweep,
# warmup + repeats, path-state capture around every scenario (flagged on
# migration), p99.9 from >=1000 high-frequency samples (gated to null when
# short). Up/down loads use separate server ports ($6/$7, default
# 5201/5202 — the server must listen on both); failed loads mark their row
# valid=false instead of hiding behind -1 placeholders.
set -u
PEER="${1:-10.7.0.2}"
DURATION="${2:-10}"
PRODUCT="${3:-tunnet}"
REPEATS="${4:-2}"
MTU="${5:-0}"
# Independent iperf3 server ports per direction: two simultaneous clients
# against one default port conflict (single active test per listener).
# The server side must listen on both: `iperf3 -s -p 5201` + `-p 5202`.
PORT_UP="${6:-5201}"
PORT_DOWN="${7:-5202}"
RESULTS_DIR="./bench-results/$(date +%Y%m%d-%H%M%S)-$PRODUCT"
mkdir -p "$RESULTS_DIR"
JSONL="$RESULTS_DIR/results.jsonl"

# Exported BEFORE the first consumer (every python block below reads them).
export BENCH_PRODUCT="$PRODUCT" BENCH_DURATION="$DURATION"
export BENCH_JSONL="$JSONL"

meta_json() {
  python3 -c "
import json,platform,subprocess
try: sha=subprocess.check_output(['git','rev-parse','--short','HEAD'],text=True).strip()
except Exception: sha=''
print(json.dumps({'commit':sha,'mtu':$MTU,'os':platform.platform(),'cpu':platform.processor() or platform.machine(),'peer':'$PEER','duration_s':$DURATION}))"
}
META=$(meta_json)
export BENCH_META="$META"

# Product-aware path collection: the Tunnet API only exists for tunnet runs.
path_json() {
  if [ "$PRODUCT" = "tunnet" ]; then
    python3 -c "
import json,subprocess
mode='unknown'; detail=''
try:
  import urllib.request
  st=json.load(urllib.request.urlopen('http://127.0.0.1:8899/api/status',timeout=5))
  mode=str(st.get('path_state','unknown')); detail=str(st.get('selected_path',''))
except Exception as e:
  detail='tunnet api unreachable'
print(json.dumps({'product':'$PRODUCT','mode':mode,'detail':detail[:400]}))"
  else
    # e.g. zerotier: summarize peer path states instead of querying Tunnet.
    zerotier-cli peers 2>/dev/null | head -6 | tr '\n' '|' | cut -c1-400 > "$RESULTS_DIR/.pathdetail" 2>/dev/null || echo "path collection n/a for $PRODUCT" > "$RESULTS_DIR/.pathdetail"
    python3 -c "
import json
detail=open('$RESULTS_DIR/.pathdetail').read().strip()
mode='unknown'
if 'DIRECT' in detail: mode='direct'
elif 'RELAY' in detail: mode='relay'
print(json.dumps({'product':'$PRODUCT','mode':mode,'detail':detail[:400]}))"
  fi
}

# High-frequency latency probe: COUNT samples back to back (p99.9 needs n>=1000).
ping_samples_json() { # COUNT OUTFILE
  ping -c "$1" -i 0.005 "$PEER" 2>/dev/null | grep -oE 'time=[0-9.]+' | cut -d= -f2 > "$2"
  python3 -c "
import json
xs=sorted(float(x) for x in open('$2') if x.strip())
n=len(xs)
def q(p): return xs[min(n-1,int(p*n))] if n else -1
r={'n':n}
if n:
    r.update({'min':round(xs[0],2),'p50':round(q(.5),2),'p95':round(q(.95),2),'p99':round(q(.99),2),'max':round(xs[-1],2)})
    r['p999']=round(q(.999),2) if n>=1000 else None
print(json.dumps(r))"
}

# Structured iperf runner: prints nothing human; writes JSON file; echoes path.
run_iperf() { # NAME EXTRA_ARGS...
  local name="$1"; shift
  iperf3 -c "$PEER" -t "$DURATION" "$@" --json > "$RESULTS_DIR/$name.json" 2>&1
}

echo "=== Tunnet Benchmark v3 ($PRODUCT) ==="
echo "Peer: $PEER | Duration: ${DURATION}s | Repeats: $REPEATS | Results: $RESULTS_DIR"

# --- connectivity + warmup ---
echo "[0] Connectivity + warmup..."
ping -c 4 "$PEER" > /dev/null 2>&1 || { echo "  FAIL: $PEER unreachable"; exit 1; }
iperf3 -c "$PEER" -p "$PORT_UP" -t 5 -P 2 > /dev/null 2>&1 || { echo "  FAIL: warmup iperf3 failed (is the server listening on port $PORT_UP?)"; exit 1; }
echo "  OK, warmed up"

# --- idle latency: 1200 samples for real p99.9 ---
echo "[1] Idle latency (1200 samples)..."
IDLE_JSON=$(ping_samples_json 1200 "$RESULTS_DIR/ping-idle.txt")
echo "  idle: $IDLE_JSON"
path_json > "$RESULTS_DIR/idle.path"
echo "$IDLE_JSON" > "$RESULTS_DIR/idle.lat"
python3 - "$RESULTS_DIR/idle.lat" "$RESULTS_DIR/idle.path" <<'EOF'
import json,sys,datetime,os
lat = json.load(open(sys.argv[1]))
path = json.load(open(sys.argv[2]))
row = {'scenario': 'idle', 'direction': 'none', 'latency': lat, 'path': path}
row['ts'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
row['product'] = os.environ['BENCH_PRODUCT']
row['meta'] = json.loads(os.environ['BENCH_META'])
open(os.environ['BENCH_JSONL'], 'a').write(json.dumps(row) + chr(10))
EOF

# --- throughput matrix with repeats; explicit bidir parse ---
echo "[2] Throughput matrix..."
CAP_UP=0; CAP_DOWN=0
tp_case() { # NAME DIR REPEAT EXTRA...
  local name="$1" dir="$2" rep="$3"; shift 3
  path_json > "$RESULTS_DIR/$name-r$rep.path"
  run_iperf "$name-r$rep" "$@"
  MBPS=$(python3 - "$RESULTS_DIR/$name-r$rep.json" "$RESULTS_DIR/$name-r$rep.path" "$name" "$dir" "$rep" <<'EOF'
import json,sys,datetime,os
ipath, ppath, name, direction, rep = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
d = json.load(open(ipath))
path = json.load(open(ppath))
if isinstance(d.get('error'), str):
    print(f"  {name} r{rep}: ERROR {d['error']}", flush=True)
    print(0)
else:
    mbps = round(d['end']['sum_received']['bits_per_second']/1e6, 1)
    try: sent = round(d['end']['sum_sent']['bits_per_second']/1e6, 1)
    except Exception: sent = -1
    try: retr = int(d['end']['sum_sent'].get('retransmits', 0))
    except Exception: retr = -1
    print(f"  {name} r{rep}: {mbps} Mbps (retr={retr})", flush=True)
    row = {'scenario': name, 'direction': direction, 'repeat': int(rep),
           'actual_mbps': mbps, 'sent_mbps': sent, 'retransmits': retr,
           'path': path}
    row['ts'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    row['product'] = os.environ['BENCH_PRODUCT']
    row['meta'] = json.loads(os.environ['BENCH_META'])
    open(os.environ['BENCH_JSONL'], 'a').write(json.dumps(row) + chr(10))
    print(mbps)
EOF
)
  echo "$MBPS" | tail -1
}
for rep in $(seq 1 "$REPEATS"); do
  tp_case tcp-up-1 up "$rep" -p "$PORT_UP" -P 1 > /dev/null
  MB=$(tp_case tcp-up-4 up "$rep" -p "$PORT_UP" -P 4 | tail -1)
  CAP_UP=$(python3 -c "print(max(float('$CAP_UP'), float('$MB')))")
  tp_case tcp-down-1 down "$rep" -p "$PORT_DOWN" -P 1 -R > /dev/null
  MB=$(tp_case tcp-down-4 down "$rep" -p "$PORT_DOWN" -P 4 -R | tail -1)
  CAP_DOWN=$(python3 -c "print(max(float('$CAP_DOWN'), float('$MB')))")
  # Bidirectional: parse both directions explicitly (v2 never did).
  path_json > "$RESULTS_DIR/tcp-bidir-r$rep.path"
  run_iperf "tcp-bidir-r$rep" -p "$PORT_UP" -P 4 --bidir
  python3 - "$RESULTS_DIR/tcp-bidir-r$rep.json" "$RESULTS_DIR/tcp-bidir-r$rep.path" "$rep" <<'EOF'
import json,sys,datetime,os
ipath, ppath, rep = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(ipath))
path = json.load(open(ppath))
up = round(d['end']['sum_sent']['bits_per_second']/1e6, 1)
down = round(d['end']['sum_received']['bits_per_second']/1e6, 1)
try: retr = int(d['end']['sum_sent'].get('retransmits', 0))
except Exception: retr = -1
print(f"  tcp-bidir r{rep}: up={up}Mbps down={down}Mbps (retr={retr})")
row = {'scenario': 'tcp-bidir', 'direction': 'bidir', 'repeat': int(rep),
       'actual_mbps': up, 'down_mbps': down, 'retransmits': retr, 'path': path}
row['ts'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
row['product'] = os.environ['BENCH_PRODUCT']
row['meta'] = json.loads(os.environ['BENCH_META'])
open(os.environ['BENCH_JSONL'], 'a').write(json.dumps(row) + chr(10))
EOF
done
# No invented capacity: if the TCP matrix failed, every capacity-dependent
# sweep would be built on fiction. Stop loudly instead.
if ! python3 -c "import sys; sys.exit(0 if float('$CAP_UP')>0 and float('$CAP_DOWN')>0 else 1)"; then
  echo "  FATAL: TCP capacity measurement failed (up=${CAP_UP} down=${CAP_DOWN}). Refusing to invent 50 Mbps; fix the TCP path first."
  echo "Results so far: $JSONL"
  exit 1
fi
echo "  measured capacity: up=${CAP_UP}Mbps down=${CAP_DOWN}Mbps"

# --- loaded latency per direction at fractions of directional capacity ---
echo "[3] Loaded-latency sweeps..."
for dir in "upload:$CAP_UP:$PORT_UP:" "download:$CAP_DOWN:$PORT_DOWN:-R"; do
  name="${dir%%:*}"; rest="${dir#*:}"; cap="${rest%%:*}"; rest2="${rest#*:}"
  port="${rest2%%:*}"; extra="${rest2#*:}"
  for F in 0.25 0.50 0.75 0.90 1.00 1.10; do
    RATE=$(python3 -c "print(round(float('$cap')*float('$F'),1))")
    PCT=$(python3 -c "print(int(float('$F')*100))")
    echo "  $name ${PCT}% (${RATE}Mbps)..."
    path_json > "$RESULTS_DIR/load-$name-$F.path0"
    # shellcheck disable=SC2086
    iperf3 -c "$PEER" -p "$port" -t "$DURATION" -u -b "${RATE}M" $extra --json > "$RESULTS_DIR/load-$name-$F.json" 2>&1 &
    LOAD_PID=$!
    sleep 2
    # 1000 samples: p99.9 under load is real (gated to null when short).
    ping_samples_json 1000 "$RESULTS_DIR/ping-load-$name-$F.txt" > "$RESULTS_DIR/ping-load-$name-$F.lat"
    wait $LOAD_PID
    path_json > "$RESULTS_DIR/load-$name-$F.path1"
    python3 - "$RESULTS_DIR/load-$name-$F.json" "$RESULTS_DIR/load-$name-$F.path0" "$RESULTS_DIR/load-$name-$F.path1" "$RESULTS_DIR/ping-load-$name-$F.lat" "$name" "$F" "$RATE" <<'EOF'
import json,sys,datetime,os
ipath, p0path, p1path, latpath, name, frac, rate = (sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], float(sys.argv[6]), float(sys.argv[7]))
valid = True
try:
    d = json.load(open(ipath))
    if isinstance(d.get('error'), str):
        raise ValueError(d['error'])
    s = d['end']['sum']
    actual = round(s['bits_per_second']/1e6, 1); loss = round(s.get('lost_percent', -1), 2)
except Exception as e:
    actual, loss = -1, -1
    valid = False
    print(f"  {name} {frac}: LOAD ERROR {e}", flush=True)
lat = json.load(open(latpath))
b = json.load(open(p0path)); a = json.load(open(p1path))
notes = []
if b.get('mode') != a.get('mode'):
    notes.append('PATH CHANGED mid-run; result flagged')
if actual > 0 and actual < rate*0.7 and frac <= 1.0:
    notes.append('under-delivered load')
if not valid:
    notes.append('LOAD FAILED: row invalid, values are placeholders')
note = '; '.join(notes)
print(f"  actual={actual}Mbps loss={loss}% p50={lat.get('p50')} p95={lat.get('p95')} p99={lat.get('p99')} max={lat.get('max')} {note}")
row = {'scenario': 'loaded-latency', 'direction': name, 'fraction': frac,
       'offered_mbps': rate, 'actual_mbps': actual, 'loss_pct': loss,
       'latency': lat, 'path': b, 'path_after': a, 'note': note,
       'valid': valid}
row['ts'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
row['product'] = os.environ['BENCH_PRODUCT']
row['meta'] = json.loads(os.environ['BENCH_META'])
open(os.environ['BENCH_JSONL'], 'a').write(json.dumps(row) + chr(10))
EOF
  done
done

# --- bidirectional loaded latency: full-duplex UDP at fractions ---
# Up and down loads run on SEPARATE server ports (see PORT_UP/PORT_DOWN):
# two clients against one listener conflict on a normal iperf3 server.
echo "  bidir (full duplex)..."
for F in 0.25 0.50 0.75 0.90 1.00; do
  RATE_UP=$(python3 -c "print(round(float('$CAP_UP')*float('$F'),1))")
  RATE_DOWN=$(python3 -c "print(round(float('$CAP_DOWN')*float('$F'),1))")
  PCT=$(python3 -c "print(int(float('$F')*100))")
  echo "  bidir ${PCT}% (up=${RATE_UP}Mbps down=${RATE_DOWN}Mbps)..."
  path_json > "$RESULTS_DIR/load-bidi-$F.path0"
  iperf3 -c "$PEER" -p "$PORT_UP" -t "$DURATION" -u -b "${RATE_UP}M" --json > "$RESULTS_DIR/load-bidi-$F-up.json" 2>&1 &
  UP_PID=$!
  iperf3 -c "$PEER" -p "$PORT_DOWN" -t "$DURATION" -u -b "${RATE_DOWN}M" -R --json > "$RESULTS_DIR/load-bidi-$F-down.json" 2>&1 &
  DOWN_PID=$!
  sleep 2
  ping_samples_json 1000 "$RESULTS_DIR/ping-load-bidi-$F.txt" > "$RESULTS_DIR/ping-load-bidi-$F.lat"
  UP_OK=0; DOWN_OK=0
  wait $UP_PID || UP_OK=$?
  wait $DOWN_PID || DOWN_OK=$?
  path_json > "$RESULTS_DIR/load-bidi-$F.path1"
  python3 - "$RESULTS_DIR/load-bidi-$F-up.json" "$RESULTS_DIR/load-bidi-$F-down.json" "$RESULTS_DIR/load-bidi-$F.path0" "$RESULTS_DIR/load-bidi-$F.path1" "$RESULTS_DIR/ping-load-bidi-$F.lat" "$F" "$RATE_UP" "$RATE_DOWN" "$UP_OK" "$DOWN_OK" <<'EOF'
import json,sys,datetime,os
uppath, downpath, p0path, p1path, latpath, frac, rate_up, rate_down, up_ok, down_ok = (sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], float(sys.argv[6]), float(sys.argv[7]), float(sys.argv[8]), int(sys.argv[9]), int(sys.argv[10]))
def loadsum(p):
    try:
        d = json.load(open(p))
        if isinstance(d.get('error'), str):
            raise ValueError(d['error'])
        s = d['end']['sum']
        return round(s['bits_per_second']/1e6, 1), round(s.get('lost_percent', -1), 2), None
    except Exception as e:
        return -1, -1, str(e)[:200]
actual_up, loss_up, err_up = loadsum(uppath)
actual_down, loss_down, err_down = loadsum(downpath)
if up_ok != 0:
    err_up = (err_up + '; ' if err_up else '') + f'iperf up client exited {up_ok}'
if down_ok != 0:
    err_down = (err_down + '; ' if err_down else '') + f'iperf down client exited {down_ok}'
lat = json.load(open(latpath))
b = json.load(open(p0path)); a = json.load(open(p1path))
notes = []
if b.get('mode') != a.get('mode'):
    notes.append('PATH CHANGED mid-run; result flagged')
if actual_up > 0 and actual_up < rate_up*0.7 and frac <= 1.0:
    notes.append('under-delivered up load')
if actual_down > 0 and actual_down < rate_down*0.7 and frac <= 1.0:
    notes.append('under-delivered down load')
# A bidirectional row is only produced when BOTH directions ran: errors
# mark the row invalid explicitly instead of hiding behind -1 values.
valid = err_up is None and err_down is None
if err_up:
    notes.append(f'BIDIR INVALID: up load failed ({err_up})')
if err_down:
    notes.append(f'BIDIR INVALID: down load failed ({err_down})')
note = '; '.join(notes)
print(f"  up={actual_up}Mbps loss={loss_up}% down={actual_down}Mbps loss={loss_down}% p50={lat.get('p50')} p95={lat.get('p95')} p99={lat.get('p99')} p999={lat.get('p999')} valid={valid} {note}")
row = {'scenario': 'loaded-latency', 'direction': 'bidir', 'fraction': frac,
       'offered_up_mbps': rate_up, 'offered_down_mbps': rate_down,
       'actual_up_mbps': actual_up, 'actual_down_mbps': actual_down,
       'loss_up_pct': loss_up, 'loss_down_pct': loss_down,
       'latency': lat, 'path': b, 'path_after': a, 'note': note,
       'valid': valid}
row['ts'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
row['product'] = os.environ['BENCH_PRODUCT']
row['meta'] = json.loads(os.environ['BENCH_META'])
open(os.environ['BENCH_JSONL'], 'a').write(json.dumps(row) + chr(10))
EOF
done

# --- UDP sweep: rates x sizes x directions, sender vs receiver split ---
# Sizes span single-frame (512, 900) and segmented (1200, 1460, 2700)
# dataplane behavior; both directions run. `actual_mbps` is RECEIVER-side
# delivered throughput (sum_received), never the sender offer.
echo "[4] UDP sweep (sizes x directions)..."
for dir in "up:$PORT_UP:" "down:$PORT_DOWN:-R"; do
  name="${dir%%:*}"; rest="${dir#*:}"; port="${rest%%:*}"; extra="${rest#*:}"
  for F in 0.25 0.50 1.00; do
    RATE=$(python3 -c "print(round(float('$CAP_UP')*float('$F'),1))")
    for LEN in 512 900 1200 1460 2700; do
      path_json > "$RESULTS_DIR/udp.path"
      # shellcheck disable=SC2086
      run_iperf "udp-$name-${RATE}M-${LEN}B" -p "$port" -u -b "${RATE}M" -l "$LEN" $extra
      python3 - "$RESULTS_DIR/udp-$name-${RATE}M-${LEN}B.json" "$RESULTS_DIR/udp.path" "$RATE" "$LEN" "$name" <<'EOF'
import json,sys,datetime,os
ipath, ppath, rate, length, direction = sys.argv[1], sys.argv[2], float(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
valid = True
err = ''
try:
    d = json.load(open(ipath))
    if isinstance(d.get('error'), str):
        raise ValueError(d['error'])
    send = d['end']['sum']
    recv = d['end']['sum_received']
except Exception as e:
    valid = False
    err = f'UDP FAILED: {e}'[:200]
    send, recv = {}, {}
path = json.load(open(ppath))
def num(o, *keys, default=-1):
    for k in keys:
        try:
            v = o[k]
            if v is not None:
                return v
        except Exception:
            pass
    return default
sent_mbps = round(num(send, 'bits_per_second')/1e6, 1) if valid else -1
actual = round(num(recv, 'bits_per_second')/1e6, 1) if valid else -1
pps_sent = round(num(send, 'packets', default=0)/float(os.environ.get('BENCH_DURATION', '10'))) if valid else -1
pps_recv = round(num(recv, 'packets_received', 'packets', default=0)/float(os.environ.get('BENCH_DURATION', '10'))) if valid else -1
loss = round(num(recv, 'lost_percent'), 2) if valid else -1
jitter = round(num(recv, 'jitter_ms'), 3) if valid else -1
note = '' if valid else err
print(f"  {direction} offered={rate}Mbps sent={sent_mbps}Mbps delivered={actual}Mbps pps_sent={pps_sent} pps_recv={pps_recv} len={length}B loss={loss}% jitter={jitter}ms valid={valid} {note}")
row = {'scenario': 'udp', 'direction': direction, 'offered_mbps': rate, 'packet_len': length,
       'sent_mbps': sent_mbps, 'actual_mbps': actual, 'pps_sent': pps_sent, 'pps_received': pps_recv,
       'loss_pct': loss, 'jitter_ms': jitter, 'path': path, 'note': note, 'valid': valid}
row['ts'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
row['product'] = os.environ['BENCH_PRODUCT']
row['meta'] = json.loads(os.environ['BENCH_META'])
open(os.environ['BENCH_JSONL'], 'a').write(json.dumps(row) + chr(10))
EOF
    done
  done
done

echo "=== Done: $JSONL (shared schema) ==="
