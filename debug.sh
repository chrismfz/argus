# --- Config (adjust as needed) ---
PPROF_HOST=127.0.0.1
PPROF_PORT=9601                 # use your chosen debug port (NOT 9601)
BIN_CFM=/usr/bin/cfm
BIN_FLOW=/opt/argus/bin/argus   # or wherever your binary lives
BIN=$BIN_FLOW                   # set to $BIN_CFM if profiling cfm

OUTDIR=/tmp/pprof-$(date +%F_%H%M%S)
mkdir -p "$OUTDIR"
echo "Output dir: $OUTDIR"


PID=$(pgrep -f "$BIN" | head -n1)
echo "PID=$PID"

curl -s -o "$OUTDIR/cpu.pb.gz" \
  "http://$PPROF_HOST:$PPROF_PORT/debug/pprof/profile?seconds=60"

curl -s -o "$OUTDIR/goroutines.txt" \
  "http://$PPROF_HOST:$PPROF_PORT/debug/pprof/goroutine?debug=2"

curl -s -o "$OUTDIR/heap.pb.gz" \
  "http://$PPROF_HOST:$PPROF_PORT/debug/pprof/heap"

go tool pprof "$BIN" "$OUTDIR/cpu.pb.gz"

# pprof shell:
# (pprof) top
# (pprof) top -cum
# (pprof) list ConvertToFlowRecord
# (pprof) web        # if you have graphviz
# (pprof) quit
