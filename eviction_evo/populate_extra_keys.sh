#!/usr/bin/env bash
# populate_extra_keys.sh - Pre-populate LevelDB with additional key formats
# needed by dual-client benchmark traces (e.g., dual_mixed_keys.yaml uses key_size=32).
#
# Run this ONCE before starting evolution that includes dual_mixed_keys trace.
# After running, the extra keys persist in leveldb_temp across evaluations.
#
# Usage:
#   ./populate_extra_keys.sh                    # populate leveldb_temp
#   ./populate_extra_keys.sh --source-too       # also populate source DB (survives rsync)
set -e

SERVER=/mydata/cache_ext/net_leveldb_server
INIT_TOOL=/mydata/cache_ext/My-YCSB/build/init_net_leveldb
DB_TEMP=/mydata/leveldb_temp
DB_SOURCE=/mydata/leveldb
PORT=9100
POPULATE_SOURCE=false

if [ "$1" = "--source-too" ]; then
    POPULATE_SOURCE=true
fi

# Extra key formats to populate: "key_size value_size nr_entry"
EXTRA_FORMATS=(
    "32 2048 1000000"
)

populate_db() {
    local db_path="$1"
    echo ""
    echo "=== Populating extra keys in: $db_path ==="

    # Kill any existing server
    sudo pkill -9 -f "net_leveldb_server" 2>/dev/null || true
    sleep 1

    # Start server
    echo "Starting server on port $PORT..."
    "$SERVER" "$PORT" "$db_path" &
    local server_pid=$!

    # Wait for server
    for i in $(seq 1 60); do
        (echo >/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break || sleep 1
    done
    echo "Server ready (PID $server_pid)"

    for format in "${EXTRA_FORMATS[@]}"; do
        read -r KEY_SIZE VALUE_SIZE NR_ENTRY <<< "$format"
        echo ""
        echo "--- key_size=$KEY_SIZE value_size=$VALUE_SIZE nr_entry=$NR_ENTRY ---"

        local tmpfile
        tmpfile=$(mktemp /tmp/populate_XXXXXX.yaml)
        cat > "$tmpfile" << EOF
database:
  key_size: $KEY_SIZE
  value_size: $VALUE_SIZE
  nr_entry: $NR_ENTRY
workload:
  nr_warmup_op: 0
  warmup_runtime_seconds: 0
  runtime_seconds: 0
  nr_op: 0
  nr_init_thread: 8
  nr_thread: 8
  next_op_interval_ns: 0
  operation_proportion:
    read: 0
    update: 0
    insert: 0
    scan: 0
    read_modify_write: 0
  request_distribution: "uniform"
  zipfian_constant: 0.99
  scan_length: 100
measurement:
  latency_file: ""
net_leveldb:
  addr: "127.0.0.1"
  port: $PORT
EOF
        "$INIT_TOOL" "$tmpfile"
        rm -f "$tmpfile"
        echo "Done: key_size=$KEY_SIZE, $NR_ENTRY entries added"
    done

    # Stop server
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    echo "Server stopped."
}

# Check binaries
for bin in "$SERVER" "$INIT_TOOL"; do
    if [ ! -x "$bin" ]; then
        echo "ERROR: $bin not found or not executable"
        exit 1
    fi
done

# Populate working copy
populate_db "$DB_TEMP"

# Optionally populate source (so rsync preserves extra keys)
if [ "$POPULATE_SOURCE" = "true" ]; then
    populate_db "$DB_SOURCE"
fi

echo ""
echo "=== Population complete ==="
echo "Extra key formats available in $DB_TEMP"
if [ "$POPULATE_SOURCE" = "true" ]; then
    echo "Also populated source DB: $DB_SOURCE"
fi
