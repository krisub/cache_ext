#!/bin/bash

# Compile if needed
# g++ net_leveldb.cc -o net_leveldb -lleveldb -lpthread -lsnappy
sudo pkill -9 net_leveldb

if [ -f "/sys/kernel/mm/lru_gen/enabled" ]; then
    echo "Disabling MGLRU for cache_ext tests..."
    cat /sys/kernel/mm/lru_gen/enabled
    echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null
    cat /sys/kernel/mm/lru_gen/enabled
fi

if [ -d "/mydata/my_dbs/db_A" ]; then
    echo "Data found at /mydata/my_dbs/db_A. Skipping population..."
else
    echo "Data NOT found. Running full setup..."
    
    sudo pkill -9 net_leveldb
    sudo rm -rf /mydata/my_dbs/db_A /mydata/my_dbs/db_B
    
    # Populate A
    echo "Populating DB A..."
    ./net_leveldb 0 /mydata/my_dbs/db_A --populate
    
    # Populate B
    echo "Populating DB B..."
    ./net_leveldb 0 /mydata/my_dbs/db_B --populate
fi

sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

CGROUP_PATH="/sys/fs/cgroup/cache_ext_test"
if [ ! -d "$CGROUP_PATH" ]; then
    echo "Creating v2 cgroup at $CGROUP_PATH"
    sudo mkdir -p "$CGROUP_PATH"
fi

NUMACTL_BIN="$(command -v numactl || true)"
if [ -n "$NUMACTL_BIN" ]; then
    RUN_CMD="$NUMACTL_BIN --cpunodebind=0 --membind=0"
else
    echo "Warning: numactl not found; allocations may span NUMA nodes."
    RUN_CMD=""
fi

$RUN_CMD ./net_leveldb 9001 /mydata/my_dbs/db_A &
PID_A=$!
$RUN_CMD ./net_leveldb 9002 /mydata/my_dbs/db_B &
PID_B=$!

echo "Placing net_leveldb PIDs into v2 cgroup..."
echo "$PID_A" | sudo tee "$CGROUP_PATH/cgroup.procs" > /dev/null
echo "$PID_B" | sudo tee "$CGROUP_PATH/cgroup.procs" > /dev/null
