TEST="local_indexes_unpinned.json"

nohup python3 bench_rocksdb.py \
    --results-file=/mydata/rocksdb-results/"$TEST" \
    --cpu 3 \
    --db-path=/mydata/database/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/mydata/datebase_temp \
    --disk-type=local \
    --threads-per-core=8 \
    > /mydata/bench_rocksdb.log \
    2>&1 & \
tail -f /mydata/bench_rocksdb.log

TEST="bpfof_indexes_pinned.json"
nohup python3 bench_rocksdb.py \
    --results-file=/mydata/rocksdb-results/"$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp_2 \
    --disk-type=nvmeof_tcp \
    --threads-per-core=8 \
    > /mydata/bench_rocksdb.log \
    2>&1 & \
tail -f /mydata/bench_rocksdb.log


# DONT FORGET TO CHANGE INDEXES PINNED