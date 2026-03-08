#include <iostream>
#include "rocksdb_client.h"
#include "rocksdb_config.h"
#include "worker.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <config file>\n", argv[0]);
        return -EINVAL;
    }
    YAML::Node file = YAML::LoadFile(argv[1]);
    RocksDBConfig config = RocksDBConfig::parse_yaml(file);

    RocksDBFactory factory(config.rocksdb.data_dir, config.rocksdb.options_file,
                           config.rocksdb.cache_size,
                           config.rocksdb.print_stats);

    run_init_workload_with_op_measurement(
        "Initialization", &factory, config.database.nr_entry,
        config.database.key_size, config.database.value_size,
        1); // Use 1 thread for now, as the key shuffling is buggy with many threads
}
