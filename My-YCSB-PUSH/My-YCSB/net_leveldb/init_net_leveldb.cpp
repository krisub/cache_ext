// init_net_leveldb: Populate a net_leveldb_server with initial data via TCP.
// This sends INSERT operations to create the database entries needed for
// YCSB benchmarks.
//
// Usage: ./init_net_leveldb <config.yaml>

#include <iostream>
#include "worker.h"
#include "net_leveldb_client.h"
#include "net_leveldb_config.h"
#include "yaml-cpp/yaml.h"

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s <config file>\n", argv[0]);
		return -EINVAL;
	}

	YAML::Node file = YAML::LoadFile(argv[1]);
	NetLevelDBConfig config = NetLevelDBConfig::parse_yaml(file);

	NetLevelDBFactory factory(config.net_leveldb.addr, config.net_leveldb.port);

	run_init_workload_with_op_measurement(
		"Initialization",
		&factory,
		config.database.nr_entry,
		config.database.key_size,
		config.database.value_size,
		config.workload.nr_init_thread);
}
