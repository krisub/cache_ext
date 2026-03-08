// run_net_leveldb: My-YCSB benchmark runner for the net_leveldb TCP backend.
// Sends YCSB workload operations over TCP to net_leveldb_server.
//
// Usage: ./run_net_leveldb <config.yaml>

#include <iostream>
#include <unistd.h>
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

	const char *latency_file = nullptr;
	if (!config.measurement.latency_file.empty())
		latency_file = config.measurement.latency_file.c_str();

	NetLevelDBFactory factory(config.net_leveldb.addr, config.net_leveldb.port);

	OpProportion op_prop;
	op_prop.op[READ] = config.workload.operation_proportion.read;
	op_prop.op[UPDATE] = config.workload.operation_proportion.update;
	op_prop.op[INSERT] = config.workload.operation_proportion.insert;
	op_prop.op[SCAN] = config.workload.operation_proportion.scan;
	op_prop.op[READ_MODIFY_WRITE] = config.workload.operation_proportion.read_modify_write;

	for (int i = 0; i < 2; ++i) {
		long nr_op;
		long runtime_seconds;
		if (i == 0) {
			if (config.workload.nr_warmup_op == 0 && config.workload.warmup_runtime_seconds == 0)
				continue;
			nr_op = config.workload.nr_warmup_op;
			runtime_seconds = config.workload.warmup_runtime_seconds;
		} else {
			nr_op = config.workload.nr_op;
			runtime_seconds = config.workload.runtime_seconds;
		}
		if (config.workload.request_distribution == "uniform") {
			run_uniform_workload_with_op_measurement(
				i == 0 ? "Uniform (Warm-Up)" : "Uniform",
				&factory,
				config.database.nr_entry,
				config.database.key_size,
				config.database.value_size,
				config.workload.scan_length,
				config.workload.nr_thread,
				op_prop,
				nr_op,
				runtime_seconds,
				config.workload.next_op_interval_ns,
				latency_file);
		} else if (config.workload.request_distribution == "zipfian") {
			run_zipfian_workload_with_op_measurement(
				i == 0 ? "Zipfian (Warm-Up)" : "Zipfian",
				&factory,
				config.database.nr_entry,
				config.database.key_size,
				config.database.value_size,
				config.workload.scan_length,
				config.workload.nr_thread,
				op_prop,
				config.workload.zipfian_constant,
				nr_op,
				runtime_seconds,
				config.workload.next_op_interval_ns,
				latency_file);
		} else if (config.workload.request_distribution == "latest") {
			run_latest_workload_with_op_measurement(
				i == 0 ? "Latest (Warm-Up)" : "Latest",
				&factory,
				config.database.nr_entry,
				config.database.key_size,
				config.database.value_size,
				config.workload.nr_thread,
				op_prop.op[READ],
				config.workload.zipfian_constant,
				nr_op,
				runtime_seconds,
				config.workload.next_op_interval_ns,
				latency_file);
		} else if (config.workload.request_distribution == "trace") {
			run_trace_workload_with_op_measurement(
				i == 0 ? "Trace (Warm-Up)" : "Trace",
				&factory,
				config.database.key_size,
				config.database.value_size,
				config.workload.nr_thread,
				config.workload.trace_file,
				config.workload.trace_type,
				runtime_seconds,
				config.workload.next_op_interval_ns,
				latency_file);
		} else {
			throw std::invalid_argument("unrecognized workload distribution: " +
			                            config.workload.request_distribution);
		}
	}
}
