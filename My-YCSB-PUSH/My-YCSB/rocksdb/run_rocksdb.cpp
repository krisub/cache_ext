#include <iostream>
#include<unistd.h>
#include "worker.h"
#include "rocksdb_client.h"
#include "rocksdb_config.h"

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
	sleep(5);
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
			run_uniform_workload_with_op_measurement(i == 0 ? "Uniform (Warm-Up)" : "Uniform",
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
			                                         nullptr);
		} else if (config.workload.request_distribution == "zipfian") {
			run_zipfian_workload_with_op_measurement(i == 0 ? "Zipfian (Warm-Up)" : "Zipfian",
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
			                                         nullptr);
		} else if (config.workload.request_distribution == "latest") {
			run_latest_workload_with_op_measurement(i == 0 ? "Latest (Warm-Up)" : "Latest",
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
			                                        nullptr);
		// }
		// else if (config.workload.request_distribution == "trace") {
		// 	run_trace_workload_with_op_measurement(i == 0 ? "Trace (Warm-Up)" : "Trace",
		// 	                                       &factory,
		// 	                                       config.database.key_size,
		// 	                                       config.database.value_size,
		// 	                                       config.workload.nr_thread,
		// 	                                       config.workload.trace_file_list,
		// 	                                       nr_op,
		// 										   runtime_seconds,
		// 	                                       config.workload.next_op_interval_ns,
		// 	                                       nullptr);
		} else {
			throw std::invalid_argument("unrecognized workload");
		}
		if (config.rocksdb.print_stats && i == 0) {
			factory.reset_stats();
		}
	}
	if (config.rocksdb.print_stats) {
		factory.do_print_stats();
	}
}
