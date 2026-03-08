#include <iostream>
#include<unistd.h>
#include "worker.h"
#include "io_trace_client.h"
#include "io_trace_config.h"
#include "constants.h"
#include <sys/resource.h>

void ulimit(int n) {
	struct rlimit limit;
	limit.rlim_cur = n;
	limit.rlim_max = n;
	if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
		perror("setrlimit");
		exit(1);
	}
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s <config file>\n", argv[0]);
		return -EINVAL;
	}
	initialize_random_buffer();
	ulimit(1000000);
	YAML::Node file = YAML::LoadFile(argv[1]);
	IOTraceConfig config = IOTraceConfig::parse_yaml(file);

    IOTraceFactory factory(config.io_trace.data_dir,
                           config.io_trace.print_stats,
						   config.workload.nr_thread);
	sleep(5);
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
		if (config.workload.request_distribution == "trace") {
			run_trace_workload_with_op_measurement(i == 0 ? "Trace (Warm-Up)" : "Trace",
			                                       &factory,
			                                       MAX_KEY_SIZE,
			                                       MAX_VALUE_SIZE,
			                                       config.workload.nr_thread,
			                                       config.workload.trace_file,
			                                       "google_bench",
			                                       runtime_seconds,
			                                       config.workload.next_op_interval_ns,
			                                       nullptr);
		} else {
			throw std::invalid_argument("unrecognized workload");
		}
	}
}
