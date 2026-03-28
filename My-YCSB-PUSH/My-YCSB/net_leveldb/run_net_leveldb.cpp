// run_net_leveldb: My-YCSB benchmark runner for the net_leveldb TCP backend.
// Sends YCSB workload operations over TCP to net_leveldb_server.
//
// Usage: ./run_net_leveldb <config.yaml>

#include <iostream>
#include <unistd.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include "worker.h"
#include "net_leveldb_client.h"
#include "net_leveldb_config.h"
#include "yaml-cpp/yaml.h"

static std::vector<double> load_rate_schedule_csv(const std::string &path) {
	std::ifstream f(path);
	if (!f) {
		throw std::runtime_error("rate_schedule_file: cannot open " + path);
	}
	std::vector<double> dense;
	std::string line;
	while (std::getline(f, line)) {
		while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front())))
			line.erase(line.begin());
		while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
			line.pop_back();
		if (line.empty() || line[0] == '#')
			continue;
		if (line.find_first_of("0123456789") == std::string::npos)
			continue;
		size_t comma = line.find(',');
		if (comma == std::string::npos) {
			char *endp = nullptr;
			double v = std::strtod(line.c_str(), &endp);
			if (endp == line.c_str())
				continue;
			dense.push_back(v);
		} else {
			char *endp = nullptr;
			double sec = std::strtod(line.c_str(), &endp);
			if (endp == line.c_str())
				continue;
			const char *qps_start = line.c_str() + comma + 1;
			double qps = std::strtod(qps_start, &endp);
			if (endp == qps_start)
				continue;
			int sec_i = static_cast<int>(sec);
			if (sec_i < 0)
				continue;
			if (static_cast<size_t>(sec_i) >= dense.size())
				dense.resize(static_cast<size_t>(sec_i) + 1, 0.0);
			dense[static_cast<size_t>(sec_i)] = qps;
		}
	}
	if (dense.empty())
		throw std::runtime_error("rate_schedule_file: no numeric rows in " + path);
	return dense;
}

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

	std::vector<double> rate_schedule_storage;
	const std::vector<double> *rate_schedule = nullptr;
	if (!config.workload.rate_schedule_file.empty()) {
		rate_schedule_storage = load_rate_schedule_csv(config.workload.rate_schedule_file);
		rate_schedule = &rate_schedule_storage;
		fprintf(stderr, "Loaded rate schedule: %zu entries from %s\n",
		        rate_schedule_storage.size(), config.workload.rate_schedule_file.c_str());
		if (static_cast<long>(rate_schedule_storage.size()) < config.workload.runtime_seconds) {
			fprintf(stderr,
			        "warning: rate schedule length (%zu) < runtime_seconds (%ld); "
			        "last entry repeats\n",
			        rate_schedule_storage.size(), config.workload.runtime_seconds);
		}
	}

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
		const std::vector<double> *sched = nullptr;
		if (i == 1 && rate_schedule != nullptr && !rate_schedule->empty())
			sched = rate_schedule;

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
				latency_file,
				sched);
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
				latency_file,
				sched);
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
				latency_file,
				sched);
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
				latency_file,
				sched);
		} else {
			throw std::invalid_argument("unrecognized workload distribution: " +
			                            config.workload.request_distribution);
		}
	}
	return 0;
}
