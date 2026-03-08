#ifndef YCSB_WT_CONFIG_H
#define YCSB_WT_CONFIG_H

#include <string>
#include <list>
#include "yaml-cpp/yaml.h"

using std::string;
using std::list;

struct IOTraceConfig {
	struct {
		long nr_warmup_op;
		long nr_op;
		long warmup_runtime_seconds;
		long runtime_seconds;
		int nr_thread;
		long next_op_interval_ns;
		string trace_file;
		string request_distribution;
	} workload;
	struct {
		string data_dir;
		bool print_stats;
	} io_trace;

	static IOTraceConfig parse_yaml(YAML::Node &root);
};


IOTraceConfig IOTraceConfig::parse_yaml(YAML::Node &root) {
	IOTraceConfig config;
	YAML::Node workload = root["workload"];
	config.workload.nr_warmup_op = workload["nr_warmup_op"].as<long>();
	config.workload.nr_op = workload["nr_op"].as<long>();
	config.workload.warmup_runtime_seconds = workload["warmup_runtime_seconds"].as<long>();
	config.workload.runtime_seconds = workload["runtime_seconds"].as<long>();
	config.workload.nr_thread = workload["nr_thread"].as<int>();
	config.workload.next_op_interval_ns = workload["next_op_interval_ns"].as<long>();
	config.workload.trace_file = workload["trace_file"].as<string>();
	config.workload.request_distribution = workload["request_distribution"].as<string>();

	YAML::Node io_trace = root["io_trace"];
	config.io_trace.data_dir = io_trace["data_dir"].as<string>();
	config.io_trace.print_stats = io_trace["print_stats"].as<bool>();

	return config;
}

#endif //YCSB_WT_CONFIG_H
