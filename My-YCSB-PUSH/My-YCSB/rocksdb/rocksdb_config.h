#ifndef YCSB_WT_CONFIG_H
#define YCSB_WT_CONFIG_H

#include <string>
#include <list>
#include "yaml-cpp/yaml.h"

using std::string;
using std::list;

struct RocksDBConfig {
	struct {
		long key_size;
		long value_size;
		long nr_entry;
	} database;
	struct {
		long nr_warmup_op;
		long nr_op;
		long warmup_runtime_seconds;
		long runtime_seconds;
		int nr_thread;
		long next_op_interval_ns;
		struct {
			float read;
			float update;
			float insert;
			float scan;
			float read_modify_write;
		} operation_proportion;
		string request_distribution;
		double zipfian_constant;
		list<string> trace_file_list;
		long scan_length;
	} workload;
	struct {
		string data_dir;
		string options_file;
		long long cache_size;
		bool print_stats;
	} rocksdb;

	static RocksDBConfig parse_yaml(YAML::Node &root);
};


RocksDBConfig RocksDBConfig::parse_yaml(YAML::Node &root) {
	RocksDBConfig config;
	YAML::Node database = root["database"];
	config.database.key_size = database["key_size"].as<long>();
	config.database.value_size = database["value_size"].as<long>();
	config.database.nr_entry = database["nr_entry"].as<long>();

	YAML::Node workload = root["workload"];
	config.workload.warmup_runtime_seconds = workload["warmup_runtime_seconds"].as<long>();
	config.workload.runtime_seconds = workload["runtime_seconds"].as<long>();
	config.workload.nr_warmup_op = workload["nr_warmup_op"].as<long>();
	config.workload.nr_op = workload["nr_op"].as<long>();
	config.workload.nr_thread = workload["nr_thread"].as<int>();
	config.workload.next_op_interval_ns = workload["next_op_interval_ns"].as<long>();
	YAML::Node operation_proportion = workload["operation_proportion"];
	config.workload.operation_proportion.read = operation_proportion["read"].as<float>();
	config.workload.operation_proportion.update = operation_proportion["update"].as<float>();
	config.workload.operation_proportion.insert = operation_proportion["insert"].as<float>();
	config.workload.operation_proportion.scan = operation_proportion["scan"].as<float>();
	config.workload.operation_proportion.read_modify_write = operation_proportion["read_modify_write"].as<float>();
	config.workload.request_distribution = workload["request_distribution"].as<string>();
	config.workload.zipfian_constant = workload["zipfian_constant"].as<double>();
	YAML::Node trace_file_list = workload["trace_file_list"];
	for (YAML::iterator iter = trace_file_list.begin(); iter != trace_file_list.end(); ++iter)
		config.workload.trace_file_list.push_back((*iter).as<string>());
	config.workload.scan_length = workload["scan_length"].as<long>();

	YAML::Node rocksdb = root["rocksdb"];
	config.rocksdb.data_dir = rocksdb["data_dir"].as<string>();
	// options_file is optional
	config.rocksdb.options_file = "";
	if (rocksdb["options_file"])
		config.rocksdb.options_file = rocksdb["options_file"].as<string>();
	config.rocksdb.cache_size = rocksdb["cache_size"].as<long long>();
	config.rocksdb.print_stats = rocksdb["print_stats"].as<bool>();

	return config;
}

#endif //YCSB_WT_CONFIG_H
