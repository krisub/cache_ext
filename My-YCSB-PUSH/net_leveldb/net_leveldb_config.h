#ifndef YCSB_NET_LEVELDB_CONFIG_H
#define YCSB_NET_LEVELDB_CONFIG_H

#include <string>
#include "yaml-cpp/yaml.h"

using std::string;

/// Configuration for the net_leveldb My-YCSB backend.
/// Similar to RedisConfig but connects to net_leveldb_server instead.
struct NetLevelDBConfig {
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
		int nr_init_thread;
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
		long scan_length;
		string trace_file;
		string trace_type;
	} workload;
	struct {
		string latency_file;
	} measurement;
	struct {
		string addr;
		int port;
	} net_leveldb;

	static NetLevelDBConfig parse_yaml(YAML::Node &root);
};

NetLevelDBConfig NetLevelDBConfig::parse_yaml(YAML::Node &root) {
	NetLevelDBConfig config;

	YAML::Node database = root["database"];
	config.database.key_size = database["key_size"].as<long>();
	config.database.value_size = database["value_size"].as<long>();
	config.database.nr_entry = database["nr_entry"].as<long>();

	YAML::Node workload = root["workload"];
	config.workload.nr_warmup_op = workload["nr_warmup_op"] ? workload["nr_warmup_op"].as<long>() : 0;
	config.workload.nr_op = workload["nr_op"].as<long>();
	config.workload.warmup_runtime_seconds = workload["warmup_runtime_seconds"] ? workload["warmup_runtime_seconds"].as<long>() : 0;
	config.workload.runtime_seconds = workload["runtime_seconds"] ? workload["runtime_seconds"].as<long>() : 0;
	config.workload.nr_init_thread = workload["nr_init_thread"] ? workload["nr_init_thread"].as<int>() : 1;
	config.workload.nr_thread = workload["nr_thread"].as<int>();
	config.workload.next_op_interval_ns = workload["next_op_interval_ns"] ? workload["next_op_interval_ns"].as<long>() : 0;
	YAML::Node operation_proportion = workload["operation_proportion"];
	config.workload.operation_proportion.read = operation_proportion["read"].as<float>();
	config.workload.operation_proportion.update = operation_proportion["update"].as<float>();
	config.workload.operation_proportion.insert = operation_proportion["insert"].as<float>();
	config.workload.operation_proportion.scan = operation_proportion["scan"].as<float>();
	config.workload.operation_proportion.read_modify_write = operation_proportion["read_modify_write"].as<float>();
	config.workload.request_distribution = workload["request_distribution"].as<string>();
	config.workload.zipfian_constant = workload["zipfian_constant"] ? workload["zipfian_constant"].as<double>() : 0.99;
	config.workload.scan_length = workload["scan_length"] ? workload["scan_length"].as<long>() : 100;
	config.workload.trace_file = "";
	if (workload["trace_file"])
		config.workload.trace_file = workload["trace_file"].as<string>();
	config.workload.trace_type = "";
	if (workload["trace_type"])
		config.workload.trace_type = workload["trace_type"].as<string>();

	YAML::Node measurement = root["measurement"];
	config.measurement.latency_file = measurement["latency_file"] ? measurement["latency_file"].as<string>() : "";

	YAML::Node net_leveldb = root["net_leveldb"];
	config.net_leveldb.addr = net_leveldb["addr"].as<string>();
	config.net_leveldb.port = net_leveldb["port"].as<int>();

	return config;
}

#endif // YCSB_NET_LEVELDB_CONFIG_H
