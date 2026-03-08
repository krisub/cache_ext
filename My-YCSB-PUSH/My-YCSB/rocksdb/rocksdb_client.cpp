#include <string>
#include <iostream>
#include <atomic>

#include "rocksdb_client.h"
#include "rocksdb/cache.h"
#include "rocksdb/customizable.h"
#include "rocksdb/env.h"
#include "rocksdb/options.h"
#include "rocksdb/status.h"
#include "rocksdb/statistics.h"
#include "rocksdb/utilities/options_util.h"

std::atomic<unsigned int> key_fails = 0;

RocksDBClient::RocksDBClient(RocksDBFactory *factory, int id)
	: Client(id, factory) {
	this->db = factory->db;
	}

RocksDBClient::~RocksDBClient() {}

int RocksDBClient::do_operation(Operation *op) {
	int ret = 0;
repeat:
	switch (op->type) {
	case UPDATE:
		ret = this->do_update(op->key_buffer, op->value_buffer);
		break;
	case INSERT:
		ret = this->do_insert(op->key_buffer, op->value_buffer);
		break;
	case READ:
		ret = this->do_read(op->key_buffer, &op->value_buffer);
		break;
	case SCAN:
		ret = this->do_scan(op->key_buffer, op->scan_length);
		break;
	case READ_MODIFY_WRITE:
		ret = this->do_read_modify_write(op->key_buffer, op->value_buffer);
		break;
	default:
		throw std::invalid_argument("invalid op type");
	}
	if (ret < 0) {
		std::cout << "Key actually failed: " << op->key_buffer << std::endl;
		//goto repeat;
	}
	return ret;
}

int RocksDBClient::do_read(char *key_buffer, char **value) {
	rocksdb::Status status;
	rocksdb::Slice key(key_buffer);
	std::string value_str;

	rocksdb::ReadOptions read_options = rocksdb::ReadOptions();

	status = this->db->Get(read_options, key_buffer, &value_str);
	if (!status.ok()) {
		fprintf(stderr, "RocksDBClient: read failed, key: %s ret: %s\n", key_buffer, status.ToString().c_str());
		++key_fails;

#ifdef CONFIG_BPFOF
		read_options.force_sample = true;
		status = this->db->Get(read_options, key_buffer, &value_str);
		if (!status.ok())
			return -1;
#else
		return -1;
#endif
	}
	memcpy(*value, value_str.c_str(), value_str.size());
	(*value)[value_str.size()] = '\0';
	return 0;
}

int RocksDBClient::do_update(char *key_buffer, char *value_buffer) {
	return this->do_read_modify_write(key_buffer, value_buffer);
}

int RocksDBClient::do_insert(char *key_buffer, char *value_buffer) {
	rocksdb::Status status;
	rocksdb::Slice key(key_buffer), value(value_buffer);
	std::string value_str;

	status = this->db->Put(rocksdb::WriteOptions(), key, value);
	if (!status.ok()) {
		fprintf(stderr, "RocksDBClient: update failed, ret: %s\n", status.ToString().c_str());
		return -1;
	}
	return 0;
}

int RocksDBClient::do_read_modify_write(char *key_buffer, char *value_buffer) {
	int ret;
	char *old_value = new char[strlen(value_buffer)+1];
	ret = this->do_read(key_buffer, &old_value);
	delete[] old_value;
	if (ret != 0) {
		return ret;
	}
	return this->do_insert(key_buffer, value_buffer);
}

int RocksDBClient::do_scan(char *key_buffer, long scan_length) {
    rocksdb::Iterator* it = this->db->NewIterator(rocksdb::ReadOptions());
    std::string start_key(key_buffer);
    int count = 0;
    
    for (it->Seek(start_key); it->Valid() && count < scan_length; it->Next()) {
        // Process the key-value pair pointed by the iterator
        // For example, print them out, store them, etc.
        // std::cout << it->key().ToString() << ": "  << it->value().ToString() << std::endl;
        ++count;
    }

    if (!it->status().ok()) { // Check for any errors found during the scan
        delete it;
        return -1;
    }

    delete it;
    return 0;
}

int RocksDBClient::reset() {return 0;}

void RocksDBClient::close() {}

RocksDBFactory::RocksDBFactory(std::string data_dir, std::string options_file,
							   long long cache_size, bool print_stats): client_id(0) {
	this->data_dir = data_dir;
	this->print_stats = print_stats;

	rocksdb::Status status;
	rocksdb::Options options;
	rocksdb::DBOptions db_options;
	std::vector<rocksdb::ColumnFamilyDescriptor> cf_descs;
	std::vector<rocksdb::ColumnFamilyHandle *> cf_handles;

	fprintf(stderr, "RocksDBFactory: data_dir: %s, options_file: %s, cache_size: %lldMB, print_stats: %d\n",
		data_dir.c_str(), options_file.c_str(), cache_size / 1000000, print_stats);
	if (options_file == "") {
		throw std::invalid_argument("you really want to specify an options file!");
	}
	this->_cache = rocksdb::NewLRUCache(cache_size);

    // make config_options
    rocksdb::ConfigOptions config_options;

	if (options_file != "") {
		status = rocksdb::LoadOptionsFromFile(config_options, options_file, &db_options, &cf_descs);
		if (!status.ok()) {
			fprintf(stderr, "RocksDBFactory: failed to load options from file, ret: %s\n", status.ToString().c_str());
			throw std::invalid_argument("failed to load options from file");
		}
		if (this->print_stats) {
			db_options.statistics = rocksdb::CreateDBStatistics();
			db_options.statistics->set_stats_level(rocksdb::StatsLevel::kAll);
		}
		auto existing_table_options = cf_descs[0].options.table_factory->GetOptions<rocksdb::BlockBasedTableOptions>();
		existing_table_options->block_cache = this->_cache;
		status = rocksdb::DB::Open(db_options, data_dir, cf_descs, &cf_handles, &this->db);
	} else {
		auto existing_table_options = options.table_factory->GetOptions<rocksdb::BlockBasedTableOptions>();
		existing_table_options->block_cache = this->_cache;
		options.create_if_missing = true;
		if (this->print_stats) {
			options.statistics = rocksdb::CreateDBStatistics();
		}
		status = rocksdb::DB::Open(options, data_dir, &this->db);
	}
	if (!status.ok()) {
		fprintf(stderr, "RocksDBFactory: failed to open db, ret: %s\n", status.ToString().c_str());
		throw std::invalid_argument("failed to open db");
	}
	fprintf(stderr, "RocksDBFactory: DB has '%d' levels\n" , this->db->NumberLevels());
}

RocksDBFactory::~RocksDBFactory() {
	delete this->db;
	this->_cache.reset();
}

void rocksdb_print_stat(rocksdb::DB *db, const char* key) {
	fprintf(stdout, "\n==== DB: %s ===\n", db->GetName().c_str());
	std::string stats;
	if (!db->GetProperty(key, &stats)) {
		stats = "(failed)";
	}

	fprintf(stdout, "\n%s\n", stats.c_str());
}

void RocksDBFactory::do_print_stats() {
	rocksdb_print_stat(this->db, "rocksdb.levelstats");
	rocksdb_print_stat(this->db, "rocksdb.stats");
	//fprintf(stderr, "Cache usage: %luMB\n", this->_cache->GetUsage() / 1000000);
	fprintf(stdout, "=== RocksDB Stats Start ===\n");
	fprintf(stdout, "%s\n", this->db->GetOptions().statistics->ToString().c_str());
	fprintf(stdout, "=== RocksDB Stats End ===\n");
}

void RocksDBFactory::reset_stats() {
	// Start gathering RocksDB stats
	this->db->GetOptions().statistics->Reset();
	key_fails = 0;
}

RocksDBClient * RocksDBFactory::create_client() {
	return new RocksDBClient(this, this->client_id++);
}

void RocksDBFactory::destroy_client(Client *client) {
	RocksDBClient *rocksdb_client = (RocksDBClient *)client;
	delete rocksdb_client;
}
