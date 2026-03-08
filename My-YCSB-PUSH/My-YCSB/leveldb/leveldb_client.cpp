#include <memory>
#include <string>
#include <iostream>
#include <atomic>
#include <fcntl.h>

#include "leveldb/db.h"
#include "leveldb/options.h"
#include "leveldb/status.h"

#include "leveldb_client.h"

std::atomic<unsigned int> key_fails = 0;

LevelDBClient::LevelDBClient(LevelDBFactory *factory, int id)
	: Client(id, factory) {
	this->db = factory->db;
	}

LevelDBClient::~LevelDBClient() {}

int LevelDBClient::do_operation(Operation *op) {
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
		// ret = this->scan_thread_pool_->enqueue([&] {
		// 	return this->do_scan(op->key_buffer, op->scan_length);
		// }).get();
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

int LevelDBClient::do_read(char *key_buffer, char **value) {
	leveldb::Status status;
	leveldb::Slice key(key_buffer);
	std::string value_str;

	leveldb::ReadOptions read_options = leveldb::ReadOptions();

	status = this->db->Get(read_options, key_buffer, &value_str);
	if (!status.ok()) {
		fprintf(stderr, "LevelDBClient: read failed, ret: %s\n", status.ToString().c_str());
		return -1;
	}
	memcpy(*value, value_str.c_str(), value_str.size());
	(*value)[value_str.size()] = '\0';
	return 0;
}

int LevelDBClient::do_update(char *key_buffer, char *value_buffer) {
	return this->do_read_modify_write(key_buffer, value_buffer);
}

int LevelDBClient::do_insert(char *key_buffer, char *value_buffer) {
	leveldb::Status status;
	leveldb::Slice key(key_buffer), value(value_buffer);

	status = this->db->Put(leveldb::WriteOptions(), key, value);
	if (!status.ok()) {
		fprintf(stderr, "LevelDBClient: update failed, ret: %s\n", status.ToString().c_str());
		return -1;
	}
	return 0;
}

int LevelDBClient::do_read_modify_write(char *key_buffer, char *value_buffer) {
	int ret;
	char *old_value = new char[strlen(value_buffer)+1];
	ret = this->do_read(key_buffer, &old_value);
	delete[] old_value;
	if (ret != 0) {
		return ret;
	}
	return this->do_insert(key_buffer, value_buffer);
}

int LevelDBClient::do_scan(char *key_buffer, long scan_length) {

	if (key_buffer == nullptr) {
		fprintf(stderr, "LevelDBClient: scan failed, key_buffer is null\n");
		return -1;
	}

	// fprintf(stderr, "SCAN: Start\n");
	leveldb::ReadOptions read_options = leveldb::ReadOptions();
	// If running in cache_ext mode, don't set the is_scan flag
	// Read the ENABLE_BPF_SCAN_MAP environment variable
	char* fadvise_hint_str = getenv("ENABLE_SCAN_FADVISE");
	int fadvise_hint;
	if (fadvise_hint_str != nullptr) {
		read_options.is_scan = true;
		if (strcmp(fadvise_hint_str, "NOREUSE") == 0) {
			fadvise_hint = POSIX_FADV_NOREUSE;
		} else if (strcmp(fadvise_hint_str, "SEQUENTIAL") == 0) {
			fadvise_hint = POSIX_FADV_SEQUENTIAL;
		} else if (strcmp(fadvise_hint_str, "DONTNEED") == 0) {
			fadvise_hint = POSIX_FADV_DONTNEED;
		} else {
			fprintf(stderr, "LevelDBClient: scan failed, invalid fadvise hint: %s\n",
				fadvise_hint_str);
			return -1;
		}
	} else {
		read_options.is_scan = false;
	}
	leveldb::Iterator* it = this->db->NewIterator(read_options);
	// fprintf(stderr, "SCAN: Iterator created\n");


	if (it == nullptr) {
		fprintf(stderr, "LevelDBClient: scan failed, unable to create iterator\n");
		return -1;
	}

	// Seek to the starting key
	it->Seek(key_buffer);
	if (!it->status().ok()) {
		fprintf(stderr, "LevelDBClient: seek for scan failed, ret: %s\n", it->status().ToString().c_str());
		delete it;
		return -1;
	}

	// fprintf(stderr, "SCAN: Seeked to key\n");

	// Perform the scan
	long count = 0;
	for (; it->Valid() && count < scan_length; it->Next()) {
		// Get the key and value
		leveldb::Slice key = it->key();
		leveldb::Slice value = it->value();

		// Process the key-value pair
		// ...

		count++;
	}

	// fprintf(stderr, "SCAN: Done\n");

	// Check for errors or end of scan
	if (!it->status().ok()) {
		fprintf(stderr, "LevelDBClient: scan failed, ret: %s\n", it->status().ToString().c_str());
		delete it;
		return -1;
	}

	if (count < scan_length) {
		fprintf(stderr, "LevelDB: scan ended prematurely, %ld instead of %ld\n",
			count, scan_length);
	}

	delete it;
	return 0;
}

int LevelDBClient::reset() {return 0;}

void LevelDBClient::close() {}

LevelDBFactory::LevelDBFactory(std::string data_dir, std::string options_file,
							   long long cache_size, bool print_stats,
							   int nr_thread): client_id(0) {
	this->data_dir = data_dir;
	this->print_stats = print_stats;
	// this->scan_thread_pool_ = std::make_shared<ThreadPool>(nr_thread);
	// If the ENABLE_BPF_SCAN_MAP environment variable exists, fill the map


	fprintf(stderr, "LevelDBFactory: data_dir: %s, print_stats: %d\n",
		data_dir.c_str(), print_stats);

	leveldb::DB* db;
	leveldb::Status status;
	leveldb::Options options;

	// options.write_buffer_size = 1024 * 1024 * 256;

	options.create_if_missing = true;
	status = leveldb::DB::Open(options, data_dir, &db);

	if (!status.ok()) {
		fprintf(stderr, "LevelDBFactory: failed to open db, ret: %s\n", status.ToString().c_str());
		throw std::invalid_argument("failed to open db");
	}
	this->db = db;
}

LevelDBFactory::~LevelDBFactory() {
	delete this->db;
}

void leveldb_print_stat(leveldb::DB *db, const char* key) {
	fprintf(stdout, "\n==== DB ===\n");
	std::string stats;
	if (!db->GetProperty(key, &stats)) {
		stats = "(failed)";
	}

	fprintf(stdout, "\n%s\n", stats.c_str());
}

void LevelDBFactory::do_print_stats() {
	fprintf(stdout, "=== LevelDB Stats Start ===\n");
	leveldb_print_stat(this->db, "leveldb.stats");
	fprintf(stdout, "=== LevelDB Stats End ===\n");
}

void LevelDBFactory::reset_stats() {
	// no-op
}

LevelDBClient * LevelDBFactory::create_client() {
	auto client = new LevelDBClient(this, this->client_id++);
	// client->scan_thread_pool_ = this->scan_thread_pool_;
	return client;
}

void LevelDBFactory::destroy_client(Client *client) {
	LevelDBClient *leveldb_client = static_cast<LevelDBClient *>(client);
	delete leveldb_client;
}
