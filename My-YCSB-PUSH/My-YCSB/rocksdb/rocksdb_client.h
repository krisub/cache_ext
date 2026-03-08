#ifndef YCSB_WT_CLIENT_H
#define YCSB_WT_CLIENT_H

#include "client.h"
#include "rocksdb/db.h"

struct RocksDBFactory;

struct RocksDBClient : public Client {
	rocksdb::DB *db;

	RocksDBClient(RocksDBFactory *factory, int id);
	~RocksDBClient();
	int do_operation(Operation *op) override;
	int reset() override;
	void close() override;

private:
	int do_update(char *key_buffer, char *value_buffer);
	int do_insert(char *key_buffer, char *value_buffer);
	int do_read(char *key_buffer, char **value);
	int do_scan(char *key_buffer, long scan_length);
	int do_read_modify_write(char *key_buffer, char *value_buffer);
};

struct RocksDBFactory : public ClientFactory {
	rocksdb::DB *db;
	std::atomic<int> client_id;
	std::string data_dir;
	bool print_stats;

	// Private fields
	std::shared_ptr<rocksdb::Cache> _cache;

	RocksDBFactory(std::string data_dir, std::string options_file,
				   long long cache_size, bool print_stats);
	~RocksDBFactory();
	RocksDBClient *create_client() override;
	void destroy_client(Client *client) override;
	void do_print_stats();
	void reset_stats();
};

#endif //YCSB_WT_CLIENT_H
