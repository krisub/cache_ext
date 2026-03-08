#ifndef YCSB_WT_CLIENT_H
#define YCSB_WT_CLIENT_H

#include <memory>

#include "client.h"
#include "leveldb/db.h"
//#include "threadpool.h"

struct LevelDBFactory;

struct LevelDBClient : public Client {
	leveldb::DB *db;

	// Private fields
	// std::shared_ptr<ThreadPool> scan_thread_pool_;

	LevelDBClient(LevelDBFactory *factory, int id);
	~LevelDBClient();
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

struct LevelDBFactory : public ClientFactory {
	leveldb::DB *db;
	std::atomic<int> client_id;
	std::string data_dir;
	bool print_stats;

	// Private fields
	// std::shared_ptr<ThreadPool> scan_thread_pool_;

	LevelDBFactory(std::string data_dir, std::string options_file,
				   long long cache_size, bool print_stats,
				   int nr_thread);
	~LevelDBFactory();
	LevelDBClient *create_client() override;
	void destroy_client(Client *client) override;
	void do_print_stats();
	void reset_stats();
};

#endif //YCSB_WT_CLIENT_H
