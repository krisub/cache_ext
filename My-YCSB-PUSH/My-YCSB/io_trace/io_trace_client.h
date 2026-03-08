#ifndef YCSB_WT_CLIENT_H
#define YCSB_WT_CLIENT_H

#include <memory>

#include "client.h"

struct IOTraceFactory;

struct IOTraceClient : public Client {
	std::string data_dir;

	// Private fields
	// std::shared_ptr<ThreadPool> scan_thread_pool_;

	IOTraceClient(IOTraceFactory *factory, int id, std::string data_dir);
	~IOTraceClient();
	int do_operation(Operation *op) override;
	int reset() override;
	void close() override;

private:
	int do_insert(char *key_buffer, char *value_buffer);
	int do_read(char *key_buffer, char *value);
};

struct IOTraceFactory : public ClientFactory {
	std::atomic<int> client_id;
	std::string data_dir;
	bool print_stats;

	// Private fields
	// std::shared_ptr<ThreadPool> scan_thread_pool_;

	IOTraceFactory(std::string data_dir, bool print_stats,
				   int nr_thread);
	~IOTraceFactory();
	IOTraceClient *create_client() override;
	void destroy_client(Client *client) override;
};

#endif //YCSB_WT_CLIENT_H
