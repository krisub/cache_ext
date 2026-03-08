#ifndef YCSB_NET_LEVELDB_CLIENT_H
#define YCSB_NET_LEVELDB_CLIENT_H

#include <atomic>
#include <string>
#include "client.h"

struct NetLevelDBFactory;

/// A My-YCSB client that talks to net_leveldb_server over TCP.
/// The server has block_cache disabled, so all reads go through the OS page
/// cache — this is the key property for testing cache_ext policies.
struct NetLevelDBClient : public Client {
	int sock_fd;
	std::string server_addr;
	int server_port;

	// Reusable buffers to avoid per-op allocations
	char *send_buf;
	size_t send_buf_size;
	char *recv_buf;
	size_t recv_buf_size;

	NetLevelDBClient(NetLevelDBFactory *factory, int id);
	~NetLevelDBClient();
	int do_operation(Operation *op) override;
	int reset() override;
	void close() override;

private:
	bool connect_to_server();
	bool read_exact(void *buf, size_t n);
	bool write_exact(const void *buf, size_t n);
	bool send_request(uint8_t cmd, const char *key, uint32_t key_len,
	                  const char *extra, uint32_t extra_len);
	// Returns status byte, fills resp_data and resp_len
	int recv_response(char **resp_data, uint32_t *resp_len);

	int do_get(char *key_buffer, char **value);
	int do_put(char *key_buffer, char *value_buffer);
	int do_scan(char *key_buffer, long scan_length);
	int do_read_modify_write(char *key_buffer, char *value_buffer);
};

struct NetLevelDBFactory : public ClientFactory {
	std::string server_addr;
	int server_port;
	std::atomic<int> client_id;

	NetLevelDBFactory(const std::string &addr, int port);
	NetLevelDBClient *create_client() override;
	void destroy_client(Client *client) override;
};

#endif // YCSB_NET_LEVELDB_CLIENT_H
