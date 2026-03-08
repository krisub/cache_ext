#include <cstring>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "net_leveldb_client.h"

// Protocol constants — must match net_leveldb_server.cc
static constexpr uint8_t CMD_GET  = 1;
static constexpr uint8_t CMD_PUT  = 2;
static constexpr uint8_t CMD_SCAN = 3;
static constexpr uint8_t CMD_RMW  = 4;

static constexpr uint8_t STATUS_OK        = 0;
static constexpr uint8_t STATUS_NOT_FOUND = 1;
// static constexpr uint8_t STATUS_ERROR     = 2;

static constexpr size_t INITIAL_BUF_SIZE = 64 * 1024;

// --------------------------------------------------------------------------
// NetLevelDBClient
// --------------------------------------------------------------------------

NetLevelDBClient::NetLevelDBClient(NetLevelDBFactory *factory, int id)
    : Client(id, factory), sock_fd(-1),
      server_addr(factory->server_addr), server_port(factory->server_port) {
    send_buf_size = INITIAL_BUF_SIZE;
    send_buf = new char[send_buf_size];
    recv_buf_size = INITIAL_BUF_SIZE;
    recv_buf = new char[recv_buf_size];

    if (!connect_to_server()) {
        throw std::runtime_error("NetLevelDBClient: failed to connect to " +
                                 server_addr + ":" + std::to_string(server_port));
    }
}

NetLevelDBClient::~NetLevelDBClient() {
    close();
    delete[] send_buf;
    delete[] recv_buf;
}

bool NetLevelDBClient::connect_to_server() {
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return false;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(server_port));
    if (inet_pton(AF_INET, server_addr.c_str(), &addr.sin_addr) <= 0) {
        fprintf(stderr, "NetLevelDBClient: invalid address %s\n", server_addr.c_str());
        ::close(sock_fd);
        sock_fd = -1;
        return false;
    }

    if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        ::close(sock_fd);
        sock_fd = -1;
        return false;
    }

    // Disable Nagle for lower latency
    int flag = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    return true;
}

bool NetLevelDBClient::read_exact(void *buf, size_t n) {
    size_t total = 0;
    char *p = static_cast<char*>(buf);
    while (total < n) {
        ssize_t r = read(sock_fd, p + total, n - total);
        if (r <= 0) return false;
        total += static_cast<size_t>(r);
    }
    return true;
}

bool NetLevelDBClient::write_exact(const void *buf, size_t n) {
    size_t total = 0;
    const char *p = static_cast<const char*>(buf);
    while (total < n) {
        ssize_t w = write(sock_fd, p + total, n - total);
        if (w <= 0) return false;
        total += static_cast<size_t>(w);
    }
    return true;
}

bool NetLevelDBClient::send_request(uint8_t cmd, const char *key, uint32_t key_len,
                                    const char *extra, uint32_t extra_len) {
    // Header: [1B cmd][4B key_len][4B extra_len]
    uint8_t hdr[9];
    hdr[0] = cmd;
    uint32_t net_key_len = htonl(key_len);
    uint32_t net_extra_len = htonl(extra_len);
    memcpy(hdr + 1, &net_key_len, 4);
    memcpy(hdr + 5, &net_extra_len, 4);

    // Pack into send_buf to reduce syscalls
    size_t total = 9 + key_len + extra_len;
    if (total > send_buf_size) {
        delete[] send_buf;
        send_buf_size = total * 2;
        send_buf = new char[send_buf_size];
    }
    memcpy(send_buf, hdr, 9);
    memcpy(send_buf + 9, key, key_len);
    if (extra_len > 0 && extra != nullptr)
        memcpy(send_buf + 9 + key_len, extra, extra_len);

    return write_exact(send_buf, total);
}

int NetLevelDBClient::recv_response(char **resp_data, uint32_t *resp_len) {
    // Response header: [1B status][4B data_len]
    uint8_t hdr[5];
    if (!read_exact(hdr, 5)) return -1;

    uint8_t status = hdr[0];
    uint32_t data_len;
    memcpy(&data_len, hdr + 1, 4);
    data_len = ntohl(data_len);

    if (data_len > 0) {
        if (data_len > recv_buf_size) {
            delete[] recv_buf;
            recv_buf_size = data_len * 2;
            recv_buf = new char[recv_buf_size];
        }
        if (!read_exact(recv_buf, data_len)) return -1;
    }

    if (resp_data) *resp_data = recv_buf;
    if (resp_len) *resp_len = data_len;
    return static_cast<int>(status);
}

int NetLevelDBClient::do_operation(Operation *op) {
    switch (op->type) {
    case READ:
        return do_get(op->key_buffer, &op->reply_value_buffer);
    case UPDATE:
    case INSERT:
        return do_put(op->key_buffer, op->value_buffer);
    case SCAN:
        return do_scan(op->key_buffer, op->scan_length);
    case READ_MODIFY_WRITE:
        return do_read_modify_write(op->key_buffer, op->value_buffer);
    default:
        throw std::invalid_argument("NetLevelDBClient: invalid op type");
    }
}

int NetLevelDBClient::do_get(char *key_buffer, char **value) {
    uint32_t key_len = static_cast<uint32_t>(strlen(key_buffer));
    if (!send_request(CMD_GET, key_buffer, key_len, nullptr, 0)) {
        fprintf(stderr, "NetLevelDBClient: GET send failed\n");
        return -1;
    }

    char *resp_data = nullptr;
    uint32_t resp_len = 0;
    int status = recv_response(&resp_data, &resp_len);
    if (status < 0) {
        fprintf(stderr, "NetLevelDBClient: GET recv failed\n");
        return -1;
    }
    if (status == STATUS_OK && resp_len > 0 && value && *value) {
        memcpy(*value, resp_data, resp_len);
        (*value)[resp_len] = '\0';
    }
    return (status == STATUS_OK || status == STATUS_NOT_FOUND) ? 0 : -1;
}

int NetLevelDBClient::do_put(char *key_buffer, char *value_buffer) {
    uint32_t key_len = static_cast<uint32_t>(strlen(key_buffer));
    uint32_t val_len = static_cast<uint32_t>(strlen(value_buffer));
    if (!send_request(CMD_PUT, key_buffer, key_len, value_buffer, val_len)) {
        fprintf(stderr, "NetLevelDBClient: PUT send failed\n");
        return -1;
    }

    int status = recv_response(nullptr, nullptr);
    if (status < 0) {
        fprintf(stderr, "NetLevelDBClient: PUT recv failed\n");
        return -1;
    }
    return (status == STATUS_OK) ? 0 : -1;
}

int NetLevelDBClient::do_scan(char *key_buffer, long scan_length) {
    uint32_t key_len = static_cast<uint32_t>(strlen(key_buffer));
    uint32_t net_scan_len = htonl(static_cast<uint32_t>(scan_length));
    if (!send_request(CMD_SCAN, key_buffer, key_len,
                      reinterpret_cast<char*>(&net_scan_len), 4)) {
        fprintf(stderr, "NetLevelDBClient: SCAN send failed\n");
        return -1;
    }

    int status = recv_response(nullptr, nullptr);
    if (status < 0) {
        fprintf(stderr, "NetLevelDBClient: SCAN recv failed\n");
        return -1;
    }
    return (status == STATUS_OK) ? 0 : -1;
}

int NetLevelDBClient::do_read_modify_write(char *key_buffer, char *value_buffer) {
    uint32_t key_len = static_cast<uint32_t>(strlen(key_buffer));
    uint32_t val_len = static_cast<uint32_t>(strlen(value_buffer));
    if (!send_request(CMD_RMW, key_buffer, key_len, value_buffer, val_len)) {
        fprintf(stderr, "NetLevelDBClient: RMW send failed\n");
        return -1;
    }

    int status = recv_response(nullptr, nullptr);
    if (status < 0) {
        fprintf(stderr, "NetLevelDBClient: RMW recv failed\n");
        return -1;
    }
    return (status == STATUS_OK) ? 0 : -1;
}

int NetLevelDBClient::reset() {
    return 0;
}

void NetLevelDBClient::close() {
    if (sock_fd >= 0) {
        ::close(sock_fd);
        sock_fd = -1;
    }
}

// --------------------------------------------------------------------------
// NetLevelDBFactory
// --------------------------------------------------------------------------

NetLevelDBFactory::NetLevelDBFactory(const std::string &addr, int port)
    : server_addr(addr), server_port(port), client_id(0) {}

NetLevelDBClient *NetLevelDBFactory::create_client() {
    return new NetLevelDBClient(this, client_id++);
}

void NetLevelDBFactory::destroy_client(Client *client) {
    auto *c = static_cast<NetLevelDBClient*>(client);
    c->close();
    delete c;
}
