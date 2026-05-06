// net_leveldb_server: A TCP server wrapping LevelDB with NO application-level
// block cache. All data reads go through the OS page cache, making this ideal
// for testing page cache eviction policies with cache_ext.
//
// Architecture:
//   [My-YCSB client] --TCP--> [net_leveldb_server in cgroup] --page cache--> [disk]
//
// The server runs inside a memory cgroup so that:
//   1. The page cache for LevelDB's .ldb files is constrained
//   2. cache_ext eBPF policies manage eviction within the cgroup
//   3. block_cache=NULL ensures NO app-level caching — all reads must hit page cache
//
// Build:
//   g++ net_leveldb_server.cc -o net_leveldb_server -lleveldb -lsnappy -lpthread -O2
//
// Usage:
//   ./net_leveldb_server <port> <db_path> [--populate]
//
// Wire protocol (binary, network byte order):
//
// Request:
//   [1B cmd] [4B key_len] [4B extra_len] [key_len bytes key] [extra_len bytes data]
//   cmd: 1=GET, 2=PUT, 3=SCAN, 4=READ_MODIFY_WRITE
//   For GET: extra_len=0
//   For PUT: extra_len=value_len, data=value
//   For SCAN: extra_len=4, data=scan_length (uint32 network order)
//   For READ_MODIFY_WRITE: extra_len=value_len, data=new_value
//
// Response:
//   [1B status] [4B data_len] [data_len bytes data]
//   status: 0=OK, 1=NOT_FOUND, 2=ERROR
//   For GET: data=value
//   For PUT: data_len=0
//   For SCAN: data_len=4, data=num_scanned (uint32 network order)
//   For READ_MODIFY_WRITE: data_len=0

/*
# Build everything
cd /mydata/cache_ext
./build_net_leveldb.sh

# Run a networked page cache benchmark
cd bench
python bench_net_leveldb.py \
  --leveldb-db /mydata/leveldb_db \
  --bench-binary-dir /mydata/cache_ext/My-YCSB/build \
  --server-binary /mydata/cache_ext/net_leveldb_server \
  --policy-loader /mydata/cache_ext/policies/build/cache_ext_lru.out \
  --benchmark ycsb_c \
  --cgroup-size-gib 10
*/

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <thread>
#include <arpa/inet.h>
#include <signal.h>
#include <atomic>
#include <fstream>
#include <endian.h>

#include "leveldb/db.h"
#include "leveldb/write_batch.h"
#include "leveldb/cache.h"

// Protocol constants
static constexpr uint8_t CMD_GET  = 1;
static constexpr uint8_t CMD_PUT  = 2;
static constexpr uint8_t CMD_SCAN = 3;
static constexpr uint8_t CMD_RMW  = 4;  // READ_MODIFY_WRITE
static constexpr uint8_t CMD_RESET_STATS = 5;
static constexpr uint8_t CMD_GET_STATS = 6;

static constexpr uint8_t STATUS_OK        = 0;
static constexpr uint8_t STATUS_NOT_FOUND = 1;
static constexpr uint8_t STATUS_ERROR     = 2;

static constexpr size_t REQUEST_HEADER_SIZE = 9;  // 1 + 4 + 4
static constexpr size_t MAX_KEY_SIZE = 1024;
static constexpr size_t MAX_VALUE_SIZE = 64 * 1024;  // 64KB max value

static std::atomic<uint64_t> g_read_requests{0};
static std::atomic<uint64_t> g_read_misses{0};

static uint64_t read_proc_self_read_bytes() {
    std::ifstream f("/proc/self/io");
    if (!f.is_open()) return 0;
    std::string key;
    uint64_t value = 0;
    while (f >> key >> value) {
        if (key == "read_bytes:") return value;
    }
    return 0;
}

// Read exactly n bytes from socket, returns false on error/disconnect
static bool read_exact(int fd, void *buf, size_t n) {
    size_t total = 0;
    char *p = static_cast<char*>(buf);
    while (total < n) {
        ssize_t r = read(fd, p + total, n - total);
        if (r <= 0) return false;
        total += static_cast<size_t>(r);
    }
    return true;
}

// Write exactly n bytes to socket
static bool write_exact(int fd, const void *buf, size_t n) {
    size_t total = 0;
    const char *p = static_cast<const char*>(buf);
    while (total < n) {
        ssize_t w = write(fd, p + total, n - total);
        if (w <= 0) return false;
        total += static_cast<size_t>(w);
    }
    return true;
}

// Send a response: [1B status][4B data_len][data]
static bool send_response(int fd, uint8_t status, const char *data, uint32_t data_len) {
    uint8_t hdr[5];
    hdr[0] = status;
    uint32_t net_len = htonl(data_len);
    memcpy(hdr + 1, &net_len, 4);
    if (!write_exact(fd, hdr, 5)) return false;
    if (data_len > 0 && data != nullptr) {
        if (!write_exact(fd, data, data_len)) return false;
    }
    return true;
}

// Populate DB with test data
void populate_db(leveldb::DB* db, long nr_entry, int value_size) {
    std::cout << "Populating DB with " << nr_entry << " keys (value_size=" << value_size << ")..." << std::endl;
    leveldb::WriteOptions write_options;
    write_options.sync = false;
    leveldb::WriteBatch batch;
    std::string value(static_cast<size_t>(value_size), 'x');

    for (long i = 0; i < nr_entry; ++i) {
        // Use zero-padded key format matching My-YCSB: "user0000000000000001"
        char key_buf[64];
        snprintf(key_buf, sizeof(key_buf), "user%016ld", i);
        batch.Put(key_buf, value);
        if ((i + 1) % 10000 == 0) {
            db->Write(write_options, &batch);
            batch.Clear();
            if ((i + 1) % 100000 == 0)
                std::cout << "  Inserted " << (i + 1) << " / " << nr_entry << std::endl;
        }
    }
    if (batch.ApproximateSize() > 0)
        db->Write(write_options, &batch);
    std::cout << "Population complete." << std::endl;
}

void handle_client(int socket_fd, leveldb::DB* db) {
    // Per-connection buffers
    std::vector<char> key_buf(MAX_KEY_SIZE);
    std::vector<char> extra_buf(MAX_VALUE_SIZE);
    std::string value_str;

    while (true) {
        // Read request header: [1B cmd][4B key_len][4B extra_len]
        uint8_t hdr[REQUEST_HEADER_SIZE];
        if (!read_exact(socket_fd, hdr, REQUEST_HEADER_SIZE))
            break;

        uint8_t cmd = hdr[0];
        uint32_t key_len, extra_len;
        memcpy(&key_len, hdr + 1, 4);
        memcpy(&extra_len, hdr + 5, 4);
        key_len = ntohl(key_len);
        extra_len = ntohl(extra_len);

        // Validate sizes
        if (cmd == CMD_RESET_STATS || cmd == CMD_GET_STATS) {
            if (key_len != 0 || extra_len != 0) {
                send_response(socket_fd, STATUS_ERROR, nullptr, 0);
                break;
            }
        } else {
            if (key_len == 0 || key_len > MAX_KEY_SIZE) {
                send_response(socket_fd, STATUS_ERROR, nullptr, 0);
                break;
            }
            if (extra_len > MAX_VALUE_SIZE) {
                send_response(socket_fd, STATUS_ERROR, nullptr, 0);
                break;
            }
        }

        // Read key (if any)
        std::string key;
        if (key_len > 0) {
            if (!read_exact(socket_fd, key_buf.data(), key_len))
                break;
            key.assign(key_buf.data(), key_len);
        }

        // Read extra data
        if (extra_len > 0) {
            if (extra_buf.size() < extra_len)
                extra_buf.resize(extra_len);
            if (!read_exact(socket_fd, extra_buf.data(), extra_len))
                break;
        }

        switch (cmd) {
        case CMD_RESET_STATS: {
            g_read_requests.store(0, std::memory_order_relaxed);
            g_read_misses.store(0, std::memory_order_relaxed);
            send_response(socket_fd, STATUS_OK, nullptr, 0);
            break;
        }
        case CMD_GET_STATS: {
            uint64_t req = g_read_requests.load(std::memory_order_relaxed);
            uint64_t miss = g_read_misses.load(std::memory_order_relaxed);
            uint64_t payload[2];
            payload[0] = htobe64(req);
            payload[1] = htobe64(miss);
            send_response(socket_fd, STATUS_OK, reinterpret_cast<const char*>(payload), sizeof(payload));
            break;
        }
        case CMD_GET: {
            uint64_t rb_before = read_proc_self_read_bytes();
            leveldb::ReadOptions read_opts;
            leveldb::Status status = db->Get(read_opts, key, &value_str);
            uint64_t rb_after = read_proc_self_read_bytes();
            g_read_requests.fetch_add(1, std::memory_order_relaxed);
            if (rb_after > rb_before) {
                g_read_misses.fetch_add(1, std::memory_order_relaxed);
            }
            if (status.ok()) {
                send_response(socket_fd, STATUS_OK,
                              value_str.data(), static_cast<uint32_t>(value_str.size()));
            } else if (status.IsNotFound()) {
                send_response(socket_fd, STATUS_NOT_FOUND, nullptr, 0);
            } else {
                send_response(socket_fd, STATUS_ERROR, nullptr, 0);
            }
            break;
        }

        case CMD_PUT: {
            std::string value(extra_buf.data(), extra_len);
            leveldb::WriteOptions write_opts;
            leveldb::Status status = db->Put(write_opts, key, value);
            if (status.ok()) {
                send_response(socket_fd, STATUS_OK, nullptr, 0);
            } else {
                send_response(socket_fd, STATUS_ERROR, nullptr, 0);
            }
            break;
        }

        case CMD_SCAN: {
            // extra_len should be 4 (scan_length as uint32)
            uint32_t scan_length = 0;
            if (extra_len >= 4) {
                memcpy(&scan_length, extra_buf.data(), 4);
                scan_length = ntohl(scan_length);
            }
            if (scan_length == 0) scan_length = 100;

            leveldb::ReadOptions read_opts;
            leveldb::Iterator* it = db->NewIterator(read_opts);
            uint32_t scanned = 0;
            for (it->Seek(key); it->Valid() && scanned < scan_length; it->Next()) {
                // Touch the value to ensure page cache access
                leveldb::Slice v = it->value();
                (void)v.data()[0];
                scanned++;
            }
            delete it;

            // Send back count of scanned entries
            uint32_t net_scanned = htonl(scanned);
            send_response(socket_fd, STATUS_OK,
                          reinterpret_cast<char*>(&net_scanned), 4);
            break;
        }

        case CMD_RMW: {
            // Read then write
            leveldb::ReadOptions read_opts;
            leveldb::Status status = db->Get(read_opts, key, &value_str);
            if (!status.ok() && !status.IsNotFound()) {
                send_response(socket_fd, STATUS_ERROR, nullptr, 0);
                break;
            }
            // Write the new value
            std::string new_value(extra_buf.data(), extra_len);
            leveldb::WriteOptions write_opts;
            status = db->Put(write_opts, key, new_value);
            if (status.ok()) {
                send_response(socket_fd, STATUS_OK, nullptr, 0);
            } else {
                send_response(socket_fd, STATUS_ERROR, nullptr, 0);
            }
            break;
        }

        default:
            send_response(socket_fd, STATUS_ERROR, nullptr, 0);
            break;
        }
    }
    close(socket_fd);
}

void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <port> <db_path> [--populate] [--nr-entry N] [--value-size N]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "  Starts a LevelDB TCP server with NO block cache.\n");
    fprintf(stderr, "  All reads go through the OS page cache.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --populate       Populate the DB with test data then exit\n");
    fprintf(stderr, "  --nr-entry N     Number of entries to populate (default: 536870912)\n");
    fprintf(stderr, "  --value-size N   Value size in bytes (default: 200)\n");
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string db_path = argv[2];
    bool do_populate = false;
    long nr_entry = 536870912;
    int value_size = 200;

    for (int i = 3; i < argc; ++i) {
        if (std::string(argv[i]) == "--populate") {
            do_populate = true;
        } else if (std::string(argv[i]) == "--nr-entry" && i + 1 < argc) {
            nr_entry = std::stol(argv[++i]);
        } else if (std::string(argv[i]) == "--value-size" && i + 1 < argc) {
            value_size = std::stoi(argv[++i]);
        }
    }

    // Open LevelDB with NO block cache — forces all reads through page cache
    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = true;
    options.compression = leveldb::kNoCompression;
    // CRITICAL: Disable LevelDB's block cache so all reads go through the OS page cache
    options.block_cache = leveldb::NewLRUCache(0);

    std::cout << "Opening LevelDB at: " << db_path << std::endl;
    leveldb::Status status = leveldb::DB::Open(options, db_path, &db);
    if (!status.ok()) {
        std::cerr << "Failed to open LevelDB: " << status.ToString() << std::endl;
        return 1;
    }

    if (do_populate) {
        populate_db(db, nr_entry, value_size);
        delete db;
        return 0;
    }

    // Start TCP server
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 128) < 0) {
        perror("listen");
        return 1;
    }

    std::cout << "net_leveldb_server listening on port " << port
              << " (block_cache=DISABLED, all reads go through page cache)" << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd >= 0) {
            // Disable Nagle's algorithm for lower latency
            int flag = 1;
            setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
            std::thread(handle_client, client_fd, db).detach();
        }
    }

    delete db;
    return 0;
}
