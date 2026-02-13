// put in My-YCSB directory

// ./net_leveldb <port> <db_path>

// g++ My-YCSB/net_leveldb.cc -o net_leveldb -lleveldb -lsnappy -lpthread
#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <arpa/inet.h>
#include <cstring>
#include "leveldb/db.h"
#include "leveldb/write_batch.h"

const int VALUE_SIZE = 4096; // 4KB values
const int NUM_KEYS = 500000; // 500K keys = 2GB of data
const int KEYS_PER_SCAN = 256; // 256 * 4KB = 1 MB read per request (scan window)

struct __attribute__((packed)) ScanRequest {
    char cmd[4];   
    uint32_t start_id; 
};

// load dbs with arbitrary data
void populate_db(leveldb::DB* db) {
    std::cout << "Populating DB with " << NUM_KEYS << " keys..." << std::endl;
    leveldb::WriteOptions write_options;
    write_options.sync = false;
    leveldb::WriteBatch batch;
    std::string value(VALUE_SIZE, 'x'); // arbitrary data

    for (int i = 0; i < NUM_KEYS; ++i) {
        batch.Put("key_" + std::to_string(i), value);
        if ((i + 1) % 1000 == 0) {
            db->Write(write_options, &batch);
            batch.Clear();
            if ((i+1) % 50000 == 0) std::cout << "Inserted " << i+1 << "..." << std::endl;
        }
    }
    if (batch.ApproximateSize() > 0) db->Write(write_options, &batch);
    std::cout << "Done." << std::endl;
}

void handle_client(int socket_fd, leveldb::DB* db) {
    char buffer[64];
    while(true) {
        int bytes_read = read(socket_fd, buffer, sizeof(buffer));
        if (bytes_read <= 0) break;

        int start_id = -1;

        if (bytes_read >= (int)sizeof(ScanRequest)) {
            ScanRequest req;
            memcpy(&req, buffer, sizeof(req));
            if (memcmp(req.cmd, "SCAN", 4) == 0) {
                start_id = (int)ntohl(req.start_id); // request should have start_id
            }
        }

        // if no start_id, generate a random one
        if (start_id < 0) {
            if (bytes_read >= 4 && memcmp(buffer, "SCAN", 4) == 0) {
                start_id = rand() % (NUM_KEYS - KEYS_PER_SCAN);
            } else {
                continue;
            }
        }

        if (start_id < 0) start_id = 0;
        if (start_id > (NUM_KEYS - KEYS_PER_SCAN)) start_id = (NUM_KEYS - KEYS_PER_SCAN);
        std::string start_key = "key_" + std::to_string(start_id);

        leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
        int scanned = 0;
        int total_bytes = 0;
        

        char sink[VALUE_SIZE]; // buffer to store the read data

        // scan from start_key to start_key + KEYS_PER_SCAN
        for (it->Seek(start_key); it->Valid() && scanned < KEYS_PER_SCAN; it->Next()) {
            leveldb::Slice v = it->value();
            memcpy(sink, v.data(), 1); 
            total_bytes += v.size();
            scanned++;
        }
        delete it;

        std::string response = "OK " + std::to_string(total_bytes);
        send(socket_fd, response.data(), response.size(), 0);
    }
    close(socket_fd);
}

int main(int argc, char** argv) {
    srand(time(NULL));
    if (argc < 3) return 1;
    int port = std::stoi(argv[1]);
    std::string db_path = argv[2];
    bool mode_populate = (argc >= 4 && std::string(argv[3]) == "--populate");

    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = true;
    options.compression = leveldb::kNoCompression;
    options.block_cache = NULL; 
    
    leveldb::Status status = leveldb::DB::Open(options, db_path, &db);

    if (mode_populate) {
        populate_db(db);
        delete db;
        return 0;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 50);

    std::cout << "SCAN Server (1MB/req) running on " << port << std::endl;

    while (true) {
        int new_socket = accept(server_fd, NULL, NULL);
        if (new_socket >= 0) {
            std::thread(handle_client, new_socket, db).detach();
        }
    }
    return 0;
}