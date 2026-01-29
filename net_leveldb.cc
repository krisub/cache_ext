#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "leveldb/db.h"

// put in My-YCSB directory
// ./net_leveldb <port> <db_path>
// g++ My-YCSB/net_leveldb.cc -o net_leveldb \    -lleveldb -lsnappy -lpthread

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <db_path>" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string db_path = argv[2];

    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = true;
    options.compression = leveldb::kNoCompression; 
    
    leveldb::Status status = leveldb::DB::Open(options, db_path, &db);
    if (!status.ok()) {
        std::cerr << "Error opening DB: " << status.ToString() << std::endl;
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    std::cout << "Server listening on port " << port << " writing to " << db_path << std::endl;

    while (true) {
        int new_socket = accept(server_fd, NULL, NULL);
        char buffer[4096] = {0};
        
        int count = 0;
        while(true) {
            int bytes_read = read(new_socket, buffer, 4096);
            if (bytes_read <= 0) break;

            std::string key = "k_" + std::to_string(count++);
            std::string value(buffer, bytes_read);

            db->Put(leveldb::WriteOptions(), key, value);
        }
        close(new_socket);
    }
    
    delete db;
    return 0;
}