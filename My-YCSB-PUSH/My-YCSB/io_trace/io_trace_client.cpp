#include <memory>
#include <string>
#include <iostream>
#include <atomic>
#include <unistd.h>
#include <fcntl.h>
#include <unordered_map>
#include <stdio.h>

#include "io_trace_client.h"
#include "constants.h"


IOTraceClient::IOTraceClient(IOTraceFactory *factory, int id, std::string data_dir)
	: Client(id, factory), data_dir(data_dir) {
	}

IOTraceClient::~IOTraceClient() {
}

class FileDescriptorCache {
private:
	std::mutex lock;
	std::unordered_map<std::string, int> file_descriptor_map;

public:
	FileDescriptorCache() {}
	~FileDescriptorCache() {
		// Close all file descriptors
		std::lock_guard<std::mutex> guard(lock);
		for (auto &it : file_descriptor_map) {
			close(it.second);
		}
	}

	int get_file_descriptor(const std::string &filename) {
		std::lock_guard<std::mutex> guard(lock);
		auto it = file_descriptor_map.find(filename);
		if (it == file_descriptor_map.end()) {
			int fd = open(filename.c_str(), O_RDWR);
			if (fd < 0) {
				std::cerr << "Failed to open file: " << filename << std::endl;
				perror("open");
				return -1;
			}
			file_descriptor_map[filename] = fd;
			return fd;
		}
		return it->second;
	}
};

// Global file descriptor cache
FileDescriptorCache file_descriptor_cache;

struct file_and_offset {
	std::string file;
	int offset;
};

struct file_and_offset_and_size {
	std::string file;
	int offset;
	int size;
};

std::vector<std::string> split(const std::string &str, char delimiter) {
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(str);
	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}
	return tokens;
}

struct file_and_offset get_file_and_offset_from_key(char *key_buffer) {
    // Assume key_buffer contains a filename and offset encoded as a string
    // <filename>:<offset>
    std::string key_str(key_buffer);
    std::vector<std::string> parts = split(key_str, ':');

    if (parts.size() != 2) {
        throw std::invalid_argument("Invalid key format: " + key_str);
    }

    std::string filename = parts[0];
    int offset;

    try {
        offset = std::stoi(parts[1]);
    } catch (const std::exception& e) {
        throw std::invalid_argument("Invalid offset in key: " + key_str);
    }

    return {filename, offset};
}

struct file_and_offset_and_size get_file_and_offset_and_size_from_key(char *key_buffer) {
	// Assume key_buffer contains a filename, offset, and size encoded as a string
	// <filename>:<offset>:<size>
	std::string key_str(key_buffer);
	std::vector<std::string> parts = split(key_str, ':');

	if (parts.size() != 3) {
		throw std::invalid_argument("Invalid key format: " + key_str);
	}

	std::string filename = parts[0];
	int offset;
	int size;

	try {
		offset = std::stoi(parts[1]);
		size = std::stoi(parts[2]);
	} catch (const std::exception& e) {
		throw std::invalid_argument("Invalid offset or size in key: " + key_str);
	}

	// Sanity check
	if (size > MAX_VALUE_SIZE) {
		throw std::invalid_argument("Size too large: " + std::to_string(size) + ", MAX_VALUE_SIZE: " + std::to_string(MAX_VALUE_SIZE));
	}

	return {filename, offset, size};
}

int IOTraceClient::do_operation(Operation *op) {
	int ret = 0;
repeat:
	switch (op->type) {
	case UPDATE:
		throw std::invalid_argument("update not supported");
	case INSERT:
		// Print value size
		ret = this->do_insert(op->key_buffer, op->value_buffer);
		break;
	case READ:
		ret = this->do_read(op->key_buffer, op->value_buffer);
		break;
	case SCAN:
		throw std::invalid_argument("scan not supported");
	case READ_MODIFY_WRITE:
		throw std::invalid_argument("read_modify_write not supported");
	default:
		throw std::invalid_argument("invalid op type");
	}
	if (ret < 0) {
		std::cout << "Key actually failed: " << op->key_buffer << std::endl;
		//goto repeat;
	}
	return ret;
}

int IOTraceClient::do_read(char *key_buffer, char *value) {
	struct file_and_offset_and_size fos = get_file_and_offset_and_size_from_key(key_buffer);
	// Log the operation, file, and offset
	// fprintf(stderr, "Operation: READ, File: %s, Offset: %ld, Size: %ld\n", fos.file.c_str(), fos.offset, fos.size);
	// Join data_dir and file
	std::string file_path = this->data_dir + "/" + fos.file;
	int fd = file_descriptor_cache.get_file_descriptor(file_path);
	if (fd < 0) {
		return -1;
	}
	// Read value from file
	int ret = pread(fd, value, fos.size, fos.offset);
	if (ret < 0) {
		std::cerr << "Failed to read from file: " << file_path << std::endl;
		return -1;
	}
	return 0;
}

// thread_local unsigned int seed = 42;
// thread_local char value_buffer[MAX_VALUE_SIZE];
//
// void generate_random_string(char *buffer, int size) {
// 	if (size >= MAX_VALUE_SIZE) {
// 		throw std::invalid_argument("Size too large: " + std::to_string(size) + ", MAX_VALUE_SIZE: " + std::to_string(MAX_VALUE_SIZE));;
// 	}
//     static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
//     const size_t charset_size = sizeof(charset) - 1;

//     for (int i = 0; i < size; ++i) {
//         buffer[i] = charset[rand_r(&seed) % charset_size];
//     }
// 	buffer[std::max(0, size - 1)] = '\0';  // Ensure null-termination
// }

int IOTraceClient::do_insert(char *key_buffer, char *value_buffer) {
	struct file_and_offset_and_size fos = get_file_and_offset_and_size_from_key(key_buffer);
	// Log the operation, file, and offset
	// fprintf(stderr, "Operation: INSERT, File: %s, Offset: %ld, Size: %ld\n", fos.file.c_str(), fos.offset, fos.size);

	// Join data_dir and file
	std::string file_path = this->data_dir + "/" + fos.file;
	int fd = file_descriptor_cache.get_file_descriptor(file_path);
	if (fd < 0) {
		return -1;
	}
	generate_random_string(value_buffer, fos.size);
	// Write value to file
	int ret = pwrite(fd, value_buffer, fos.size, fos.offset);
	if (ret < 0) {
		std::cerr << "Failed to write to file: " << file_path << std::endl;
		return -1;
	}
	return 0;
}

int IOTraceClient::reset() {return 0;}

void IOTraceClient::close() {}

IOTraceFactory::IOTraceFactory(std::string data_dir, bool print_stats,
							   int nr_thread): client_id(0) {
	this->data_dir = data_dir;
	this->print_stats = print_stats;


	fprintf(stderr, "IOTraceFactory: data_dir: %s, print_stats: %d\n",
		data_dir.c_str(), print_stats);
}

IOTraceFactory::~IOTraceFactory() {}


IOTraceClient * IOTraceFactory::create_client() {
	auto client = new IOTraceClient(this, this->client_id++, this->data_dir);
	// client->scan_thread_pool_ = this->scan_thread_pool_;
	return client;
}

void IOTraceFactory::destroy_client(Client *client) {
	IOTraceClient *io_trace_client = static_cast<IOTraceClient *>(client);
	delete io_trace_client;
}
