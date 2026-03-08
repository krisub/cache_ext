#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <string>


int KiB = 1024;
int MiB = 1024 * KiB;

int MAX_KEY_SIZE = 16 * KiB;
int MAX_VALUE_SIZE = 32 * MiB;

char *random_buffer = new char[MAX_VALUE_SIZE];

void initialize_random_buffer() {
    for (int i = 0; i < MAX_VALUE_SIZE; ++i) {
        random_buffer[i] = 'a' + (rand() % ('z' - 'a' + 1));
    }
    random_buffer[MAX_VALUE_SIZE - 1] = '\0';
}

void generate_random_string(char *buffer, int size) {
	if (size >= MAX_VALUE_SIZE) {
		throw std::invalid_argument("Size too large: " + std::to_string(size) + ", MAX_VALUE_SIZE: " + std::to_string(MAX_VALUE_SIZE));;
	}
    // Copy from the global random buffer
    memcpy(buffer, random_buffer, size);
    buffer[std::max(0, size - 1)] = '\0';  // Ensure null-termination
}

#endif //CONSTANTS_H