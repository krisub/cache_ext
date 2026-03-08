#ifndef CONSTANTS_H
#define CONSTANTS_H

extern int KiB;
extern int MiB;

extern int MAX_KEY_SIZE;
extern int MAX_VALUE_SIZE;

void initialize_random_buffer();
void generate_random_string(char* buffer, int size);


#endif // CONSTANTS_H
