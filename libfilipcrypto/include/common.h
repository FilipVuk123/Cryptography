
#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>

void print_encrypted_hex(unsigned char* buffer, int size);

void print_encrypted_hex_interval(unsigned char* buffer, int first_index, int last_index);

int compare_buffers(char* buffer1, char* buffer2, int size);

#endif