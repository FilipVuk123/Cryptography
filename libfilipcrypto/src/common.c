#include "common.h"


void print_encrypted_hex(unsigned char* buffer, int size){
    for (int i = 0; i < size; i++)
    {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}