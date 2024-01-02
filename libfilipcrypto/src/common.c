#include "common.h"


void print_encrypted_hex(unsigned char* buffer, int size){
    for (int i = 0; i < size; i++)
    {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

void print_encrypted_hex_interval(unsigned char* buffer, int first_index, int last_index){
    for (int i = first_index; i < last_index; i++)
    {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}


int compare_buffers(char* buffer1, char* buffer2, int size){
    for(int i = 0; i < size; i++){
        if (buffer1[i] != buffer2[i]){
            return 1;
        }
    }
    return 0;
}