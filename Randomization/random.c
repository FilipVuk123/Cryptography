#include <stdio.h>
#include <openssl/rand.h>

int generateRandomBytes(unsigned char* outbuf, const int len){
    if (RAND_poll() != 1) {
        printf("RAND_poll\n");
        return 1;
    }

    if (RAND_bytes(outbuf, len) != 1) {
        printf("RAND_bytes\n");
        return 1;
    }

    return 0;
}

int main(void) {
    unsigned char randomBytes[16];

    generateRandomBytes(randomBytes, sizeof(randomBytes));
    
    printf("Random: \n");
    for (int i = 0; i < sizeof(randomBytes); i++) {
        printf("%02x", randomBytes[i]);
    }
    printf("\n");

    return 0;
}


