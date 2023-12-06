#include <stdio.h>
#include <openssl/rand.h>



int main(void) {
    unsigned char randomBytes[16];

    if (RAND_poll() != 1) {
        perror("RAND_poll");
    }

    if (RAND_bytes(randomBytes, sizeof(randomBytes)) != 1) {
        perror("RAND_bytes");
    }

    printf("Random: ");
    for (int i = 0; i < sizeof(randomBytes); i++) {
        printf("%02x", randomBytes[i]);
    }
    printf("\n");

    return 0;
}
