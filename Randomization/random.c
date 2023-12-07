#include <stdio.h>
#include <openssl/rand.h>



int main(void) {
    unsigned char randomBytes[16];

    if (RAND_poll() != 1) {
        printf("RAND_poll\n");
    }

    if (RAND_bytes(randomBytes, sizeof(randomBytes)) != 1) {
        printf("RAND_bytes\n");
    }

    printf("Random: \n");
    for (int i = 0; i < sizeof(randomBytes); i++) {
        printf("%02x", randomBytes[i]);
    }
    printf("\n\n");

    return 0;
}
