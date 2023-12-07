#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>



void sha256(const unsigned char *message, size_t message_len, unsigned char *digest) {
    if (SHA256(message, message_len, digest) == NULL) {
        printf("SHA256\n");
    }
}

void sha384(const unsigned char *message, size_t message_len, unsigned char *digest) {
    if (SHA384(message, message_len, digest) == NULL) {
        printf("SHA384\n");
    }
}

void sha512(const unsigned char *message, size_t message_len, unsigned char *digest) {
    if (SHA512(message, message_len, digest) == NULL) {
        printf("SHA512\n");
    }
}

int main(void) {
    unsigned char message[] = "Hello, FIPS 140-2!";
    size_t message_len = strlen((char *)message);

    // Buffers to store the hash values
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    unsigned char sha384_digest[SHA384_DIGEST_LENGTH];
    unsigned char sha512_digest[SHA512_DIGEST_LENGTH];

    // Compute the hash values
    sha256(message, message_len, sha256_digest);
    sha384(message, message_len, sha384_digest);
    sha512(message, message_len, sha512_digest);

    // Print the hash values
    printf("SHA-256 Digest: \n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", sha256_digest[i]);
    }
    printf("\n\n");

    printf("SHA-384 Digest: \n");
    for (int i = 0; i < SHA384_DIGEST_LENGTH; i++) {
        printf("%02x", sha384_digest[i]);
    }
    printf("\n\n");

    printf("SHA-512 Digest: \n");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        printf("%02x", sha512_digest[i]);
    }
    printf("\n\n");

    return 0;
}
