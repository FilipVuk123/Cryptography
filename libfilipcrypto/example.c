
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "include/asymmetric.h"
#include "include/symmetric.h"
#include "include/random.h"
#include "include/hash.h"
#include "include/common.h"


int main(){

    int keysize = 2048;

    const char *publicFilename = "publicKey.pem";
    const char *privateFilename = "privateKey.pem";

    generate_rsa_key_pair(publicFilename, privateFilename, keysize);

    unsigned char message[] = "Testing text to encrypt and decrypt!2345";

    printf("Message: %s\n", message);

    // unsigned char key[32];
    // generate_random_bytes(key, 32);
    // unsigned char iv[16];
    // generate_random_bytes(iv, 16);

    unsigned char key[] = "testtesttesttest";
    unsigned char iv[] = "testtesttesttest";
    

    unsigned char* encrypted = malloc(strlen(message) * 2);
    unsigned char* decrypted = malloc(strlen(message) * 2);

    int encrypted_len, decrypted_len;

    symmetric_t encrypt, decrypt;
    
    symmetric_new(&encrypt, SYMMETRIC_ENCRYPT, SYMMETRIC_AES128_ECB, key, 32, iv);
    symmetric_new(&decrypt, SYMMETRIC_DECRYPT, SYMMETRIC_AES128_ECB, key, 32, iv);
    
    symmetric_encrypt_decrypt(&encrypt, message, strlen(message), encrypted, &encrypted_len);

    print_encrypted_hex_interval(encrypted, encrypted_len);

    // symmetric_encrypt_decrypt(&encrypt, message, strlen(message), encrypted, &encrypted_len);

    // print_encrypted_hex_interval(encrypted, encrypted_len);

    symmetric_encrypt_decrypt(&decrypt, encrypted, encrypted_len, decrypted, &decrypted_len);

    printf("Decrypted: %s\n", decrypted);

    symmetric_encrypt_decrypt(&decrypt, encrypted, encrypted_len, decrypted, &decrypted_len);

    printf("Decrypted: %s\n", decrypted);


    unsigned char* aencrypted = malloc(keysize / 8);
    unsigned char* adecrypted = malloc(keysize / 8);

    // asymmetric_new(&aencrypt, ASYMMETRIC_ENCRYPT, publicFilename);
    // asymmetric_new(&adecrypt, ASYMMETRIC_DECRYPT, privateFilename);

    // asymmetric_t aencrypt, adecrypt;
    // int aencrypted_len, adecrypted_len;

    // asymmetric_encrypt_decrypt(&aencrypt, message, strlen(message), aencrypted, &aencrypted_len);    

    // print_encrypted_hex_interval(aencrypted, aencrypted_len);


    // asymmetric_encrypt_decrypt(&adecrypt, aencrypted, aencrypted_len, adecrypted, &adecrypted_len);

    // printf("Decrypted: %s\n", adecrypted);

    // asymmetric_free(&aencrypt);    
    // asymmetric_free(&adecrypt);

    symmetric_free(&encrypt);
    symmetric_free(&decrypt);

    return 0;
}
