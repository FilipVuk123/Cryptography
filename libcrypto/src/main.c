
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "asymmetric.h"
#include "symmetric.h"
#include "random.h"
#include "hash.h"
#include "common.h"


int main(){

    int keysize = 2048;

    const char *publicFilename = "publicKey.pem";
    const char *privateFilename = "privateKey.pem";

    generate_rsa_key_pair(publicFilename, privateFilename, keysize);

    char message[] = "Testing text to encrypt and decrypt!";

    printf("Message: %s\n", message);

    unsigned char key[32];
    generate_random_bytes(key, 32);
    unsigned char iv[16];
    generate_random_bytes(iv, 16);

    symmetric_t encrypt, decrypt;
    asymmetric_t aencrypt, adecrypt;
    
    symmetric_encrypt_new(&encrypt, SYMMETRIC_AES128_CBC, key, 32, iv);
    symmetric_decrypt_new(&decrypt, SYMMETRIC_AES128_CBC, key, 32, iv);

    symmetric_encrypt(&encrypt, message, strlen(message));

    print_encrypted_hex(encrypt.output_buffer, encrypt.output_size);

    symmetric_decrypt(&decrypt, encrypt.output_buffer, encrypt.output_size);

    printf("Decrypted: %s\n", decrypt.output_buffer);

    asymmetric_encrypt_new(&aencrypt, publicFilename, keysize);
    asymmetric_decrypt_new(&adecrypt, privateFilename, keysize);


    asymmetric_encrypt(&aencrypt, message, strlen(message));    

    print_encrypted_hex(aencrypt.output_buffer, aencrypt.output_size);


    asymmetric_decrypt(&adecrypt, aencrypt.output_buffer, aencrypt.output_size);

    printf("Decrypted: %s\n", adecrypt.output_buffer);

    asymmetric_free(&aencrypt);    
    asymmetric_free(&adecrypt);

    symmetric_free(&encrypt);
    symmetric_free(&decrypt);

    return 0;
}
