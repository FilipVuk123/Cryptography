#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int encryptAES256cbc(char *bufferToEncrypt, int bufferSize, char *encryptedBuffer, char *key, char *iv)
{
    int outLen1 = 0;
    int outLen2 = 0;

    // Set up encryption
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
    EVP_EncryptUpdate(ctx, encryptedBuffer, &outLen1, bufferToEncrypt, bufferSize);
    EVP_EncryptFinal(ctx, encryptedBuffer + outLen1, &outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return outLen1 + outLen2;
}

int decryptAES256cbc(char *bufferToDecrypt, int bufferSize, char *decryptedBuffer, char *key, char *iv)
{
    int outLen1 = 0;
    int outLen2 = 0;

    // setup decryption
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);
    EVP_DecryptUpdate(ctx, decryptedBuffer, &outLen1, bufferToDecrypt, bufferSize);
    EVP_DecryptFinal(ctx, decryptedBuffer + outLen1, &outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return outLen1 + outLen2;
}

int main()
{

    unsigned char ckey[] = "thiskeyisverybadthiskeyisverybad";
    unsigned char ivec[] = "dontusethisinput";

    char message[] = "Message to encrypt!!! Message to encrypt!!! Message to encrypt!!! 123123 321213 Message to encrypt!!! Message to encrypt!!! Message to encrypt!!! ";
    int messageLen = strlen(message);
    printf("%d\n", messageLen);

    char encryptedData[messageLen + AES_BLOCK_SIZE - (messageLen % AES_BLOCK_SIZE)];
    char decryptedData[messageLen];

    encryptAES256cbc(message, messageLen, encryptedData, ckey, ivec);

    for (int i = 0; i < sizeof(encryptedData); i++)
    {
        printf("%02x", encryptedData[i]);
    }

    printf("\n");

    decryptAES256cbc(encryptedData, messageLen + AES_BLOCK_SIZE - (messageLen % AES_BLOCK_SIZE), decryptedData, ckey, ivec);

    decryptedData[messageLen] = '\0';

    printf("%s\n", decryptedData);

    return 0;
}