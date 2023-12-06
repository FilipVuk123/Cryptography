#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void generateKeys(const char *publicKeyFilename, const char *privateKeyFilename, int key_size)
{
    EVP_PKEY *pkey = EVP_RSA_gen(key_size);
    if (pkey == NULL)
    {
        perror("rsa gen");
        return;
    }
    FILE *fp = fopen(publicKeyFilename, "w");
    if (fp != NULL)
    {
        PEM_write_PUBKEY(fp, pkey);
        fclose(fp);
    }
    else
    {
        perror("PEM_write_PUBKEY");
    }
    fp = fopen(privateKeyFilename, "w");
    if (fp != NULL)
    {
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(fp);
    }
    else
    {
        perror("PEM_write_PrivateKey");
    }
    EVP_PKEY_free(pkey);
}

int encryptRSA(char *input, int input_size, char *output, const char* pathToPublicKey)
{
    FILE *fp = fopen(pathToPublicKey, "r");
    if (fp == NULL)
    {
        perror("file error");
        return -1;
    }
    EVP_PKEY *pkey;
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        perror("PEM_read_PUBKEY");
        return -1;
    }

    size_t outlen;
    size_t outl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    EVP_PKEY_encrypt(ctx, NULL, &outlen, input, input_size);

    if (!EVP_PKEY_encrypt(ctx, output, &outl, input, (size_t)input_size))
    {
        perror("EVP_PKEY_encrypt");
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    output[outl] = '\0';

    return outl;
}

int decryptRSA(char *input, int input_size, char *output, const char* pathToPrivateKey)
{
    FILE *fp = fopen(pathToPrivateKey, "r");
    if (fp == NULL)
    {
        perror("file error");
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        perror("PEM_read_PrivateKey");
        return -1;
    }
    
    size_t outlen;
    size_t outl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    EVP_PKEY_decrypt(ctx, NULL, &outlen, input, input_size);

    if (!EVP_PKEY_decrypt(ctx, output, &outl, input, input_size))
    {
        perror("EVP_PKEY_decrypt");
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    output[outl] = '\0';
    
    return outl;
}

int calcMaxEncryptSizeInBytes(const int keySizeInBits){

    return keySizeInBits / 8 - 11;
}

int main(){
    int keysize = 2048;
    int maxBufferSize = calcMaxEncryptSizeInBytes(keysize);

    const char* publicFilename = "publicKey.txt";
    const char* privateFilename = "privateKey.txt";

    // generateKeys(publicFilename, privateFilename, keysize);

    char message[] = "This is my message to be encrypted!";
    int messageLen = strlen(message);

    char encryptedBuffer[maxBufferSize];

    char decryptedBuffer[maxBufferSize];

    printf("Message:\t %s\n", message);

    int encryptedSize = encryptRSA(message, messageLen, encryptedBuffer, publicFilename);

    printf("Encrypted:\t ");
    for (int i = 0; i < encryptedSize; i++){
        printf("%02x", encryptedBuffer[i]);
    }
    printf("\n");

    int size = decryptRSA(encryptedBuffer, encryptedSize, decryptedBuffer, privateFilename);

    

    printf("Decrypted:\t %s\n", decryptedBuffer);
    

    return 0;
}