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
        printf("rsa gen\n");
        return;
    }
    FILE *fp = fopen(publicKeyFilename, "w\n");
    if (fp != NULL)
    {
        if(PEM_write_PUBKEY(fp, pkey) == 0){
            printf("Error PEM_write_PUBKEY\n");
        }
        fclose(fp);
    }
    else
    {
        printf("Error PEM_write_PUBKEY\n");
    }
    fp = fopen(privateKeyFilename, "w\n");
    if (fp != NULL)
    {
        if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) == 0){
            printf("Error PEM_write_PrivateKey\n");
        }
        fclose(fp);
    }
    else
    {
        printf("Error PEM_write_PrivateKey\n");
    }
    EVP_PKEY_free(pkey);
}

int encryptRSA(char* inbuf, int inlen, char* outbuf, int* outlen, const char* pathToPublicKey)
{
    int to_ret = 0;
    FILE *fp = fopen(pathToPublicKey, "r\n");
    if (fp == NULL)
    {
        printf("file error\n");
        return 1;
    }
    EVP_PKEY *pkey;
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        printf("Error PEM_read_PUBKEY\n");
        return 1;
    }

    size_t outlength;
    size_t outl;

    EVP_PKEY_CTX *ctx;
    if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL))){
        printf("Error: EVP_PKEY_CTX_new\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    EVP_PKEY_free(pkey);

    if (1 != EVP_PKEY_encrypt_init(ctx)){
        printf("Error: EVP_PKEY_encrypt_init\n");
        to_ret += 1;
    }
    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)){
        printf("Error: EVP_PKEY_CTX_set_rsa_padding\n");
        to_ret += 1;
    }
    if (1 != EVP_PKEY_encrypt(ctx, NULL, &outlength, inbuf, inlen)){
        printf("Error: EVP_PKEY_encrypt\n");
        to_ret += 1;
    }

    if (1 != EVP_PKEY_encrypt(ctx, outbuf, &outl, inbuf, (size_t)inlen))
    {
        printf("Error: EVP_PKEY_encrypt\n");
        to_ret += 1;
    }
    EVP_PKEY_CTX_free(ctx);

    *outlen = outl;

    outbuf[outl] = '\0';

    return to_ret;
}

int decryptRSA(char* inbuf, int inlen, char* outbuf, int* outlen, const char* pathToPrivateKey)
{
    int to_ret = 0;
    FILE *fp = fopen(pathToPrivateKey, "r\n");
    if (fp == NULL)
    {
        printf("file error\n");
        return 1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        printf("Error PEM_read_PrivateKey\n");
        return 1;
    }
    
    size_t outlength;
    size_t outl;

    EVP_PKEY_CTX *ctx;
    if(!(ctx = EVP_PKEY_CTX_new(pkey, NULL))){
        printf("Error: EVP_PKEY_CTX_new\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    EVP_PKEY_free(pkey);


    if (1 != EVP_PKEY_decrypt_init(ctx)){
        printf("Error: EVP_PKEY_decrypt_init\n");
        to_ret += 1;
    }
    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)){
        printf("Error: EVP_PKEY_CTX_set_rsa_padding\n");
        to_ret += 1;
    }
    if (1 != EVP_PKEY_decrypt(ctx, NULL, &outlength, inbuf, inlen)){
        printf("Error: EVP_PKEY_decrypt\n");
        to_ret += 1;
    }

    if (1 != EVP_PKEY_decrypt(ctx, outbuf, &outl, inbuf, inlen))
    {
        printf("Error: EVP_PKEY_decrypt\n");
        to_ret += 1;
    }

    EVP_PKEY_CTX_free(ctx);

    outbuf[outl] = '\0';

    *outlen = outl;
    
    return to_ret;
}

int calcMaxEncryptSizeInBytes(const int keySizeInBits){

    return keySizeInBits / 8 - 11;
}

int main(){
    int keysize = 2048;
    int maxBufferSize = calcMaxEncryptSizeInBytes(keysize);

    const char* publicFilename = "publicKey.txt";
    const char* privateFilename = "privateKey.txt";

    generateKeys(publicFilename, privateFilename, keysize);

    char message[] = "This is my message to be encrypted!";
    int messageLen = strlen(message);

    int size;
    char encryptedBuffer[maxBufferSize];
    char decryptedBuffer[maxBufferSize];

    printf("Message: %s\n", message);

    int ret = encryptRSA(message, messageLen, encryptedBuffer, &size, publicFilename);
    if (ret > 0)
        printf("encryptRSA\n");

    printf("Encrypted: \n");
    for (int i = 0; i < size; i++){
        printf("%#x", encryptedBuffer[i]);
    }
    printf("\n\n");


    ret = decryptRSA(encryptedBuffer, size, decryptedBuffer, &size, privateFilename);
    if (ret > 0)
        printf("decryptRSA\n");


    printf("Decrypted: %s\n", decryptedBuffer);
    

    return 0;
}