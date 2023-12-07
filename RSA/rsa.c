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
        if(PEM_write_PUBKEY(fp, pkey) == 0){
            perror("PEM_write_PUBKEY");
        }
        fclose(fp);
    }
    else
    {
        perror("PEM_write_PUBKEY");
    }
    fp = fopen(privateKeyFilename, "w");
    if (fp != NULL)
    {
        if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) == 0){
            perror("PEM_write_PrivateKey");
        }
        fclose(fp);
    }
    else
    {
        perror("PEM_write_PrivateKey");
    }
    EVP_PKEY_free(pkey);
}

int encryptRSA(char* inbuf, int inlen, char* outbuf, int* outlen, const char* pathToPublicKey)
{
    int to_ret = 0;
    FILE *fp = fopen(pathToPublicKey, "r");
    if (fp == NULL)
    {
        perror("file error");
        return 1;
    }
    EVP_PKEY *pkey;
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        perror("PEM_read_PUBKEY");
        return 1;
    }

    size_t outlength;
    size_t outl;

    EVP_PKEY_CTX *ctx;
    if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL))){
        perror("EVP_PKEY_CTX_new");
        EVP_PKEY_free(pkey);
        return 1;
    }
    EVP_PKEY_free(pkey);

    if (1 != EVP_PKEY_encrypt_init(ctx)){
        perror("EVP_PKEY_encrypt_init");
        to_ret += 1;
    }
    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)){
        perror("EVP_PKEY_CTX_set_rsa_padding");
        to_ret += 1;
    }
    if (1 != EVP_PKEY_encrypt(ctx, NULL, &outlength, inbuf, inlen)){
        perror("EVP_PKEY_encrypt");
        to_ret += 1;
    }

    if (1 != EVP_PKEY_encrypt(ctx, outbuf, &outl, inbuf, (size_t)inlen))
    {
        perror("EVP_PKEY_encrypt");
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
    FILE *fp = fopen(pathToPrivateKey, "r");
    if (fp == NULL)
    {
        perror("file error");
        return 1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        perror("PEM_read_PrivateKey");
        return 1;
    }
    
    size_t outlength;
    size_t outl;

    EVP_PKEY_CTX *ctx;
    if(!(ctx = EVP_PKEY_CTX_new(pkey, NULL))){
        perror("EVP_PKEY_CTX_new");
        EVP_PKEY_free(pkey);
        return 1;
    }
    EVP_PKEY_free(pkey);


    if (1 != EVP_PKEY_decrypt_init(ctx)){
        perror("EVP_PKEY_decrypt_init");
        to_ret += 1;
    }
    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)){
        perror("EVP_PKEY_CTX_set_rsa_padding");
        to_ret += 1;
    }
    if (1 != EVP_PKEY_decrypt(ctx, NULL, &outlength, inbuf, inlen)){
        perror("EVP_PKEY_decrypt");
        to_ret += 1;
    }

    if (1 != EVP_PKEY_decrypt(ctx, outbuf, &outl, inbuf, inlen))
    {
        perror("EVP_PKEY_decrypt");
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

    printf("Message:\t %s\n", message);

    int ret = encryptRSA(message, messageLen, encryptedBuffer, &size, publicFilename);
    if (ret > 0)
        perror("encryptRSA");

    printf("Encrypted:\t ");
    for (int i = 0; i < size; i++){
        printf("%#x", encryptedBuffer[i]);
    }
    printf("\n");


    ret = decryptRSA(encryptedBuffer, size, decryptedBuffer, &size, privateFilename);
    if (ret > 0)
        perror("decryptRSA");


    printf("Decrypted:\t %s\n", decryptedBuffer);
    

    return 0;
}