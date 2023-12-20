
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "cipher.h"
#include "asymmetric.h"
#include "symmetric.h"
#include "cipher.h"
#include "random.h"
#include "hash.h"


// AES GCM
#if 0
int main(){

    unsigned char key[] = "ThisisverybadkeyThisisverybadkey";
    unsigned char iv[] = "Thisisverybadkey";

    unsigned char aad[] = "Additional Auth Data";

    char message[] = "Testing text to encrypt and decrypt!";

    symmetric_t symmEnc;
    symmetric_encrypt_new(&symmEnc, SYMMETRIC_AES256_GCM, key, strlen((char *)key), iv);  

    symmetric_encrypt(&symmEnc, message, strlen(message), aad, strlen(aad));

    
    printf("Plain text: %s\n", message);

    printf("Encrypted: \n");
    printEncryptedHex(symmEnc.output_buffer, symmEnc.output_size);
    printf("Tag: \n");
    printEncryptedHex(symmEnc.tag, 16);
    
    symmetric_t symmDec;
    symmetric_decrypt_new(&symmDec, SYMMETRIC_AES256_GCM, key, strlen((char *) key), iv);  

    symmetric_decrypt(&symmDec, (char *) symmEnc.output_buffer, symmEnc.output_size, aad, strlen(aad), symmEnc.tag);


    printf("Decrypt: %s\n", symmDec.output_buffer);
    symmetric_decrypt_free(&symmDec);
    symmetric_encrypt_free(&symmEnc);

    return 0;
}
#endif

// Other symmetric
#if 0
int main(){

    unsigned char key[] = "ThisisverybadkeyThisisverybadkey";
    unsigned char iv[] = "Thisisverybadkey";

    char message[] = "Testing text to encrypt and decrypt!";

    symmetric_t symmEnc;
    symmetric_encrypt_new(&symmEnc, SYMMETRIC_3DES_CBC, key, strlen((char *)key), iv);  

    symmetric_encrypt(&symmEnc, message, strlen(message), NULL, 0);

    
    printf("Plain text: %s\n", message);

    printf("Encrypted: \n");
    printEncryptedHex(symmEnc.output_buffer, symmEnc.output_size);
    
    symmetric_t symmDec;
    symmetric_decrypt_new(&symmDec, SYMMETRIC_3DES_CBC, key, strlen((char *) key), iv);  

    symmetric_decrypt(&symmDec, (char *) symmEnc.output_buffer, symmEnc.output_size, NULL, 0, NULL);


    printf("Decrypt: %s\n", symmDec.output_buffer);
    symmetric_decrypt_free(&symmDec);
    symmetric_encrypt_free(&symmEnc);

    return 0;
}
#endif

// asymmetric
#if 0

int main(){

    int keysize = 2048;

    const char *publicFilename = "publicKey.pem";
    const char *privateFilename = "privateKey.pem";

    char message[] = "This is my message to be encrypted!";
    int messageLen = strlen(message);

    printf("%s\n", message);

    generate_rsa_key_pair(publicFilename, privateFilename, keysize);

    asymmetric_t asymmEnc;
    asymmetric_encrypt_new(&asymmEnc, publicFilename, keysize);
    asymmetric_encrypt(&asymmEnc, message, messageLen);
    
    printf("Encrypted: \n");
    printEncryptedHex(asymmEnc.output_buffer, asymmEnc.output_size);

    asymmetric_t asymmDec;
    asymmetric_decrypt_new(&asymmDec, privateFilename, keysize);
    asymmetric_decrypt(&asymmDec, asymmEnc.output_buffer, asymmEnc.output_size);
    asymmetric_encrypt_free(&asymmEnc);

    printf("Decrypted: %s\n", asymmDec.output_buffer);

    asymmetric_decrypt_free(&asymmDec);
return 0;
}
#endif

// client
#if 0
#define PORT 12345

volatile sig_atomic_t exit_flag = 0;

void handle_signal(int signum) {
    if (signum == SIGINT) {
        exit_flag = 1;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    unsigned char key[] = "ThisisverybadkeyThisisverybadkey";
    unsigned char iv[] = "Thisisverybadkey";

    char *server_ip = argv[1];

    struct sockaddr_in server_addr;
    int socket_fd;
    char message[][150] = {"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc lobortis at elit non convallis.", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", "Nunc lobortis at elit non convallis. "};

    int keyLen = strlen(key);

    // Create UDP socket
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        printf("Socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(PORT);

    // Set the socket to non-blocking
    fcntl(socket_fd, F_SETFL, O_NONBLOCK);

    // Register the signal handler for Ctrl+C
    signal(SIGINT, handle_signal);

    symmetric_t sym;
    symmetric_encrypt_new(&sym, 3DES_CBC, key, strlen((char *)key), iv);

    while (!exit_flag) {
        for (int i = 0; i < 3; i++){
            symmetric_encrypt(&sym, message[i], strlen(message[i]), NULL, 0);
            printEncryptedHex(sym.output_buffer, sym.output_size);

            // Send the encrypted message to the server
            sendto(socket_fd, sym.output_buffer, sym.output_size, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

            sleep(1);
        }
        break;
    }

    close(socket_fd);
    printf("Socket closed! Exiting... \n");
    return 0;
}


#endif

// server
#if 0
#define PORT 12345
#define BUFFER_SIZE 1024

volatile sig_atomic_t exit_flag = 0;

void handle_signal(int signum)
{
    printf("In handle_signal!\n");
    if (signum == SIGINT)
    {
        exit_flag = 1;
    }
}

int main()
{
    unsigned char key[] = "ThisisverybadkeyThisisverybadkey";
    unsigned char iv[] = "Thisisverybadkey";


    struct sockaddr_in server_addr, client_addr;
    int socket_fd, bytes_received;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Create UDP socket
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        printf("Socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);


    // Set the socket to non-blocking
    fcntl(socket_fd, F_SETFL, O_NONBLOCK);

    // Bind the socket
    if (bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("Bind failed\n");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    // Register the signal handler for Ctrl+C
    signal(SIGINT, handle_signal);

    printf("UDP Server is listening on port %d...\n", PORT);

    symmetric_t sym;
    symmetric_decrypt_new(&sym, 3DES_CBC, key, strlen((char *)key), iv);

    while (!exit_flag)
    {
        // Receive data from the client
        bytes_received = recvfrom(socket_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (bytes_received < 0)
        {

            if (errno == EAGAIN && errno == EWOULDBLOCK)
            {
                continue;
            }
        }
        else
        {
            printEncryptedHex(buffer, bytes_received);
            symmetric_decrypt(&sym, buffer, bytes_received, NULL, 0, NULL);
            printf("%s\n", sym.output_buffer);
            memset(buffer, 0, BUFFER_SIZE);
        }
    }
    close(socket_fd);
    symmetric_decrypt_free(&sym);
    printf("Socket closed! Exiting... \n");

    return 0;
}

#endif



int main(){

    int keysize = 2048;

    const char *publicFilename = "publicKey.pem";
    const char *privateFilename = "privateKey.pem";

    generate_rsa_key_pair(publicFilename, privateFilename, keysize);

    // unsigned char key[] = "ThisisverybadkeyThisisverybadkey";
    // unsigned char iv[] = "Thisisverybadkey";

    // char aad[] = "Aad Aad Aad!";
    char message[] = "Testing text to encrypt and decrypt!";

    unsigned char key[32];
    generate_random_bytes(key, 32);
    unsigned char iv[16];
    generate_random_bytes(iv, 16);
    char aad[8];
    generate_random_bytes(aad, 8);


    cipher_t cipherEncrypt;
    cipher_encrypt_new(&cipherEncrypt, CIPHER_AES256_CTR, key, strlen(key), iv, publicFilename, keysize);

    cipher_encrypt(&cipherEncrypt, message, strlen(message), aad, strlen(aad));
    
    printEncryptedHex(cipherEncrypt.output_buffer, cipherEncrypt.output_size);

    // printEncryptedHex(cipherEncrypt.tag, 16);

    cipher_t cipherDecrypt;
    cipher_decrypt_new(&cipherDecrypt, CIPHER_AES256_CTR, key, strlen(key), iv, privateFilename, keysize);

    cipher_decrypt(&cipherDecrypt, cipherEncrypt.output_buffer, cipherEncrypt.output_size, aad, strlen(aad), cipherEncrypt.tag);
    
    printf("%s\n", cipherDecrypt.output_buffer);

    cipher_decrypt_free(&cipherDecrypt);

    cipher_encrypt_free(&cipherEncrypt);

    return 0;
}
