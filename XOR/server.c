#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>


#define PORT 12345
#define BUFFER_SIZE 1024

volatile sig_atomic_t exit_flag = 0;

void handle_signal(int signum) {
    if (signum == SIGINT) {
        exit_flag = 1;
    }
}


char* XORCipher(char* data, char* key, int dataLen, int keyLen) {
	for (int i = 0; i < dataLen; ++i) {
		data[i] = data[i] ^ key[i % keyLen];
	}
}
int main() {
    struct sockaddr_in server_addr, client_addr;
    int socket_fd, bytes_received;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int messageLen = 93;
    char key[] = "sifra";

    // Create UDP socket
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    // Set the socket to non-blocking
    fcntl(socket_fd, F_SETFL, O_NONBLOCK);

    // Register the signal handler for Ctrl+C
    signal(SIGINT, handle_signal);

    printf("UDP Server is listening on port %d...\n", PORT);

    while (!exit_flag) {
        // Receive data from the client
        bytes_received = recvfrom(socket_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &addr_len);

        if (bytes_received < 0) {
            
            if (errno == EAGAIN && errno == EWOULDBLOCK) {
                continue;
            }
        } else {

            printf("Encrypted message: \n");
            for (int i = 0; i < messageLen; i++){
                printf("%#x ", buffer[i]);
            }
            printf("\n");

            // Decrypt the received message using XOR
            XORCipher(buffer, key, messageLen, strlen(key));

            // Display the decrypted message
            printf("Decrypted message: %s\n", buffer);
            memset(buffer, 0, BUFFER_SIZE);

            printf("\n\n");
        }
    }

    close(socket_fd);
    printf("Socket closed! Exiting... \n\n");
    return 0;
}
