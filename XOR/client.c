#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>


#define PORT 12345

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
    data[dataLen] = '\0';
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];

    struct sockaddr_in server_addr;
    int socket_fd;
    char message[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc lobortis at elit non convallis.";
    char key[] = "sifra123";

    int messageLen = strlen(message);
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

    printf("Message: %s\n", message);

    XORCipher(message, key, messageLen, keyLen);

    while (!exit_flag) {

        // Send the encrypted message to the server
        sendto(socket_fd, message, messageLen, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

        sleep(1);
    }

    close(socket_fd);
    printf("Socket closed! Exiting... \n\n");
    return 0;
}
