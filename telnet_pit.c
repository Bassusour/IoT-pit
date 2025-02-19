#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/time.h>
#include <limits.h>

#define PORT 23
#define MAX_CLIENTS 4096 // Same as endlessh
#define DELAY_MS 1000

#define IAC 255
#define DO 253
#define DONT 254
#define WILL 251
#define WONT 252

// Telnet negotiation options
unsigned char negotiations[][3] = {
    {IAC, WILL, 1}, 
    {IAC, DO, 3}, 
    {IAC, DONT, 5},
    {IAC, WILL, 31}, 
    {IAC, DO, 24}, 
    {IAC, WONT, 39}
};
int num_options = sizeof(negotiations) / sizeof(negotiations[0]);

struct client {
    char ipaddr[INET_ADDRSTRLEN];
    long long connect_time;
    // long long send_next;
    // struct client *next;
    int port;
    int fd;
};

static struct client *client_new(int fd)
{
    struct client *client = malloc(sizeof(struct client));
    if (client == NULL) {
        return NULL;
    }

    client->ipaddr[0] = '\0';
    client->connect_time = epochms();
    client->fd = fd;
    client->next = NULL;
    // client->send_next = send_next;
    return client;
}

// struct timeval last_sent_time[MAX_CLIENTS]; // Per-client last message timestamp (For delay between option messages)

long get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

int create_server(int port) {
    int r; 
    int socket;
    int value;

    // IPv4 socket
    socket = socket(AF_INET, SOCK_STREAM, 0);
    if (socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Enable SO_REUSEADDR for faster restarts
    value = 1;
    r = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
    if (r == -1) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }

    // Bind to IPv4 address and port
    struct sockaddr_in addr4 = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {INADDR_ANY}
    };
    r = bind(socket, (struct sockaddr *)&addr4, sizeof(addr4));
    if (r == -1) {
        perror("Bind failed");
        close(socket);
        exit(EXIT_FAILURE);
    }

    // Listen with a very large backlog (INT_MAX) to handle massive bot traffic
    r = listen(socket, INT_MAX);
    if (r == -1) {
        perror("Listen failed");
        close(socket);
        exit(EXIT_FAILURE);
    }

    printf("Telnet tarpit listening on port %d...\n", port);
    return socket;
}

int main() {
    int server_sock = server_create(PORT);
    int client_sock;

    struct sockaddr_in
    struct server_addr
    struct client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // init poll
    struct pollfd fds[MAX_CLIENTS];
    int client_count = 0;

    // monitors connections on index 0. > 0 monitors clients
    fds[0].fd = server_sock;
    fds[0].events = POLLIN;
    client_count = 1; // poll index

    printf("Telnet tarpit listening on port %d...\n", PORT);

    while (1) {
        // Check for new connections
        if (fds[0].revents & POLLIN) {
            client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock >= 0) {
                printf("New connection from %socket\n", inet_ntoa(client_addr.sin_addr));
                if (client_count < MAX_CLIENTS) {
                    fds[client_count].fd = client_sock;
                    fds[client_count].events = POLLOUT; // Ready to send
                    client_count++;
                } else {
                    close(client_sock);
                }
            }
        }

        // TODO: Figure out how to use poll
        int pollSuccess = poll(fds, client_count, 100);

        if (pollSuccess < 0) {
            perror("Poll error");
            continue;
        }

        // Monitors when clients can write, and sends random negotiation options
        for (int i = 1; i < client_count; i++) {
            if (fds[i].revents & POLLOUT) {
                int index = rand() % num_options;
                write(fds[i].fd, negotiations[index], sizeof(negotiations[index]));
                // usleep(DELAY_MS * 1000); // TODO: Figure out how not to block thread
            }
        }
    }

    close(server_sock);
    return 0;
}
