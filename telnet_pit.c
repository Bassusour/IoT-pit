#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/time.h>
#include <limits.h>
#include <fcntl.h>

#define PORT 23
#define MAX_CLIENTS 4096
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
    int fd;
    long long send_next;
    struct client *next;
};

// queue for the order of clients in descending order of send time
struct fifo {
    struct client *head;
    struct client *tail;
    int length;
};

long long get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
}

void fifo_init(struct fifo *q) {
    q->head = q->tail = NULL;
    q->length = 0;
}

void fifo_append(struct fifo *q, struct client *c) {
    c->next = NULL;
    if (q->tail != NULL) {
        q->tail->next = c;
    } else {
        q->head = c;
    }
    q->tail = c;
    q->length++;
}

struct client *fifo_pop(struct fifo *q) {
    if (q->head == NULL) return NULL;
    struct client *c = q->head;
    q->head = c->next;
    if (!q->head) {
        q->tail = NULL;
    }
    q->length--;
    return c;
}

// TODO: Look more into server creation
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
    struct fifo client_queue;
    fifo_init(&client_queue);
    
    int server_sock = create_server(PORT);
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    struct pollfd fds = {server_sock, POLLIN, 0};
    
    while (1) {
        long long now = get_time_ms();
        // Block until first client is received. Then block until head of queue should receive data
        int timeout = (client_queue.head) ? client_queue.head->send_next - now : -1;
        if (timeout < 0) timeout = 0;

        int poll_result = poll(&fds, 1, timeout);
        if (poll_result < 0) {
            perror("Poll error");
            continue;
        }

        // Accept new connections
        if (fds.revents & POLLIN) {
            int client_fd = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
            if (client_fd >= 0) {
                fcntl(client_fd, F_SETFL, O_NONBLOCK); // Set non-blocking mode
                struct client *new_client = malloc(sizeof(struct client));
                if (!new_client) {
                    perror("Out of memory");
                    close(client_fd);
                    continue;
                }

                new_client->fd = client_fd;
                new_client->send_next = now + DELAY_MS;
                fifo_append(&client_queue, new_client);

                printf("Accepted connection from %s:%d\n",
                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            }
        }

        // Process clients in queue
        while (client_queue.head && client_queue.head->send_next <= now) {
            struct client *c = fifo_pop(&client_queue);
            if (!c) continue;

            int option_index = rand() % num_options;
            ssize_t out = write(c->fd, negotiations[option_index], sizeof(negotiations[option_index]));

            if (out == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    c->send_next = now + DELAY_MS; // Reschedule if write would block
                    fifo_append(&client_queue, c);
                } else {
                    close(c->fd);
                    free(c);
                    printf("Client disconnected\n");
                }
            } else {
                c->send_next = now + DELAY_MS;
                fifo_append(&client_queue, c);
            }
        }
    }

    close(server_sock);
    return 0;
}
