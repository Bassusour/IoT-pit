#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/time.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>

#define PORT 23
#define MAX_CLIENTS 4096
#define DELAY_MS 100
#define HEARTBEAT_INTERVAL_MS 600000 // 10 minutes

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
    long long sendNext;
    struct client *next;
    long long timeConnected;
    char ipaddr[INET6_ADDRSTRLEN];
    int port;
};

// queue for the order of clients in descending order of sendNext
struct queue {
    struct client *head;
    struct client *tail;
    int length;
} clientQueue;

struct statistics {
    long totalConnects;
    long long totalWastedTime;
} stats;

long long currentTimeMs() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

void queue_init(struct queue *q) {
    q->head = q->tail = NULL;
    q->length = 0;
}

void queue_append(struct queue *q, struct client *c) {
    c->next = NULL;
    if (q->tail != NULL) {
        q->tail->next = c;
    } else {
        q->head = c;
    }
    q->tail = c;
    q->length++;
}

struct client *queue_pop(struct queue *q) {
    if (q->head == NULL) return NULL;
    struct client *c = q->head;
    q->head = c->next;
    if (!q->head) {
        q->tail = NULL;
    }
    q->length--;
    return c;
}

void heartbeat_log() {
    syslog(LOG_INFO, "Server is running with %d connected clients.", clientQueue.length);
    syslog(LOG_INFO, "Current statistics: wasted time: %lld ms. Total connected clients: %ld", stats.totalWastedTime, stats.totalConnects);
}

int create_server(int port) {
    int r; 
    int sockfd;
    int value;

    // IPv4 TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        syslog(LOG_ERR,"Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Enable SO_REUSEADDR for faster restarts
    value = 1;
    r = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
    if (r == -1) {
        syslog(LOG_ERR,"setsockopt failed");
    }

    // Bind to IPv4 address and port
    struct sockaddr_in addr4 = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {INADDR_ANY}
    };
    r = bind(sockfd, (struct sockaddr *)&addr4, sizeof(addr4));
    if (r == -1) {
        syslog(LOG_ERR,"Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Listen with a very large backlog (INT_MAX) to handle massive bot traffic
    r = listen(sockfd, INT_MAX);
    if (r == -1) {
        syslog(LOG_ERR,"Listen failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO,"Telnet tarpit listening on port %d...\n", port);
    return sockfd;
}

int main() {
    openlog("telnet_tarpit", LOG_PID | LOG_CONS, LOG_USER);
    stats.totalConnects = 0;
    stats.totalWastedTime = 0;
    signal(SIGPIPE, SIG_IGN); // Ignore 
    queue_init(&clientQueue);
    
    int serverSock = create_server(PORT);
    if (serverSock < 0) {
        syslog(LOG_ERR, "Invalid server socket fd: %d", serverSock);
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    
    struct pollfd fds;
    memset(&fds, 0, sizeof(fds));
    fds.fd = serverSock;
    fds.events = POLLIN;
    
    long long lastHeartbeat = currentTimeMs();
    while (1) {
        long long now = currentTimeMs();
        int timeout = -1;

        if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
            heartbeat_log();
            lastHeartbeat = now;
        }

        // Process clients in queue
        while (clientQueue.head) {
            if(clientQueue.head->sendNext <= now){
                struct client *c = queue_pop(&clientQueue);
                
                int optionIndex = rand() % num_options;
                ssize_t out = write(c->fd, negotiations[optionIndex], sizeof(negotiations[optionIndex]));
                
                if (out <= 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) { // Avoid blocking
                        c->sendNext = now + DELAY_MS;
                        c->timeConnected += DELAY_MS;
                        stats.totalWastedTime += DELAY_MS;
                        queue_append(&clientQueue, c);
                    } else {
                        long long timeTrapped = c->timeConnected;
                        syslog(LOG_INFO, "Client disconnected from IP: %s:%d with fd: %d with time %lld", 
                            c->ipaddr, c->port, c->fd, timeTrapped);
                        close(c->fd);
                        free(c);
                    }
                } else {
                    c->sendNext = now + DELAY_MS;
                    c->timeConnected += DELAY_MS;
                    stats.totalWastedTime += DELAY_MS;
                    queue_append(&clientQueue, c);
                }
            } else {
                timeout = clientQueue.head->sendNext - now;
                break;
            }
        }
        
        int pollResult = poll(&fds, 1, timeout);
        if (pollResult < 0) {
            syslog(LOG_ERR, "Poll error with error %s", strerror(errno));
            continue;
        }

        // Accept new connections
        if (fds.revents & POLLIN) {
            int clientFd = accept(serverSock, (struct sockaddr *)&clientAddr, &addrLen);
            if (clientFd >= 0) {
                fcntl(clientFd, F_SETFL, O_NONBLOCK); // Set non-blocking mode
                struct client *newClient = malloc(sizeof(struct client));
                if (!newClient) {
                    syslog(LOG_ERR, "Out of memory");
                    close(clientFd);
                    continue;
                }

                stats.totalConnects += 1;
                newClient->fd = clientFd;
                newClient->sendNext = now + DELAY_MS;
                newClient->timeConnected = 0;
                strncpy(newClient->ipaddr, inet_ntoa(clientAddr.sin_addr), INET6_ADDRSTRLEN);
                newClient->port = ntohs(clientAddr.sin_port);
                queue_append(&clientQueue, newClient);

                syslog(LOG_INFO,"Accepted connection from %s:%d\n",
                    inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
            }
        }
    }

    closelog();
    close(serverSock);
    return 0;
}
