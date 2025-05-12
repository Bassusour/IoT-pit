#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <stdio.h>
#include "structs.h"

struct queue clientQueueTelnet;
struct queue clientQueueUpnp;
struct telnetStatistics statsTelnet;
struct upnpStatistics statsUpnp;
struct mqttStatistics statsMqtt;

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

int createServer(int port) {
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

    // Set TCP receive window
    int winSize = 256; // Doubled
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &winSize, sizeof(winSize));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &winSize, sizeof(winSize));

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

    // Listen with a very large backlog
    r = listen(sockfd, INT_MAX);
    if (r == -1) {
        syslog(LOG_ERR,"Listen failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO,"Server listening on port %d...\n", port);
    return sockfd;
}

long long currentTimeMs() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

void setFdLimit(int limit) {
    struct rlimit rl;
    rl.rlim_cur = limit;
    rl.rlim_max = limit;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "setrlimit failed"); 
    }
}

void sendMetric(const char* message) {
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", "/tmp/tarpit_exporter.sock");

    ssize_t sent = sendto(sock, message, strlen(message), 0, (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0) {
        perror("sendto failed");
    }
    close(sock);
}