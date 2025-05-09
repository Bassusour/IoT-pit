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
#include "../shared/structs.h"

#define PORT 23
#define DELAY_MS 100
#define HEARTBEAT_INTERVAL_MS 600000 // 10 minutes
#define FD_LIMIT 4096
#define SERVER_ID "Telnet"

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

void heartbeatLog() {
    syslog(LOG_INFO, "Server is running with %d connected clients. Number of most concurrent connected clients is %d", clientQueueTelnet.length, statsTelnet.mostConcurrentConnections);
    syslog(LOG_INFO, "Current statistics: wasted time: %lld ms. Total connected clients: %ld", statsTelnet.totalWastedTime, statsTelnet.totalConnects);
}

void initializeStats(){
    statsTelnet.totalConnects = 0;
    statsTelnet.totalWastedTime = 0;
    statsTelnet.mostConcurrentConnections = 0;
}

int main() {
    openlog("telnet_tarpit", LOG_PID | LOG_CONS, LOG_USER);
    initializeStats();
    setFdLimit(FD_LIMIT);
    signal(SIGPIPE, SIG_IGN); // Ignore 
    queue_init(&clientQueueTelnet);
    
    int serverSock = createServer(PORT);
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
            heartbeatLog();
            lastHeartbeat = now;
        }

        // Process clients in queue
        while (clientQueueTelnet.head) {
            if(clientQueueTelnet.head->sendNext <= now){
                struct client *c = queue_pop(&clientQueueTelnet);
                
                int optionIndex = rand() % num_options;
                ssize_t out = write(c->fd, negotiations[optionIndex], sizeof(negotiations[optionIndex]));
                
                if (out == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) { // Avoid blocking
                        c->sendNext = now + DELAY_MS;
                        c->timeConnected += DELAY_MS;
                        statsTelnet.totalWastedTime += DELAY_MS;
                        queue_append(&clientQueueTelnet, c);
                    } else {
                        long long timeTrapped = c->timeConnected;
                        // syslog(LOG_INFO, "Client disconnected from IP: %s with fd: %d with time %lld", 
                        //     c->ipaddr, c->fd, timeTrapped);
                        char msg[256];
                        snprintf(msg, sizeof(msg), "%s disconnect %s  %lld",
                            SERVER_ID, c->ipaddr, timeTrapped);
                        sendMetric(msg);
                        close(c->fd);
                        free(c);
                    }
                } else {
                    c->sendNext = now + DELAY_MS;
                    c->timeConnected += DELAY_MS;
                    statsTelnet.totalWastedTime += DELAY_MS;
                    queue_append(&clientQueueTelnet, c);
                }
            } else {
                timeout = clientQueueTelnet.head->sendNext - now;
                break;
            }
        }
        
        int pollResult = poll(&fds, 1, timeout);
        now = currentTimeMs(); // Poll will cause old value to be misrepresenting
        if (pollResult < 0) {
            syslog(LOG_ERR, "Poll error with error %s", strerror(errno));
            continue;
        }

        // Accept new connections
        if (fds.revents & POLLIN) {
            int clientFd = accept(serverSock, (struct sockaddr *)&clientAddr, &addrLen);
            if(clientFd == -1) {
                syslog(LOG_ERR, "Failed accepting new client with error %s", strerror(errno));
                continue;
            }

            fcntl(clientFd, F_SETFL, O_NONBLOCK); // Set non-blocking mode
            struct client* newClient = malloc(sizeof(struct client));
            if (!newClient) {
                syslog(LOG_ERR, "Out of memory");
                close(clientFd);
                continue;
            }

            statsTelnet.totalConnects += 1;
            newClient->fd = clientFd;
            newClient->sendNext = now + DELAY_MS;
            newClient->timeConnected = 0;
            strncpy(newClient->ipaddr, inet_ntoa(clientAddr.sin_addr), INET6_ADDRSTRLEN);
            queue_append(&clientQueueTelnet, newClient);

            if(statsTelnet.mostConcurrentConnections < clientQueueTelnet.length) {
                statsTelnet.mostConcurrentConnections = clientQueueTelnet.length;
            }

            syslog(LOG_INFO,"Accepted connection from %s\n",
                inet_ntoa(clientAddr.sin_addr));
        }
    }

    closelog();
    close(serverSock);
    return 0;
}
