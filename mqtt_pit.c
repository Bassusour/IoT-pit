// Idea: Never finish the 4-way handshake that is required for QoS 2. Specifications on this is undefined, since a server is expected to always complete the handshake

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <sys/socket.h>
#include "structs.h"

#define PORT 1883
#define MAX_FDS 1024
#define MAX_EVENTS 10

int main() {
    openlog("mqtt_tarpit", LOG_PID | LOG_CONS, LOG_USER);
    
    signal(SIGPIPE, SIG_IGN); // Ignore 
    
    int serverSock = createServer(PORT);
    if (serverSock < 0) {
        syslog(LOG_ERR, "Invalid server socket fd: %d", serverSock);
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);

    struct epoll_event ev, eventsQueue[MAX_EVENTS];
    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        syslog(LOG_ERR, "epoll_create1 failed");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN;
    ev.data.fd = serverSock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, serverSock, &ev) == -1) {
        syslog(LOG_ERR, "epoll_ctl: server_sock");
        exit(EXIT_FAILURE);
    }

    int nfds;
    while(true) {
        nfds = epoll_wait(epollfd, eventsQueue, MAX_EVENTS, -1);
        if (nfds == -1) {
            syslog(LOG_ERR, "epoll_wait");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int currentFd = eventsQueue[n].data.fd;
            if (currentFd == serverSock) {
                int clientFd = accept(serverSock, (struct sockaddr *) &clientAddr, &addrLen);
                if (clientFd == -1) {
                    syslog(LOG_ERR, "accept");
                    exit(EXIT_FAILURE);
                }
                struct mqttClient* newClient = malloc(sizeof(struct mqttClient));
                newClient->fd = clientFd;
                strncpy(newClient->ipaddr, inet_ntoa(clientAddr.sin_addr), INET6_ADDRSTRLEN);
                newClient->port = ntohs(clientAddr.sin_port);
                newClient->state = CONNREQ;
                newClient->timeConnected = 0;
                // ev.events = EPOLLIN | EPOLLET;
                // ev.data.fd = clientFd;
                fcntl(clientFd, F_SETFL, O_NONBLOCK);
                struct epoll_event clientEv;
                clientEv.events = EPOLLIN;
                clientEv.data.fd = clientFd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, clientFd, &clientEv) == -1) {
                    syslog(LOG_ERR, "epoll_ctl: clientFd");
                    exit(EXIT_FAILURE);
                }
            } else {
                struct mqttClient* client = lookupClient(currentFd);
                char* buffer[100];
                ssize_t n = read(currentFd, buffer, 100);
                if(n < 0) {
                    syslog(LOG_ERR, "Failed reading");
                    exit(EXIT_FAILURE);
                }

                if (client->state == CONNREQ) {
                    sendConnack(currentFd);
                    sendPublish(currentFd);
                    // Set event to poll for incoming
                    client->state = PUBACK;
                } else if (client->state == PUBACK) {
                    // Do nothing
                }
            }
        }

    closelog();
    close(serverSock);
    return 0;
    }
}

