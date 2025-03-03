#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>

#define SSDP_PORT 1900
#define HTTP_PORT 8080
#define SSDP_MULTICAST "239.255.255.250"

const char *FAKE_SSDP_RESPONSE = "fake ssdp response";
const char *FAKE_SUBSCRIBE_RESPONSE = "fake subscribe response";
const char *FAKE_DEVICE_DESCRIPTION = "fake description response";

// Handles SSDP discovery requests and sends fake responses
void *ssdpListener(void *arg) {
    int sock;
    struct sockaddr_in serverAddr, client_addr;
    socklen_t addrLen = sizeof(client_addr);
    char buffer[1024];

    // Create UDP socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "SSDP Socket creation failed");
        return NULL;
    }

    // Bind to SSDP multicast address
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(SSDP_PORT);

    if (bind(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        syslog(LOG_ERR, "SSDP Bind failed");
        close(sock);
        return NULL;
    }

    syslog(LOG_INFO, "UPnP SSDP tarpit started on port %d\n", SSDP_PORT);

    while (1) {
        memset(buffer, 0, sizeof(buffer));

        if (recvfrom(sock, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&client_addr, &addrLen) < 0) {
            syslog(LOG_ERR, "Error receiving SSDP request");
            continue;
        }

        if (strstr(buffer, "M-SEARCH") != NULL) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            syslog(LOG_INFO, "Received SSDP M-SEARCH request from %s\n", client_ip);

            sendto(sock, FAKE_SSDP_RESPONSE, strlen(FAKE_SSDP_RESPONSE), 0,
                   (struct sockaddr *)&client_addr, sizeof(client_addr));
            syslog(LOG_INFO, "Sent fake SSDP response to %s\n", client_ip);
        }
    }

    close(sock);
    return NULL;
}

void *httpServer(void *arg) {
    int serverFd, clientFd;
    struct sockaddr_in serverAddr, client_addr;
    socklen_t addrLen = sizeof(client_addr);
    char buffer[1024];

    serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd == -1) {
        syslog(LOG_ERR, "HTTP Socket creation failed");
        return NULL;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(HTTP_PORT);

    if (bind(serverFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        syslog(LOG_ERR, "HTTP Bind failed");
        close(serverFd);
        return NULL;
    }

    listen(serverFd, 5);
    syslog(LOG_INFO, "Fake UPnP HTTP Server started on port %d\n", HTTP_PORT);

    while (1) {
        clientFd = accept(serverFd, (struct sockaddr *)&client_addr, &addrLen);
        if (clientFd < 0) continue;

        read(clientFd, buffer, sizeof(buffer));
        write(clientFd, "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n", 46);

        if (strstr(buffer, "SUBSCRIBE")) {
            write(clientFd, FAKE_SUBSCRIBE_RESPONSE, strlen(FAKE_SUBSCRIBE_RESPONSE));
        } else {
            write(clientFd, FAKE_DEVICE_DESCRIPTION, strlen(FAKE_DEVICE_DESCRIPTION));
        }

        close(clientFd);
    }

    close(serverFd);
    return NULL;
}

int main() {
    pthread_t ssdpThread, httpThread;
    pthread_create(&ssdpThread, NULL, ssdpListener, NULL);
    pthread_create(&httpThread, NULL, httpServer, NULL);
    pthread_join(ssdpThread, NULL);
    pthread_join(httpThread, NULL);
    return 0;
}
