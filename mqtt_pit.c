// Idea: Never finish the 4-way handshake that is required for QoS 2. Specifications on this is undefined, since a server is expected to always complete the handshake
// Idea: Server sets a low (1) Receive Maximum in CONNACK 
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

#define PORT 1884 // Remember to change to 1883
#define MAX_FDS 1024
#define MAX_EVENTS 10

struct mqttClient* clients = NULL;

struct mqttClient* lookupClient(int fd) {
    struct mqttClient* client;

    HASH_FIND_INT(clients, &fd, client);
    return client;
}

void addClient(struct mqttClient* client) {
    HASH_ADD_INT(clients, fd, client);
}

void deleteClient(struct mqttClient* client) {
    HASH_DEL(clients, client);
}

void readConnreq(uint8_t* buffer, int length, int offset, struct mqttClient* client){
    // --- Protocol Name ---
    if (offset + 2 > length) return;
    uint16_t proto_name_len = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (proto_name_len != 4 || memcmp(&buffer[offset], "MQTT", 4) != 0) {
        syslog(LOG_ERR, "Malformed CONNECT request. Expected \"MQTT\" but instead got 0x%04X", buffer[offset]);
        return;
    }
    offset += 4;

    // --- Protocol Version ---
    if (offset >= length) return;
    uint8_t proto_level = buffer[offset++];
    if(proto_level == 0b101) {
        client->version = V5;
    } else if (proto_level == 0b100) {
        client->version = V311;
    } else {
        syslog(LOG_ERR, "Unsupported MQTT version: %d", proto_level);
        return;
    }
    printf("Protocol Level: %d\n", proto_level);

    // --- Connect Flags ---
    if (offset >= length) return;
    uint8_t connect_flags = buffer[offset++];
    printf("Connect Flags: 0x%02X\n", connect_flags);

    // --- Keep Alive ---
    if (offset + 2 > length) return;
    uint16_t keep_alive = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    printf("Keep Alive: %u seconds\n", keep_alive);

    // --- Properties Length (varint) --- (ONLY VERSION 5)
    if(proto_level == 0b101) {
        int prop_len = 0; // uint32_t
        int multiplier = 1;
        // int prop_offset_start = offset;
        uint8_t byte;
        do {
            if (offset >= length) return;
            byte = buffer[offset++];
            prop_len += (byte & 127) * multiplier;
            multiplier *= 128;
        } while ((byte & 0x80) != 0);

        printf("Properties Length: %u bytes\n", prop_len);

        if (offset + prop_len > length) {
            syslog(LOG_ERR, "Malformed properties: exceeds packet bounds");
            return;
        }

        // --- Parse Properties ---
        int props_end = offset + prop_len;
        while (offset < props_end && offset < length) {
            uint8_t prop_id = buffer[offset++];
            switch (prop_id) {
                case 0x11:  // Session expiry interval
                    break;
                case 0x21:  // Receive Maximum
                    if (offset + 2 > length) return;
                    uint16_t receive_max = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;
                    printf("Receive Maximum: %u\n", receive_max);
                    break;
                default:
                    printf("Unknown Property ID: 0x%02X\n", prop_id);
                    return;
            }
        }
    }

    // --- Payload: Client ID ---
    if (offset + 2 > length) return;
    uint16_t client_id_len = (buffer[offset] << 8) | buffer[offset + 1];
    // printf("Client ID Length: %u\n", client_id_len);
    offset += 2;

    if (offset + client_id_len > length) return;
    char client_id[256] = {0};
    uint16_t safe_len = client_id_len < 255 ? client_id_len : 255;
    memcpy(client_id, &buffer[offset], safe_len);
    offset += client_id_len;
    printf("Client ID: %s\n", client_id);

    // --- Optional Username ---
    if (connect_flags & 0x80) {
        if (offset + 2 > length) return;
        uint16_t user_len = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        if (offset + user_len > length) return;

        char username[256] = {0};
        uint16_t safe_len = user_len < 255 ? user_len : 255;
        memcpy(username, &buffer[offset], safe_len);
        offset += user_len;
        printf("Username: %s\n", username);
    }

    // --- Optional Password ---
    if (connect_flags & 0x40) {
        if (offset + 2 > length) return;
        uint16_t pass_len = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        if (offset + pass_len > length) return;

        char password[256] = {0};
        uint16_t safe_len = pass_len < 255 ? pass_len : 255;
        memcpy(password, &buffer[offset], safe_len);
        offset += pass_len;
        printf("Password: %s\n", password);
    }
}

void sendConnack(struct mqttClient* client){
    int size = client->version == V5 ? 8 : 4;
    uint8_t *arr = (uint8_t *)malloc( sizeof(uint8_t) * size ) ;
    if(client->version == V5) {
        arr[0] = 0x20;       // CONNACK fixed header
        arr[1] = 0x06;       // Remaining Length
        arr[2] = 0x00;       // Connect Acknowledge Flags (no session flag)
        arr[3] = 0x00;       // Reason Code (Success)
        arr[4] = 0x03;       // Properties Length
        arr[5] = 0x21;       // Property ID: Receive Maximum
        arr[6] = 0x00;       // MSB
        arr[7] = 0x01;       // LSB (Receive Maximum = 1)
    } else {
        arr[0] = 0x20;       // CONNACK fixed header
        arr[1] = 0x02;       // Remaining length
        arr[2] = 0x00;       // Connect Acknowledge Flags (no session flag)
        arr[3] = 0x00;       // Return code (Success)
    }

    write(client->fd, arr, sizeof(arr));
    free(arr);
}

enum State determineRequest(uint8_t firstByte) {
    switch ((int) firstByte)
    {
    case 0b00010000:
        return CONNECT;
    case 0b01010000:
        return PUBREC;
    // case PUBLISH
    default:
        return UNSUPPORTED_REQUEST;
    }
}

void calculateTotalPacketLength(uint8_t *buffer, int bytesWrittenToBuffer, int result[]) {
    if (bytesWrittenToBuffer < 2) result[0] = -1; // Not enough for fixed header

    int offset = 1; // Start at the remaining length field
    uint32_t value = 0; // The actual number of bytes in the variable header + payload
    int encodedBytes = 0; // The number of bytes that were used to encode value

    // uint8_t encodedByte;
    int multiplier = 1;
    // do {
    //     encodedByte = buffer[offset++];
    //     value += (encodedByte & 0b01111111) * multiplier; // Only use the least significant seven bits
    //     if (multiplier > 128*128*128) {
    //         // error
    //     }
    //     multiplier *= 128; // Maybe bit-shift instead for performance
    //     encodedBytes++;
    // } while((encodedByte & 0b10000000) != 0);

    for (int i = 0; i < 4 && offset < bytesWrittenToBuffer; i++) { // do-while maybe
        uint8_t byte = buffer[offset++];
        value += (byte & 0b01111111) * multiplier; // Only use the least significant seven bits
        multiplier *= 128; // Maybe bit-shift instead for performance
        encodedBytes++;
        if (!(byte & 0b10000000)) break;
    }

    // fixed header + number of bytes used to encode value +  (number of bytes in the variable header + payload)
    int totalPacketBytes = 1 + encodedBytes + value;
    result[1] = offset;
    if (bytesWrittenToBuffer >= totalPacketBytes)
        result[0] = totalPacketBytes;
    else
        result[0] = -1; // Not full packet yet
}

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
        // Maybe use edge trigger, to avoid checking fd multiple times for incomplete packet transfer
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
                struct mqttClient* newClient = malloc(sizeof(struct mqttClient)); // TODO: Remember to free
                newClient->fd = clientFd;
                strncpy(newClient->ipaddr, inet_ntoa(clientAddr.sin_addr), INET6_ADDRSTRLEN);
                newClient->port = ntohs(clientAddr.sin_port);
                newClient->timeConnected = 0;
                newClient->state = CONNECT;
                newClient->bytesWrittenToBuffer = 0;
                memset(newClient->buffer, 0, sizeof(newClient->buffer)); // Maybe not necessary
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
                addClient(newClient);
            } else {
                struct mqttClient* client = lookupClient(currentFd);
                ssize_t bytesRead = read(currentFd,
                          client->buffer + client->bytesWrittenToBuffer,
                          sizeof(client->buffer) - client->bytesWrittenToBuffer);

                if(bytesRead < 0) {
                    syslog(LOG_ERR, "Failed reading");
                    exit(EXIT_FAILURE);
                }

                client->bytesWrittenToBuffer += bytesRead;

                int result[2]; // [total packet length, offset pointing to variable header]
                calculateTotalPacketLength(client->buffer, client->bytesWrittenToBuffer, result);
                if (result[0] < 0) {
                    continue;
                }

                enum State state = determineRequest(client->buffer[0]);
                if(state != client->state) {
                    syslog(LOG_ERR, "wrong state");
                    // Close fd and free client
                }

                switch (state) {
                    case CONNECT:
                        readConnreq(client->buffer, result[0], result[1], client);
                        sendConnack(client);
                        break;
                    case PUBREC:
                        break;
                    default:
                        break;
                }

                // Leftover ?
            }
        }
    }

    closelog();
    close(serverSock);
    return 0;
}

