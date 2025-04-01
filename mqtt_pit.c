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

void readConnreq(uint8_t* buffer, uint32_t length, uint32_t offset, struct mqttClient* client){
    if (offset + 2 > length) return;

    uint16_t protocolName = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    
    // printf("CONNECT request package:\n");
    // for (size_t i = 0; i < length; i++) {
    //     printf("%02X ", buffer[i]);
    // }
    // printf("\n");

    if (protocolName != 4 || memcmp(&buffer[offset], "MQTT", 4) != 0) {
        char wrong[5] = {0};
        memcpy(wrong, &buffer[offset], protocolName < 4 ? protocolName : 4);
        syslog(LOG_ERR, "Malformed CONNECT request. Expected \"MQTT\" but got \"%s\"", wrong);
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

    // Connect Flags
    if (offset >= length) return;
    uint8_t connect_flags = buffer[offset++];
    printf("Connect Flags: 0x%02X\n", connect_flags);

    // Keep Alive
    if (offset + 2 > length) return;
    uint16_t keep_alive = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    printf("Keep Alive: %u seconds\n", keep_alive);

    // Properties Length (varint) (ONLY VERSION 5)
    if(client->version == V5) {
        uint32_t prop_len = 0;
        int multiplier = 1;
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

        // Parse Properties
        uint32_t props_end = offset + prop_len;
        while (offset < props_end && offset < length) {
            uint8_t prop_id = buffer[offset++];
            switch (prop_id) {
                case 0x11:  // TODO: Session expiry interval
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

    // Payload: Client ID
    if (offset + 2 > length) return;
    uint16_t clientIdLength = (buffer[offset] << 8) | buffer[offset + 1];
    // printf("Client ID Length: %u\n", clientIddLength);
    offset += 2;

    if (offset + clientIdLength > length) return;
    char client_id[256] = {0};
    uint16_t safeLength = clientIdLength < 255 ? clientIdLength : 255;
    memcpy(client_id, &buffer[offset], safeLength);
    offset += clientIdLength;
    printf("Client ID: %s\n", client_id);

    // Optional Username
    if (connect_flags & 0x80) {
        if (offset + 2 > length) return;
        uint16_t user_len = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        if (offset + user_len > length) return;

        char username[256] = {0};
        uint16_t safeLength = user_len < 255 ? user_len : 255;
        memcpy(username, &buffer[offset], safeLength);
        offset += user_len;
        printf("Username: %s\n", username);
    }

    // Optional Password
    if (connect_flags & 0x40) {
        if (offset + 2 > length) return;
        uint16_t passwordLength = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        if (offset + passwordLength > length) return;

        char password[256] = {0};
        uint16_t safeLength = passwordLength < 255 ? passwordLength : 255;
        memcpy(password, &buffer[offset], safeLength);
        offset += passwordLength;
        printf("Password: %s\n", password);
    }
}

void readSubscribe(uint8_t* buffer, uint32_t length, uint32_t offset, enum MqttVersion version, uint32_t* packetId, char* topic, bool* allowedQoS) {
    if (offset + 2 > length) {
        syslog(LOG_ERR, "SUBSCRIBE request too short");
        return;
    }

    *packetId = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    printf("SUBSCRIBE Packet ID: %d\n", *packetId);

    if (version == V5) {
        uint32_t propsLength = 0;
        int multiplier = 1;
        int varintBytes = 0;
        uint8_t byte;

        do {
            if (offset >= length) return;
            byte = buffer[offset++];
            propsLength += (byte & 0b01111111) * multiplier;
            multiplier *= 128;
            varintBytes++;
        } while ((byte & 0b10000000) != 0 && varintBytes <= 4);

        printf("Properties Length: %u\n", propsLength);

        if (offset + propsLength > length) {
            printf("Malformed property section in SUBSCRIBE\n");
            return;
        }

        // parse actual properties here if needed
        offset += propsLength;
    } else if (version == V311) {
        printf("MQTT v3.1.1 — no SUBSCRIBE properties\n");
    } else {
        printf("Unknown MQTT version.\n");
        return;
    }

    while (offset + 3 <= length) {  // 2 bytes topic + 1 byte options
        uint16_t topicLength = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        if (offset + topicLength + 1 > length) {
            printf("Malformed topic filter\n");
            return;
        }

        uint16_t safeLength = topicLength < 255 ? topicLength : 255;
        memcpy(topic, &buffer[offset], safeLength);
        topic[safeLength] = '\0';
        offset += topicLength;

        uint8_t options = buffer[offset++];
        uint8_t qos = options & 0b11;
        if(qos < 2) {
            *allowedQoS = false;
        } else {
            *allowedQoS = true;
        }

        printf("Topic Filter: %s\n", topic);
        printf("QoS: %d\n", options & 0b11);
        // printf("  No Local: %d\n", (options >> 2) & 0b01);
        // printf("  Retain As Published: %d\n", (options >> 3) & 0b01);
        // printf("  Retain Handling: %d\n", (options >> 4) & 0b11);
    }
}

void sendSuback(struct mqttClient* client, uint16_t packet_id, bool allwedQoS) {
    uint8_t fixedHeader[5];
    uint8_t propsLength = 0;

    size_t remainingLength = 2 + (client->version == V5 ? 1 + propsLength : 0) + 1;  // Packet ID + [Props] + Reason Code

    // Encode Remaining Length
    size_t fixedHeaderLength = 0;
    fixedHeader[fixedHeaderLength++] = 0b10010000;  // SUBACK

    size_t rem = remainingLength;
    do {
        uint8_t byte = rem % 128;
        rem /= 128;
        if (rem > 0) byte |= 128;
        fixedHeader[fixedHeaderLength++] = byte;
    } while (rem > 0);

    // Build Full Packet
    ssize_t totalLength = fixedHeaderLength + remainingLength;
    uint8_t* packet = malloc(totalLength);
    if (!packet) return;

    size_t offset = 0;
    memcpy(packet, fixedHeader, fixedHeaderLength);
    offset += fixedHeaderLength;

    // Packet ID (big endian)
    packet[offset++] = packet_id >> 8;
    packet[offset++] = packet_id & 0xFF;

    // Properties (MQTT v5 only)
    if (client->version == V5) {
        packet[offset++] = propsLength;
    }

    // Reason Code / Return Code
    packet[offset++] = allwedQoS ? 0x02 : 0x80;

    // printf("SUBACK package:\n");
    // for (size_t i = 0; i < totalLength; i++) {
    //     printf("%02X ", packet[i]);
    // }
    // printf("\n");

    // Send
    ssize_t w = write(client->fd, packet, totalLength);
    if (w != totalLength) {
        perror("sendSuback: write failed");
    } else {
        printf("Sent SUBACK (QoS 2) to client %d\n", client->fd);
    }

    free(packet);
}

void sendConnack(struct mqttClient* client){
    int size = client->version == V5 ? 5 : 4;
    uint8_t *arr = (uint8_t *)malloc( sizeof(uint8_t) * size ) ;
    if(client->version == V5) {
        arr[0] = 0x20;      // CONNACK fixed header
        arr[1] = 0x03;      // Remaining Length
        arr[2] = 0x00;      // Connect Acknowledge Flags (no session flag)
        arr[3] = 0x00;      // Reason Code (Success)
        arr[4] = 0x00;      // Properties Length
                            // Maybe set session expiry interval
        // arr[5] = 0x21;      // Property ID: Receive Maximum
        // arr[6] = 0x00;      // MSB
        // arr[7] = 0x01;      // LSB (Receive Maximum = 1)
    } else {
        arr[0] = 0x20;      // CONNACK fixed header
        arr[1] = 0x02;      // Remaining length
        arr[2] = 0x00;      // Connect Acknowledge Flags (no session flag)
        arr[3] = 0x00;      // Return code (Success)
    }

    write(client->fd, arr, size);
    printf("Sent CONNACK\n");
    free(arr);
}

void sendPublish(struct mqttClient* client, const char* topic, const char* message) {
    uint16_t topicLength = strlen(topic);
    uint16_t payloadLength = strlen(message);
    uint8_t propertiesLength = 0; // No props

    size_t remainingLength = 2 + topicLength + 2; // length prefix + Topic + Packet ID (QoS2)
    if (client->version == V5) {
        remainingLength += 1 + propertiesLength; // Must add properties
    }
    remainingLength += payloadLength;

    uint8_t fixedHeader[5];
    size_t fixedHeaderLength = 0;
    // fixedHeader[fixedHeaderLength++] = 0b110100; // QoS 2
    fixedHeader[fixedHeaderLength++] = 0x34;

    // Encode Remaining Length
    size_t rem = remainingLength;
    do {
        uint8_t byte = rem % 128;
        rem /= 128;
        if (rem > 0) byte |= 128;
        fixedHeader[fixedHeaderLength++] = byte;
    } while (rem > 0);

    ssize_t packetLength = fixedHeaderLength + remainingLength;
    uint8_t* packet = malloc(packetLength);
    if (!packet) return;

    size_t offset = 0;
    memcpy(packet, fixedHeader, fixedHeaderLength);
    offset += fixedHeaderLength;

    // Big endian topic
    packet[offset++] = topicLength >> 8;
    packet[offset++] = topicLength & 0xFF;
    memcpy(packet + offset, topic, topicLength);
    offset += topicLength;

    // Big endian packetId
    static uint16_t packetId = 1234; // TODO: Random id generator
    packet[offset++] = packetId >> 8;
    packet[offset++] = packetId & 0xFF;

    if (client->version == V5) {
        packet[offset++] = propertiesLength;
    }

    memcpy(packet + offset, message, payloadLength);
    offset += payloadLength;

    // printf("Send publish packet: \n");
    // for (size_t i = 0; i < packetLength; i++) {
    //     printf("%02X ", packet[i]);
    // }
    printf("\n");
    ssize_t w = write(client->fd, packet, packetLength);
    if (w != packetLength) {
        syslog(LOG_ERR, "sendPublish: write failed");
    } else {
        printf("Sent PUBLISH to client (fd=%d), topic=%s\n", client->fd, topic);
    }

    free(packet);
}

void readPubrec(uint8_t* buffer, uint32_t length, uint32_t offset, struct mqttClient* client) {
    if (offset + 2 > length) {
        printf("PUBREC packet too short for Packet Identifier\n");
        return;
    }

    uint16_t packet_id = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    printf("PUBREC Packet ID: %u\n", packet_id);

    if (client->version == V5) {
        if (offset >= length) {
            printf("No Reason Code (default: Success)\n");
            return;
        }
        uint8_t reason_code = buffer[offset++];
        printf("Reason Code: 0x%02X\n", reason_code);

        if (offset >= length) {
            printf("No Properties present\n");
            return;
        }

        uint32_t prop_len = 0;
        int multiplier = 1;
        int varint_bytes = 0;
        uint8_t byte;
        do {
            if (offset >= length) return;
            byte = buffer[offset++];
            prop_len += (byte & 127) * multiplier;
            multiplier *= 128;
            varint_bytes++;
        } while ((byte & 128) != 0 && varint_bytes <= 4);

        printf("Properties Length: %u\n", prop_len);

        if (offset + prop_len > length) {
            printf("Invalid Properties Length\n");
            return;
        }
    }
}

void sendPingresp(struct mqttClient* client) {
    uint8_t packet[2] = { 0xD0, 0x00 };
    ssize_t w = write(client->fd, packet, sizeof(packet));
    if (w == 2) {
        printf("Sent PINGRESP to client (fd=%d)\n", client->fd);
    } else {
        syslog(LOG_ERR, "sendPingresp: write failed");
    }
}

void disconnectClient(struct mqttClient* client, int epollFd){
    epoll_ctl(epollFd, EPOLL_CTL_DEL, client->fd, NULL);
    deleteClient(client);
    close(client->fd);
    free(client);
}

enum State determineRequest(uint8_t firstByte) {
    switch ((int) firstByte)
    {
    case 0b00010000:
        return CONNECT;
    case 0b01010000:
        return PUBREC;
    case 0b10000010:
        return SUBSCRIBE;
    case 0b11000000:
        return PING;
    case 0b11100000:
        return DISCONNECT;
    default:
        return UNSUPPORTED_REQUEST;
    }
}

void calculateTotalPacketLength(uint8_t *buffer, uint32_t bytesWrittenToBuffer, uint32_t* totalPacketLength, uint32_t* offset) {
    *totalPacketLength = 0;  // Default to "not ready"

    if (bytesWrittenToBuffer < 2) {
        return;  // Not enough for even fixed header
    }

    *offset = 1;                // Start at the remaining length field
    uint32_t value = 0;         // The actual number of bytes in the variable header + payload
    uint32_t encodedBytes = 0;  // The number of bytes that were used to encode value
    uint32_t multiplier = 1;    

    // Parse the variable-length Remaining Length field (max 4 bytes)
    for (int i = 0; i < 4; i++) {
        if (*offset >= bytesWrittenToBuffer) {
            return;  // Not enough data to finish varint
        }
        uint8_t byte = buffer[*offset];
        value += (byte & 0b01111111) * multiplier;
        multiplier *= 128;
        (*offset)++;
        encodedBytes++;

        if ((byte & 0b10000000) == 0) {
            break;  // Finished parsing varint
        }
    }

    // fixed header + number of bytes used to encode value +  (number of bytes in the variable header + payload)
    uint32_t totalBytes = 1 + encodedBytes + value;
    if (bytesWrittenToBuffer >= totalBytes) {
        *totalPacketLength = totalBytes;
    }
}

void cleanupBuffer(struct mqttClient* client, uint32_t packetLength){
    int leftover = client->bytesWrittenToBuffer - packetLength;
    memmove(client->buffer, client->buffer + packetLength, leftover);
    client->bytesWrittenToBuffer = leftover;
}

int main() {
    openlog("mqtt_tarpit", LOG_PID | LOG_CONS, LOG_USER);
    
    // signal(SIGPIPE, SIG_IGN);
    
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
                struct mqttClient* newClient = malloc(sizeof(struct mqttClient));
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
                    // TODO: Error handling
                    // exit(EXIT_FAILURE);
                }

                client->bytesWrittenToBuffer += bytesRead;

                // int result[2]; // [total packet length, offset pointing to variable header]
                uint32_t totalPacketLength, variableHeaderOffset = 100;
                calculateTotalPacketLength(client->buffer, client->bytesWrittenToBuffer, &totalPacketLength, &variableHeaderOffset);
                if (totalPacketLength == 0) {
                    // printf("No full packet");
                    continue;
                }

                enum State state = determineRequest(client->buffer[0]);

                switch (state) {
                    case CONNECT:
                        readConnreq(client->buffer, totalPacketLength, variableHeaderOffset, client);
                        cleanupBuffer(client, totalPacketLength);
                        sendConnack(client);
                        sendPublish(client, "$SYS/confidential", "username=admin password=admin");
                        break;
                    case SUBSCRIBE:
                        uint32_t packetId;
                        char topic[256];
                        bool allowedQoS;
                        readSubscribe(client->buffer, totalPacketLength, variableHeaderOffset, client->version, &packetId, topic, &allowedQoS);
                        cleanupBuffer(client, totalPacketLength);
                        sendSuback(client, packetId, allowedQoS);
                        sendPublish(client, topic, "hehhe");
                        break;
                    case PUBREC:
                        readPubrec(client->buffer, totalPacketLength, variableHeaderOffset, client);
                        cleanupBuffer(client, totalPacketLength);
                        break;
                    case PING:
                        cleanupBuffer(client, totalPacketLength);
                        sendPingresp(client);
                        break;
                    case DISCONNECT:
                        disconnectClient(client, epollfd);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    closelog();
    close(serverSock);
    return 0;
}

