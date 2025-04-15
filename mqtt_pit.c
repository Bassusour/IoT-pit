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
#define MAX_EVENTS 1024
#define EPOLL_TIMEOUT_INTERVAL_MS 5000
#define PUBREL_INTERVAL_MS 10000
#define HEARTBEAT_INTERVAL_MS 10000
#define MAX_PACKETS_PER_CLIENTS 50
#define FD_LIMIT 4096

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

void heartbeatLog() {
    syslog(LOG_INFO, "Server is running with %d connected clients. Number of most concurrent connected clients is %d", HASH_COUNT(clients), statsMqtt.mostConcurrentConnections);
    syslog(LOG_INFO, "The total amount of wasted time is %lld", statsMqtt.totalWastedTime);
}

void initializeStats(){
    statsMqtt.totalConnects = 0;
    statsMqtt.totalWastedTime = 0;
    statsMqtt.mostConcurrentConnections = 0;
}

bool decodeVarint(const uint8_t* buffer, uint32_t packetEnd, uint32_t* offset, uint32_t* value) {
    uint32_t result = 0;
    int multiplier = 1;
    uint8_t byte;
    int bytesRead = 0;

    do {
        if (*offset >= packetEnd) {
            syslog(LOG_ERR, "Incomplete variable byte integer");
            return false;
        }
        byte = buffer[(*offset)++];
        result += (byte & 0b01111111) * multiplier;
        multiplier *= 128;
        bytesRead++;

        if (bytesRead > 4) {
            syslog(LOG_ERR, "Variable byte integer exceeds maximum length");
            return false;
        }
    } while ((byte & 0b10000000) != 0);

    *value = result;
    return true;
}

uint8_t readConnreq(uint8_t* buffer, uint32_t packetEnd, uint32_t offset, struct mqttClient* client){
    // syslog(LOG_INFO, "Reading CONNECT request");
    if (offset + 2 > packetEnd) {
        syslog(LOG_ERR, "CONNECT request too small for fixed header");
        return 0x80; // Unspecified error
    } 

    uint16_t protocolName = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (protocolName != 4 || memcmp(&buffer[offset], "MQTT", 4) != 0) {
        char wrong[5] = {0};
        memcpy(wrong, &buffer[offset], protocolName < 4 ? protocolName : 4);
        syslog(LOG_ERR, "Malformed CONNECT request. Expected \"MQTT\" but got \"%s\"", wrong);
        return 0x01; // Unacceptable protocol version
    }
    offset += 4;

    // Protocol Version
    if (offset >= packetEnd) {
        syslog(LOG_ERR, "No protocol version given for CONNECT request");
        return 0x80;
    }
    uint8_t proto_level = buffer[offset++];
    if(proto_level != 0b101) {
        syslog(LOG_ERR, "Unsupported MQTT version: %d", proto_level);
        return 0x01; // Unacceptable protocol version
    }

    // Connect Flags
    if (offset >= packetEnd) {
        syslog(LOG_ERR, "No connect flags supplied");
        return 0x80;
    }
    uint8_t connect_flags = buffer[offset++];
    // printf("Connect Flags: 0x%02X\n", connect_flags);

    // Keep Alive
    if (offset + 2 > packetEnd){
        syslog(LOG_ERR, "No keep-alive value supplied");
        return 0x80;
    } 
    int keepAlive = (buffer[offset] << 8) | buffer[offset + 1];
    if(keepAlive < 0) {
        syslog(LOG_ERR, "Negative keep-alive value received: %d", keepAlive);
        return 0x80;
    }
    client->keepAlive = keepAlive;
    offset += 2;

    // Properties Length (varint)
    uint32_t varint;
    bool decodeSuccess = decodeVarint(buffer, packetEnd, &offset, &varint);
    if(!decodeSuccess) {
        return 0x80;
    }

    uint32_t props_end = offset + varint;
    while (offset < props_end && offset < packetEnd) {
        offset++; // Don't parse props, just skip
    }

    // Payload: Client ID
    if (offset + 2 > packetEnd) return 0x80;
    uint16_t clientIdLength = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (offset + clientIdLength > packetEnd) {
        syslog(LOG_ERR, "clientId too long for packet");
        return 0x02;
    }
    offset += clientIdLength;

    // Username
    char username[256] = {0};
    if (connect_flags & 0b10000000) {
        if (offset + 2 > packetEnd) {
            syslog(LOG_ERR, "Username flag supplied, but with no username");
            return 0x80;
        } 
        uint16_t user_len = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        if (offset + user_len > packetEnd) {
            syslog(LOG_ERR, "Username too long");
            return 0x80;
        }

        uint16_t safeLength = user_len < 255 ? user_len : 255;
        memcpy(username, &buffer[offset], safeLength);
        offset += user_len;
        // syslog(LOG_INFO, "Username: %s\n", username);
    }

    // Password
    char password[256] = {0};
    if (connect_flags & 0b1000000) {
        if (offset + 2 > packetEnd) {
            syslog(LOG_ERR, "Password flag supplied, but with no password");
            return 0x80;
        } 
        uint16_t passwordLength = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        if (offset + passwordLength > packetEnd){
            syslog(LOG_ERR, "Password too long");
            return 0x80;
        }

        
        uint16_t safeLength = passwordLength < 255 ? passwordLength : 255;
        memcpy(password, &buffer[offset], safeLength);
        offset += passwordLength;
        // syslog(LOG_INFO, "Password: %s\n", password);
    }

    syslog(LOG_INFO, "Successfully read CONNECT request with keep-alive: %d username: %s password: %s", keepAlive, username, password);
    return 0x00; // Success
}

void readSubscribe(uint8_t* buffer, uint32_t packetEnd, uint32_t offset) {
    // syslog(LOG_INFO, "Reading SUBSCRIBE request");
    if (offset + 2 > packetEnd) {
        syslog(LOG_ERR, "SUBSCRIBE request too short for fixed header");
        return;
    }

    // *packetId = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2; // packetId

    uint32_t varint;
    bool decodeSuccess = decodeVarint(buffer, packetEnd, &offset, &varint);
    if(!decodeSuccess) {
        syslog(LOG_INFO, "SUBSCRIBE Failed decoding varint");
        return;
    }

    // parse actual properties here if needed
    offset += varint;

    if (offset + 3 > packetEnd) { // 2 bytes topic + 1 byte options
        syslog(LOG_ERR, "SUBSCRIBE topic section too short");
        return;
    }

    uint16_t topicLength = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (offset + topicLength + 1 > packetEnd) {
        syslog(LOG_ERR, "SUBSCRIBE topic filter length exceeds packet size");
        return;
    }

    char topic[256];
    uint16_t safeLength = topicLength < 255 ? topicLength : 255;
    memcpy(topic, &buffer[offset], safeLength);
    topic[safeLength] = '\0';
    offset += topicLength;

    uint8_t options = buffer[offset++];
    uint8_t qos = options & 0b11;

    syslog(LOG_INFO, "Successfully read SUBSCRIBE request with topic: %s and QoS %d", topic, qos);
    return;
}

void generateFakeMatchingTopic(char* sub, size_t length) {
    const char* fakeFolder = "confidential";
    const char* fakeLeaf = "data";
    char buffer[256] = {0};
    size_t bufOffset = 0;

    const char* p = sub;
    while (*p && bufOffset < sizeof(buffer) - 1) {
        if (*p == '+') {
            bufOffset += snprintf(buffer + bufOffset, sizeof(buffer) - bufOffset, "%s", fakeFolder);
            p++;  // skip '+'
        } else if (*p == '#') {
            // '#' must be last, fill with a multi-level tail
            bufOffset += snprintf(buffer + bufOffset, sizeof(buffer) - bufOffset, "%s/%s", fakeFolder, fakeLeaf);
            break; // '#' ends the pattern
        } else {
            buffer[bufOffset++] = *p++;
        }
    }

    buffer[bufOffset] = '\0';
    strncpy(sub, buffer, length);
}

bool sendConnack(struct mqttClient* client, uint8_t reasonCode) {
    uint8_t arr[8] = {0};
    arr[0] = 0x20;       // CONNACK fixed header
    arr[1] = 0x06;       // Remaining Length
    arr[2] = 0x00;       // Connect Acknowledge Flags (Session Present = 0)
    arr[3] = reasonCode; // Reason Code
    arr[4] = 0x03;       // Properties Length
    arr[5] = 0x21;       // Property ID: Receive Maximum
    arr[6] = 0x00;       // MSB
    arr[7] = 0x01;       // LSB (Receive Maximum = 1)

    ssize_t w = write(client->fd, arr, 8);
    if (w == -1) {
        syslog(LOG_ERR, "sendConnack: write failed. May retry.");
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return false;
        }
    } else {
        syslog(LOG_INFO, "Sent CONNACK to client fd=%d\n", client->fd);
    }

    return true;
}

void readPublish(uint8_t* buffer, uint32_t packetEnd, uint32_t offset) {
    if (offset + 2 > packetEnd) {
        syslog(LOG_ERR, "PUBLISH packet too short for topic length");
        return;
    }

    uint16_t topicLen = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (offset + topicLen > packetEnd) {
        syslog(LOG_ERR, "PUBLISH topic exceeds packet bounds");
        return;
    }

    char topic[256] = {0};
    memcpy(topic, &buffer[offset], topicLen < 255 ? topicLen : 255);
    offset += topicLen;

    uint8_t qos = (buffer[0] & 0b00000110) >> 1;
    if (qos > 0) {
        if (offset + 2 > packetEnd) return;
        offset += 2; // packet id (don't care)
    }

    uint32_t varint;
    bool decodeSuccess = decodeVarint(buffer, packetEnd, &offset, &varint);
    if(!decodeSuccess) {
        return;
    }

    // Skip properties
    offset += varint;

    // Remaining is payload
    if (offset >= packetEnd) return;

    uint32_t payloadLen = packetEnd - offset;
    char payload[512] = {0};
    memcpy(payload, &buffer[offset], payloadLen < 511 ? payloadLen : 511);

    syslog(LOG_INFO, "PUBLISH received. Topic: %s, Payload: %s, QoS: %d", topic, payload, qos);
}

void readUnsubscribe(uint8_t* buffer, uint32_t packetEnd, uint32_t offset) {
    if (offset + 2 > packetEnd) {
        syslog(LOG_ERR, "UNSUBSCRIBE packet too short");
        return;
    }

    uint16_t packetId = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    uint32_t varint;
    bool decodeSuccess = decodeVarint(buffer, packetEnd, &offset, &varint);
    if(!decodeSuccess) {
        return;
    }

    // Skip properties
    offset += varint;

    while (offset + 2 <= packetEnd) {
        uint16_t topicLen = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        if (offset + topicLen > packetEnd) return;

        char topic[256] = {0};
        memcpy(topic, &buffer[offset], topicLen < 255 ? topicLen : 255);
        offset += topicLen;

        syslog(LOG_INFO, "UNSUBSCRIBE received for topic: %s (Packet ID: %u)", topic, packetId);
    }
}

bool sendPublish(struct mqttClient* client, const char* topic, const char* message) {
    uint16_t topicLength = strlen(topic);
    uint16_t payloadLength = strlen(message);
    uint8_t propertiesLength = 0; // No props

    size_t remainingLength = 2 + topicLength + 2; // length prefix + Topic + Packet ID (QoS2)
    remainingLength += 1 + propertiesLength; // Must add properties
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
    if (!packet) {
        syslog(LOG_ERR, "Out of memory for publish packet");
        return false;
    }

    size_t offset = 0;
    memcpy(packet, fixedHeader, fixedHeaderLength);
    offset += fixedHeaderLength;

    // Big endian topic
    packet[offset++] = topicLength >> 8;
    packet[offset++] = topicLength & 0xFF;
    memcpy(packet + offset, topic, topicLength);
    offset += topicLength;

    // Big endian packetId
    static uint16_t packetId = 1234;
    packet[offset++] = packetId >> 8;
    packet[offset++] = packetId & 0xFF;

    packet[offset++] = propertiesLength;

    memcpy(packet + offset, message, payloadLength);
    offset += payloadLength;

    ssize_t w = write(client->fd, packet, packetLength);
    free(packet);
    if (w < 0) {
        syslog(LOG_ERR, "sendPublish: write failed. May retry.");
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return false;
        }
    } else {
        syslog(LOG_INFO, "Sent PUBLISH to client (fd=%d), topic=%s\n", client->fd, topic);
    }
    
    return true;
}

void readPubrec(uint8_t* buffer, uint32_t packetEnd, uint32_t offset, struct mqttClient* client) {
    syslog(LOG_INFO, "Received PUBREC for fd=%d", client->fd);
    if (offset + 2 > packetEnd) {
        syslog(LOG_ERR, "PUBREC packet too short for Packet Identifier\n");
        return;
    }

    uint16_t packetId = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    // syslog(LOG_INFO, "PUBREC Packet ID: %u\n", packetId);

    if (offset >= packetEnd) {
        return;
    }
    uint8_t reasonCode = buffer[offset++];

    if (offset >= packetEnd) {
        return;
    }

    uint32_t varint;
    bool decodeSuccess = decodeVarint(buffer, packetEnd, &offset, &varint);
    if(!decodeSuccess) {
        return;
    }

    if (offset + varint > packetEnd) {
        return;
    }

    uint32_t propsEnd = offset + varint;
    while (offset < propsEnd && offset < packetEnd) {
        uint8_t propId = buffer[offset++];
        switch (propId) {
            case 0x1F: {  // Reason String
                if (offset + 2 > propsEnd) {
                    syslog(LOG_ERR, "Malformed Reason String in PUBREC");
                    return;
                }
                uint16_t strLen = (buffer[offset] << 8) | buffer[offset + 1];
                offset += 2;
                if (offset + strLen > propsEnd) {
                    syslog(LOG_ERR, "Truncated Reason String in PUBREC");
                    return;
                }
                char reasonStr[256] = {0};
                uint16_t copyLen = strLen < 255 ? strLen : 255;
                memcpy(reasonStr, &buffer[offset], copyLen);
                offset += strLen;
                syslog(LOG_INFO, "Reason String: %s", reasonStr);
                break;
            }

            case 0x26: {  // User Property (key-value pair)
                // Read key
                if (offset + 2 > propsEnd) return;
                uint16_t keyLen = (buffer[offset] << 8) | buffer[offset + 1];
                offset += 2;
                if (offset + keyLen > propsEnd) return;

                char key[128] = {0};
                memcpy(key, &buffer[offset], keyLen < 127 ? keyLen : 127);
                offset += keyLen;

                // Read value
                if (offset + 2 > propsEnd) return;
                uint16_t valLen = (buffer[offset] << 8) | buffer[offset + 1];
                offset += 2;
                if (offset + valLen > propsEnd) return;

                char val[128] = {0};
                memcpy(val, &buffer[offset], valLen < 127 ? valLen : 127);
                offset += valLen;

                syslog(LOG_INFO, "User Property: %s = %s", key, val);
                break;
            }
            default:
                syslog(LOG_WARNING, "Unknown property ID in PUBREC: 0x%02X", propId);
                return;
        }
    }

    syslog(LOG_INFO, "PUBREC packet ID: %d, Reason Code: 0x%02X\n", packetId, reasonCode);
}

bool sendPubrel(struct mqttClient* client, uint16_t packetId) {
    uint8_t fixedHeader[6];
    size_t offset = 0;

    fixedHeader[offset++] = 0b01100010;         // Fixed header
    fixedHeader[offset++] = 0x04;               // Remaining Length
    fixedHeader[offset++] = packetId >> 8;      // packetId
    fixedHeader[offset++] = packetId & 0xFF;

    fixedHeader[offset++] = 0x00;               // Reason Code: Success
    fixedHeader[offset++] = 0x00;               // Property Length

    ssize_t w = write(client->fd, fixedHeader, offset);
    if (w == -1) {
        syslog(LOG_ERR, "sendPubrel: write failed");
        return false;
    }

    syslog(LOG_INFO, "Sent PUBREL to client fd=%d", client->fd);
    return true;
}

void readPubcomp(uint8_t* buffer, uint32_t packetEnd, uint32_t offset, struct mqttClient* client) {
    // syslog(LOG_INFO, "Received PUBCOMP");
    if (offset + 2 > packetEnd) {
        syslog(LOG_ERR, "PUBCOMP packet too short for Packet Identifier");
        return;
    }

    // Extract Packet Identifier
    uint16_t packetId = (buffer[offset] << 8) | buffer[offset + 1];
    syslog(LOG_INFO, "PUBCOMP Packet ID: %u from client fd=%d", packetId, client->fd);
}

bool sendPingresp(struct mqttClient* client) {
    uint8_t packet[2] = { 0xD0, 0x00 };
    ssize_t w = write(client->fd, packet, sizeof(packet));

    if (w == -1) {
        syslog(LOG_ERR, "sendPingresp: write failed. May retry.");
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return false;
        }
    } else {
        syslog(LOG_INFO, "Sent PINGRESP to client (fd=%d)\n", client->fd);
    }
    return true;
}

void disconnectClient(struct mqttClient* client, int epollFd, long long now){
    long long wastedTime = now - client->timeOfConnection;
    statsMqtt.totalWastedTime += wastedTime;
    syslog(LOG_INFO, "Client removed with IP: %s with fd: %d with connected time %lld ms", 
        client->ipaddr, client->fd, wastedTime);
    epoll_ctl(epollFd, EPOLL_CTL_DEL, client->fd, NULL);
    deleteClient(client);
    close(client->fd);
    free(client);
}

enum Request determineRequest(uint8_t firstByte) {
    switch (firstByte >> 4)
    {
    case 0b0001:
        return CONNECT;
    case 0b0101:
        return PUBREC;
    case 0b1000:
        return SUBSCRIBE;
    case 0b1100:
        return PING;
    case 0b1110:
        return DISCONNECT;
    case 0b0011:
        return PUBLISH;
    case 0b1010:
        return UNSUBSCRIBE;
    case 0b0111:
        return PUBCOMP;
    default:
        syslog(LOG_ERR, "Unknown request %d", firstByte >> 4);
        return UNSUPPORTED_REQUEST;
    }
}

void calculateTotalPacketLengths(uint8_t *buffer, uint32_t bytesWrittenToBuffer,
                                 uint32_t *packetLengths, uint32_t *packetStarts,
                                 uint32_t *packetCount) {
    *packetCount = 0;
    uint32_t offset = 0;

    while (offset < bytesWrittenToBuffer) {
        if (bytesWrittenToBuffer - offset < 2) {
            syslog(LOG_INFO, "CALCULATE: Not enough data for fixed header");
            break; 
        }

        if (*packetCount == MAX_PACKETS_PER_CLIENTS) {
            syslog(LOG_INFO, "CALCULATE: Max count reached");
            break;
        }

        uint32_t remainingLength = 0;
        uint32_t multiplier = 1;
        uint32_t encodedBytes = 0;

        // varint
        for (int i = 0; i < 4; i++) {
            if (offset + 1 + i >= bytesWrittenToBuffer) {
                syslog(LOG_INFO, "CALCULATE: Not enough data to finish varint");
                return;
            }
            uint8_t byte = buffer[offset + 1 + i];
            remainingLength += (byte & 0b01111111) * multiplier;
            multiplier *= 128;
            encodedBytes++;

            if ((byte & 0b10000000) == 0) {
                break; 
            }
        }

        // Fixed header + variable header
        uint32_t headerLengths = 1 + encodedBytes;
        uint32_t totalPacketLength = headerLengths + remainingLength;

        if (bytesWrittenToBuffer - offset >= totalPacketLength) {
            packetLengths[*packetCount] = totalPacketLength;
            packetStarts[*packetCount] = offset + headerLengths;
            // syslog(LOG_INFO, "Packet %u: total length = %u, variable header offset = %u",
            //     *packetCount, totalPacketLength, packetStarts[*packetCount]);
            (*packetCount)++;
            offset += totalPacketLength;
        } else {
            syslog(LOG_ERR, "Incomplete packet at offset %u: expected length = %u, available = %u",
                offset, totalPacketLength, bytesWrittenToBuffer - offset);
            break;  // Incomplete packet
        }
    }
}

void cleanupBuffer(struct mqttClient* client, uint32_t packetLength){
    int leftover = client->bytesWrittenToBuffer - packetLength;
    memmove(client->buffer, client->buffer + packetLength, leftover);
    client->bytesWrittenToBuffer = leftover;
}

int main() {
    openlog("mqtt_tarpit", LOG_PID | LOG_CONS, LOG_USER);
    initializeStats();
    setFdLimit(FD_LIMIT);
    signal(SIGPIPE, SIG_IGN);
    
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

    long long lastHeartbeat = currentTimeMs();
    while(true) {
        long long now = currentTimeMs();

        if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
            heartbeatLog();
            lastHeartbeat = now;
        }

        int nfds = epoll_wait(epollfd, eventsQueue, MAX_EVENTS, EPOLL_TIMEOUT_INTERVAL_MS);
        if (nfds == -1) {
            syslog(LOG_ERR, "epoll_wait");
            exit(EXIT_FAILURE);
        }

        // Update now, since epoll_wait made the value outdated. 
        now = currentTimeMs();
        for (int n = 0; n < nfds; ++n) {
            int currentFd = eventsQueue[n].data.fd;
            if (currentFd == serverSock) {
                int clientFd = accept(serverSock, (struct sockaddr *) &clientAddr, &addrLen);
                if (clientFd == -1) {
                    syslog(LOG_ERR, "Failed accepting new client with error %s", strerror(errno));
                    continue;
                }
                struct mqttClient* newClient = malloc(sizeof(struct mqttClient));
                if (newClient == NULL) {
                    syslog(LOG_ERR, "Out of memory");
                    close(clientFd);
                    continue;
                }

                
                statsMqtt.totalConnects += 1;
                newClient->fd = clientFd;
                strncpy(newClient->ipaddr, inet_ntoa(clientAddr.sin_addr), INET6_ADDRSTRLEN);
                newClient->bytesWrittenToBuffer = 0;
                newClient->lastActivityMs = now;
                newClient->timeOfConnection = now;
                newClient->lastPubrelMs = now;
                newClient->keepAlive = 0; // Initial value. Will be updated after connect
                memset(newClient->buffer, 0, sizeof(newClient->buffer)); // Maybe not necessary
                // ev.events = EPOLLIN | EPOLLET;
                // ev.data.fd = clientFd;
                fcntl(clientFd, F_SETFL, O_NONBLOCK);
                struct epoll_event clientEv;
                clientEv.events = EPOLLIN;
                clientEv.data.fd = clientFd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, clientFd, &clientEv) == -1) {
                    syslog(LOG_ERR, "Failed adding client to epoll with error %s", strerror(errno));
                    close(clientFd);
                    free(newClient);
                    continue;
                }
                
                addClient(newClient);
                if(statsMqtt.mostConcurrentConnections < HASH_COUNT(clients)) {
                    statsMqtt.mostConcurrentConnections = HASH_COUNT(clients);
                }
            } else {
                struct mqttClient* client = lookupClient(currentFd);
                ssize_t bytesRead = read(currentFd,
                          client->buffer + client->bytesWrittenToBuffer, // Avoid overwriting existing data
                          sizeof(client->buffer) - client->bytesWrittenToBuffer);

                if(bytesRead <= 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    }
                    syslog(LOG_ERR, "Failed reading. Disconnecting client. error: %s", strerror(errno));
                    disconnectClient(client, epollfd, now);
                    continue;
                }

                client->bytesWrittenToBuffer += bytesRead;

                if (client->bytesWrittenToBuffer >= sizeof(client->buffer)) {
                    syslog(LOG_ERR, "Buffer full. Disconnecting client.");
                    disconnectClient(client, epollfd, now);
                    continue;
                }

                uint32_t packetLengths[MAX_PACKETS_PER_CLIENTS]; // Length of each packet
                uint32_t packetStarts[MAX_PACKETS_PER_CLIENTS]; // Points to the start of each packet, after the header values
                uint32_t packetCount = 0;

                calculateTotalPacketLengths(client->buffer, client->bytesWrittenToBuffer,
                            packetLengths, packetStarts, &packetCount);
                
                uint32_t processedPackets = 0;
                for (uint32_t i = 0; i < packetCount; i++) {
                    uint32_t packetLength = packetLengths[i];
                    uint32_t packetStart = packetStarts[i];
                    uint32_t packetEnd = packetStart + packetLength;
                    
                    if (packetLength == 0 || processedPackets + packetLength > client->bytesWrittenToBuffer) {
                        syslog(LOG_INFO, "Incomplete packet");
                        break; // Incomplete packet
                    }

                    client->lastActivityMs = now;
                    enum Request request = determineRequest(client->buffer[processedPackets]);

                    switch (request) {
                        case CONNECT:
                            uint8_t reasonCodeConn = readConnreq(client->buffer, packetEnd, packetStart, client);
                            bool ackSuccess = sendConnack(client, reasonCodeConn);
                            if(!ackSuccess) {
                                syslog(LOG_INFO, "Disconnecting client due to CONNACK failure");
                                disconnectClient(client, epollfd, now);
                                break;
                            }
                            break;
                        case SUBSCRIBE:
                            readSubscribe(client->buffer, packetEnd, packetStart);
                            break;
                        case PUBREC:
                            readPubrec(client->buffer, packetEnd, packetStart, client);
                            break;
                        case PUBLISH:
                            readPublish(client->buffer, packetEnd, packetStart);
                            break;
                        case PUBCOMP:
                            readPubcomp(client->buffer, packetEnd, packetStart, client);
                            bool pubSuccess = sendPublish(client, "$SYS/credentials", "username=admin123 password=admin321");
                            if(!pubSuccess) {
                                syslog(LOG_INFO, "Disconnecting client due to publish failure");
                                disconnectClient(client, epollfd, now);
                            }
                            break;
                        case UNSUBSCRIBE:
                            readUnsubscribe(client->buffer, packetEnd, packetStart);
                            break;
                        case PING:
                            bool pingSuccess = sendPingresp(client);
                            if(!pingSuccess){
                                syslog(LOG_INFO, "Disconnecting client due to ping failure");
                                disconnectClient(client, epollfd, now);
                                break;
                            }
                            break;
                        case DISCONNECT:
                            syslog(LOG_INFO, "Disconnecting client due to receiving DISCONNECT");
                            disconnectClient(client, epollfd, now);
                            break;
                        default:
                            break;
                    }
                    processedPackets += packetLength;
                }
                uint32_t leftover = client->bytesWrittenToBuffer - processedPackets;
                if (leftover > 0) {
                    memmove(client->buffer, client->buffer + processedPackets, leftover);
                }
                client->bytesWrittenToBuffer = leftover;
            }
            
        }
        
        // Detect dead clients and disconnect them
        for (struct mqttClient *c = clients, *tmp = NULL; c != NULL; c = tmp) {
            long long timeSinceLastActivityMs = now - c->lastActivityMs;
            tmp = c->hh.next;
            if ((now - c->lastPubrelMs > PUBREL_INTERVAL_MS) || (timeSinceLastActivityMs > c->keepAlive * 1400)) {
                bool success = sendPubrel(c, 1234);
                c->lastActivityMs = now;
                c->lastPubrelMs = now;

                if(!success) {
                    syslog(LOG_INFO, "Disconnecting client due to inactivity");
                    disconnectClient(c, epollfd, now);
                    continue;
                }
            }
        }
    }

    closelog();
    close(serverSock);
    return 0;
}