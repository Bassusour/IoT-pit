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
#define TIMEOUT_VALUE_MS 120000 // 120s
#define HEARTBEAT_INTERVAL_MS 600000 // 10 minutes

// void heartbeatLog() {
//     syslog(LOG_INFO, "Server is running with %d connected clients.", clientQueueUpnp.length);
//     syslog(LOG_INFO, "Current statistics: wasted time: %lld ms. Total connected clients: %ld. Total other requests: %ld", statsUpnp.totalWastedTime, statsUpnp.totalConnects, statsUpnp.otherRequests);
// }

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
    syslog(LOG_INFO, "Server is running with %d connected clients.", HASH_COUNT(clients));
}

uint8_t readConnreq(uint8_t* buffer, uint32_t length, uint32_t offset, struct mqttClient* client){
    syslog(LOG_INFO, "Reading CONNECT request");
    if (offset + 2 > length) {
        syslog(LOG_ERR, "CONNECT request too small for fixed header");
        return 0x80; // Unspecified error
    } 

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
        return 0x01; // Unacceptable protocol version
    }
    offset += 4;

    // Protocol Version
    if (offset >= length) {
        syslog(LOG_ERR, "No protocol version given for CONNECT request");
        return 0x80;
    }
    uint8_t proto_level = buffer[offset++];
    if(proto_level == 0b101) {
        syslog(LOG_INFO, "Client connected with v5");
        client->version = V5;
    // } else if (proto_level == 0b100) {
    //     syslog(LOG_INFO, "Client connected with v3.1.1");
    //     client->version = V311;
    } else {
        syslog(LOG_ERR, "Unsupported MQTT version: %d", proto_level);
        return 0x01; // Unacceptable protocol version
    }
    // printf("Protocol Level: %d\n", proto_level);

    // Connect Flags
    if (offset >= length) {
        syslog(LOG_ERR, "No connect flags supplied");
        return 0x80;
    }
    uint8_t connect_flags = buffer[offset++];
    // printf("Connect Flags: 0x%02X\n", connect_flags);

    // Keep Alive
    if (offset + 2 > length){
        syslog(LOG_ERR, "No keep-alive value supplied");
        return 0x80;
    } 
    int keepAlive = (buffer[offset] << 8) | buffer[offset + 1];
    if(keepAlive < 0) {
        syslog(LOG_ERR, "Negative keep-alive value received");
        return 0x80;
    }
    client->keepAlive = keepAlive;
    offset += 2;
    // printf("Keep Alive: %u seconds\n", client->keepAlive);

    // Properties Length (varint) (ONLY VERSION 5)
    if(client->version == V5) {
        uint32_t propsLength = 0;
        int multiplier = 1;
        uint8_t byte;
        do {
            if (offset >= length) {
                syslog(LOG_ERR, "Incomplete variable byte integer");
                return 0x80;
            }
            byte = buffer[offset++];
            propsLength += (byte & 127) * multiplier;
            multiplier *= 128;
        } while ((byte & 0b10000000) != 0);

        if (offset + propsLength > length) {
            syslog(LOG_ERR, "Malformed properties: exceeds packet bounds");
            return 0x80;
        }

        uint32_t props_end = offset + propsLength;
        while (offset < props_end && offset < length) {
            offset++; // Don't parse props, just skip
        }
    }

    // Payload: Client ID
    if (offset + 2 > length) return 0x80;
    uint16_t clientIdLength = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (offset + clientIdLength > length) {
        syslog(LOG_ERR, "clientId too long for packet");
        return 0x02;
    }
    offset += clientIdLength;

    // Username
    if (connect_flags & 0b10000000) {
        if (offset + 2 > length) {
            syslog(LOG_ERR, "Username flag supplied, but with no username");
            return 0x80;
        } 
        uint16_t user_len = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        if (offset + user_len > length) {
            syslog(LOG_ERR, "Username too long");
            return 0x80;
        }

        char username[256] = {0};
        uint16_t safeLength = user_len < 255 ? user_len : 255;
        memcpy(username, &buffer[offset], safeLength);
        offset += user_len;
        syslog(LOG_INFO, "Username: %s\n", username);
    }

    // Password
    if (connect_flags & 0b1000000) {
        if (offset + 2 > length) {
            syslog(LOG_ERR, "Password flag supplied, but with no password");
            return 0x80;
        } 
        uint16_t passwordLength = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        if (offset + passwordLength > length){
            syslog(LOG_ERR, "Password too long");
            return 0x80;
        }

        char password[256] = {0};
        uint16_t safeLength = passwordLength < 255 ? passwordLength : 255;
        memcpy(password, &buffer[offset], safeLength);
        offset += passwordLength;
        syslog(LOG_INFO, "Password: %s\n", password);
    }

    syslog(LOG_INFO, "Successfully read CONNECT request");
    return 0x00; // Success
}

void readSubscribe(uint8_t* buffer, uint32_t length, uint32_t offset, enum MqttVersion version) {
    syslog(LOG_INFO, "Reading SUBSCRIBE request");
    if (offset + 2 > length) {
        syslog(LOG_ERR, "SUBSCRIBE request too short for fixed header");
        return;
    }

    // *packetId = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2; // packetId

    if (version == V5) {
        uint32_t propsLength = 0;
        int multiplier = 1;
        int varintBytes = 0;
        uint8_t byte;

        do {
            if (offset >= length) {
                syslog(LOG_ERR, "Incomplete variable byte integer");
                return;
            }
            byte = buffer[offset++];
            propsLength += (byte & 0b01111111) * multiplier;
            multiplier *= 128;
            varintBytes++;
        } while ((byte & 0b10000000) != 0 && varintBytes <= 4);

        if (offset + propsLength > length) {
            syslog(LOG_ERR, "Malformed property section in SUBSCRIBE");
            return;
        }

        // parse actual properties here if needed
        offset += propsLength;
    } else if ( version != V5 && version != V311) {
        syslog(LOG_ERR, "Unknown MQTT version in SUBSCRIBE");
        return;
    }

    if (offset + 3 > length) { // 2 bytes topic + 1 byte options
        syslog(LOG_ERR, "SUBSCRIBE topic section too short");
        return;
    }

    uint16_t topicLength = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (offset + topicLength + 1 > length) {
        syslog(LOG_ERR, "SUBSCRIBE topic filter length exceeds packet size");
        return;
    }

    char topic[256];
    uint16_t safeLength = topicLength < 255 ? topicLength : 255;
    memcpy(topic, &buffer[offset], safeLength);
    topic[safeLength] = '\0';
    syslog(LOG_INFO, "SUBSCRIBE topic subscription: %s", topic);
    offset += topicLength;

    uint8_t options = buffer[offset++];
    uint8_t qos = options & 0b11;
    // if (qos < 2) {
    //     syslog(LOG_WARNING, "Client requested QoS (%d). Deny subscription", qos);
    //     return;
    // }

    syslog(LOG_INFO, "SUBSCRIBE topic subscription: %s with QoS %d", topic, qos);
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
    int size = client->version == V5 ? 8 : 4;
    uint8_t* arr = malloc(size);
    if (!arr) {
        syslog(LOG_ERR, "malloc failed for connack packet");
        return false;
    } 

    if (client->version == V5) {
        arr[0] = 0x20;       // CONNACK fixed header
        arr[1] = 0x06;       // Remaining Length
        arr[2] = 0x00;       // Connect Acknowledge Flags (Session Present = 0)
        arr[3] = reasonCode; // Reason Code
        arr[4] = 0x03;       // Properties Length
        arr[5] = 0x21;       // Property ID: Receive Maximum
        arr[6] = 0x00;       // MSB
        arr[7] = 0x01;       // LSB (Receive Maximum = 1)
    } else {
        arr[0] = 0x20;       // CONNACK fixed header
        arr[1] = 0x02;       // Remaining Length
        arr[2] = 0x00;       // Connect Acknowledge Flags (Session Present = 0)
        arr[3] = reasonCode; // Return Code
    }

    ssize_t w = write(client->fd, arr, size);
    if (w == -1) {
        syslog(LOG_ERR, "sendConnack: write failed. May retry.");
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return false;
        }
    } else {
        syslog(LOG_INFO, "Sent CONNACK to client %d\n", client->fd);
    }

    free(arr);
    return true;
}

void readPublish(uint8_t* buffer, uint32_t length, uint32_t offset, struct mqttClient* client) {
    if (offset + 2 > length) {
        syslog(LOG_ERR, "PUBLISH packet too short for topic length");
        return;
    }

    uint16_t topicLen = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (offset + topicLen > length) {
        syslog(LOG_ERR, "PUBLISH topic exceeds packet bounds");
        return;
    }

    char topic[256] = {0};
    memcpy(topic, &buffer[offset], topicLen < 255 ? topicLen : 255);
    offset += topicLen;

    uint8_t qos = (buffer[0] & 0b00000110) >> 1;
    if (qos > 0) {
        if (offset + 2 > length) return;
        offset += 2; // packet id (don't care)
    }

    if (client->version == V5) {
        uint32_t propLen = 0;
        int multiplier = 1;
        uint8_t byte;
        do {
            if (offset >= length) return;
            byte = buffer[offset++];
            propLen += (byte & 0b01111111) * multiplier;
            multiplier *= 128;
        } while ((byte & 0b10000000) != 0);
        // Skip properties
        offset += propLen;
    }

    // Remaining is payload
    if (offset >= length) return;

    uint32_t payloadLen = length - offset;
    char payload[512] = {0};
    memcpy(payload, &buffer[offset], payloadLen < 511 ? payloadLen : 511);

    syslog(LOG_INFO, "PUBLISH received. Topic: %s, Payload: %s, QoS: %d", topic, payload, qos);
}

void readUnsubscribe(uint8_t* buffer, uint32_t length, uint32_t offset, struct mqttClient* client) {
    if (offset + 2 > length) {
        syslog(LOG_ERR, "UNSUBSCRIBE packet too short");
        return;
    }

    uint16_t packetId = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (client->version == V5) {
        uint32_t propLen = 0;
        int multiplier = 1;
        uint8_t byte;
        do {
            if (offset >= length) return;
            byte = buffer[offset++];
            propLen += (byte & 0b01111111) * multiplier;
            multiplier *= 128;
        } while ((byte & 0b10000000) != 0);
        // Skip properties
        offset += propLen;
    }

    while (offset + 2 <= length) {
        uint16_t topicLen = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        if (offset + topicLen > length) return;

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
    // printf("\n");
    ssize_t w = write(client->fd, packet, packetLength);
    free(packet);
    if (w < 0) {
        syslog(LOG_ERR, "sendPublish: write failed. May retry."); // TODO
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return false;
        }
    } else {
        syslog(LOG_INFO, "Sent PUBLISH to client (fd=%d), topic=%s\n", client->fd, topic);
    }
    
    return true;
}

void readPubrec(uint8_t* buffer, uint32_t length, uint32_t offset, struct mqttClient* client) {
    syslog(LOG_INFO, "Received PUBREC");
    if (offset + 2 > length) {
        syslog(LOG_ERR, "PUBREC packet too short for Packet Identifier\n");
        return;
    }

    uint16_t packetId = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    syslog(LOG_INFO, "PUBREC Packet ID: %u\n", packetId);

    if (client->version == V5) {
        if (offset >= length) {
            return;
        }
        uint8_t reasonCode = buffer[offset++];
        syslog(LOG_INFO, "PUBREC Reason Code: 0x%02X\n", reasonCode);

        if (offset >= length) {
            return;
        }

        uint32_t propLength = 0;
        int multiplier = 1;
        int varint_bytes = 0;
        uint8_t byte;
        do {
            if (offset >= length) return;
            byte = buffer[offset++];
            propLength += (byte & 127) * multiplier;
            multiplier *= 128;
            varint_bytes++;
        } while ((byte & 128) != 0 && varint_bytes <= 4);

        if (offset + propLength > length) {
            return;
        }

        uint32_t propsEnd = offset + propLength;
        while (offset < propsEnd && offset < length) {
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
    }
}

// TODO: untested
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

    syslog(LOG_INFO, "Sent PUBREL to client %d", client->fd);
    return true;
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
    syslog(LOG_INFO, "Client removed with IP: %s:%d with fd: %d with connected time %lld ms", 
        client->ipaddr, client->port, client->fd, now - client->timeOfConnection);
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
    default:
        return UNSUPPORTED_REQUEST;
    }
}

void calculateTotalPacketLength(uint8_t *buffer, uint32_t bytesWrittenToBuffer, uint32_t* totalPacketLength, uint32_t* offset) {
    *totalPacketLength = 0;

    if (bytesWrittenToBuffer < 2) {
        return;  // Not enough for fixed header
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

        int nfds = epoll_wait(epollfd, eventsQueue, MAX_EVENTS, -1);
        if (nfds == -1) {
            syslog(LOG_ERR, "epoll_wait");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int currentFd = eventsQueue[n].data.fd;
            if (currentFd == serverSock) {
                int clientFd = accept(serverSock, (struct sockaddr *) &clientAddr, &addrLen);
                if (clientFd == -1) {
                    syslog(LOG_ERR, "error accepting client");
                    continue;
                }
                struct mqttClient* newClient = malloc(sizeof(struct mqttClient));
                newClient->fd = clientFd;
                strncpy(newClient->ipaddr, inet_ntoa(clientAddr.sin_addr), INET6_ADDRSTRLEN);
                newClient->port = ntohs(clientAddr.sin_port);
                newClient->bytesWrittenToBuffer = 0;
                newClient->lastActivityMs = now;
                newClient->timeOfConnection = now;
                newClient->keepAlive = 0; // Initial value. Will be updated after connect
                memset(newClient->buffer, 0, sizeof(newClient->buffer)); // Maybe not necessary
                // ev.events = EPOLLIN | EPOLLET;
                // ev.data.fd = clientFd;
                fcntl(clientFd, F_SETFL, O_NONBLOCK);
                struct epoll_event clientEv;
                clientEv.events = EPOLLIN;
                clientEv.data.fd = clientFd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, clientFd, &clientEv) == -1) {
                    syslog(LOG_ERR, "Failed adding client to epoll");
                    free(newClient);
                    continue;
                }

                addClient(newClient);
            } else {
                struct mqttClient* client = lookupClient(currentFd);
                ssize_t bytesRead = read(currentFd,
                          client->buffer + client->bytesWrittenToBuffer,
                          sizeof(client->buffer) - client->bytesWrittenToBuffer);

                if(bytesRead < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    }
                    syslog(LOG_ERR, "Failed reading. Disconnecting client.");
                    disconnectClient(client, epollfd, now);
                    continue;
                }

                client->bytesWrittenToBuffer += bytesRead;

                uint32_t totalPacketLength, variableHeaderOffset;
                calculateTotalPacketLength(client->buffer, client->bytesWrittenToBuffer, &totalPacketLength, &variableHeaderOffset);
                if (totalPacketLength == 0) {
                    continue;
                }
                client->lastActivityMs = now;
                enum Request request = determineRequest(client->buffer[0]);

                switch (request) {
                    case CONNECT:
                        uint8_t reasonCodeConn = readConnreq(client->buffer, totalPacketLength, variableHeaderOffset, client);
                        cleanupBuffer(client, totalPacketLength);
                        bool ackSuccess = sendConnack(client, reasonCodeConn);
                        if(!ackSuccess) {
                            disconnectClient(client, epollfd, now);
                            break;
                        }
                        bool pubSuccess = sendPublish(client, "$SYS/confidential", "username=admin password=admin");
                        if(!pubSuccess) {
                            disconnectClient(client, epollfd, now);
                        }
                        break;
                    case SUBSCRIBE:
                        readSubscribe(client->buffer, totalPacketLength, variableHeaderOffset, client->version);
                        cleanupBuffer(client, totalPacketLength);
                        break;
                    case PUBREC:
                        readPubrec(client->buffer, totalPacketLength, variableHeaderOffset, client);
                        cleanupBuffer(client, totalPacketLength);
                        break;
                    case PUBLISH:
                        readPublish(client->buffer, totalPacketLength, variableHeaderOffset, client);
                        cleanupBuffer(client, totalPacketLength);
                        break;
                    case UNSUBSCRIBE:
                        readUnsubscribe(client->buffer, totalPacketLength, variableHeaderOffset, client);
                        cleanupBuffer(client, totalPacketLength);
                        break;
                    case PING:
                        cleanupBuffer(client, totalPacketLength);
                        bool pingSuccess = sendPingresp(client);
                        if(!pingSuccess){
                            disconnectClient(client, epollfd, now);
                            break;
                        }
                        break;
                    case DISCONNECT:
                        disconnectClient(client, epollfd, now);
                        break;
                    default:
                        break;
                        // TODO: Keep PUBREC and PUBCOMP?
                        // TODO: Clean up version 311
                        // TODO: Test pubrel function
                        // TODO: Remove port from clients (no need to save that)
                }
            }
        }
        
        // Detect dead clients and disconnect them
        for (struct mqttClient *c = clients, *tmp = NULL; c != NULL; c = tmp) {
            long long timeSinceLastActivityMs = now - c->lastActivityMs;
            tmp = c->hh.next;
            if ((c->keepAlive != 0 && timeSinceLastActivityMs > c->keepAlive * 1400) || 
                (timeSinceLastActivityMs > TIMEOUT_VALUE_MS)) {
                bool success = sendPubrel(c, 1234);
                c->lastActivityMs = now;

                if(!success) {
                    disconnectClient(c, epollfd, now);
                    continue;
                }
                sendPublish(c, "$SYS/confidential", "username=admin123 password=admin321");
            }
        }
    }

    closelog();
    close(serverSock);
    return 0;
}