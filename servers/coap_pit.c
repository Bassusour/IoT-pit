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
#include <time.h>
#include "../shared/structs.h"

#define CLASS_REQUEST 0x0
#define DETAIL_GET 0x1
#define DETAIL_POST 0x2
#define DETAIL_PUT 0x3
#define DETAIL_DELETE 0x4
#define TYPE_CONFIRMABLE 0x0
#define TYPE_NON_CONFIRMABLE 0x1
#define TYPE_ACK 0x2
#define TYPE_RST 0x3
#define MAX_BUF_LEN 1024
#define SERVER_ID "CoAP"

int port = 5683;
int timeout = -1;
int delay = 1000;
int ACK_TIMEOUT = 2000;
int sockFd;

int buildCoapBlockResponse(uint16_t messageId, uint8_t* token, uint8_t tkl, int blockNumber, struct sockaddr_in addr, socklen_t addrLen) {
    // TODO: Make it so block_num can't exceed 20 bits (1048575)
    // Block2 Option (delta = 23, length = 1)
    // NUM(20 bits) | (M=1) | SZX=2(64 bytes)
    uint32_t block_opt_value = (blockNumber << 4) | (0b1 << 3) | 0x02;
    uint8_t block_len = (block_opt_value <= 0xFF) ? 1 :
                        (block_opt_value <= 0xFFFF) ? 2 : 3;
    
    int payloadLength = 32;
    int responseLength = 4 + tkl + block_len + payloadLength;
    char response[responseLength];
    
    // Version (1) | Type (CON) | TKL (1)
    response[0] = (0b01 << 6) | (0b0 << 4) | 0b1;
    // class (2) | detail (5). Content response
    response[1] = (0b010 << 5) | (0b101);
    response[2] = (messageId >> 8) & 0xFF;
    response[3] = messageId & 0xFF;

    int index = 4;

    // Token
    for (int i = 0; i < tkl; i++) {
        response[index++] = token[i];
    }

    // Option Delta 13 | Length = 1
    response[index++] = (0b1101 << 4) | block_len;
    if (block_len == 1) {
        response[++index] = block_opt_value & 0xFF;
    } else if (block_len == 2) {
        response[++index] = (block_opt_value >> 8) & 0xFF;
        response[++index] = block_opt_value & 0xFF;
    } else {
        response[++index] = (block_opt_value >> 16) & 0xFF;
        response[++index] = (block_opt_value >> 8) & 0xFF;
        response[++index] = block_opt_value & 0xFF;
    }

    // Payload marker
    response[index++] = 0xFF;

    // Payload
    for (int i = 0; i < payloadLength; i++) {
        response[index + i] = 'A';
    }

    return sendto(sockFd, response, responseLength, 0, (struct sockaddr *)&addr, addrLen);
}

int main(int argc, char* argv[]) {
    struct sockaddr_in serverAddr;

    if ((sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "SSDP Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind to all interfaces and ports
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    // Join the multicast group
    // struct ip_mreq mreq;
    // mreq.imr_multiaddr.s_addr = inet_addr("224.0.1.187");
    // mreq.imr_interface.s_addr = INADDR_ANY;
    // setsockopt(sockFd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    if (bind(sockFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Bind failed");
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    printf("CoAP listener started on port %d\n", port);

    struct pollfd pollFd;
    memset(&pollFd, 0, sizeof(pollFd));
    pollFd.fd = sockFd;
    pollFd.events = POLLIN;

    while (1) {
        int now = currentTimeMs();

        while (clientQueueCoap.head) {
            if(clientQueueCoap.head->sendNext <= now){
                struct baseClient *bc = queue_pop(&clientQueueCoap);
                struct coapClient *c = (struct coapClient *)bc;

                // TODO: Check if received confirmable from last message
                // If not, skip (re-add to queue). 
                // If after x amount of tries/x amount of time, consider the client disconnected
                if(!c->receivedAck) {
                    if(c->retransmits < 5) {
                        c->base.sendNext = now + (ACK_TIMEOUT << (c->retransmits));;
                        c->retransmits += 1;
                        c->base.timeConnected += delay;
                        buildCoapBlockResponse(c->messageId, c->token, c->tkl, c->blockNumber, c->clientAddr, c->addrLen);
                        queue_append(&clientQueueCoap, (struct baseClient *)c);
                    } else {
                        // Disconnect client
                    }
                }

                uint16_t messageId = 1234; // TODO: automatically generate
                c->messageId = messageId;

                // Write a block
                int out = buildCoapBlockResponse(messageId, c->token, c->tkl, c->blockNumber, c->clientAddr, c->addrLen);
                
                if (out == -1) {
                    long long timeTrapped = c->base.timeConnected;
                    char msg[256];
                    snprintf(msg, sizeof(msg), "%s disconnect %s  %lld\n",
                        SERVER_ID, c->base.ipaddr, timeTrapped);
                    printf("%s", msg);
                    sendMetric(msg);
                    free(c);
                } else {
                    c->base.sendNext = now + delay;
                    c->base.timeConnected += delay;
                    queue_append(&clientQueueCoap, (struct baseClient *)c);
                }
            } else {
                timeout = clientQueueCoap.head->sendNext - now;
                break;
            }
        }

        int pollResult = poll(&pollFd, 1, timeout);
        now = currentTimeMs();
        if (pollResult < 0) {
            fprintf(stderr, "Poll error with error %s", strerror(errno));
            continue;
        }

        if (pollFd.revents & POLLIN) {
            struct sockaddr_in clientAddr;
            socklen_t addrLen = sizeof(clientAddr);
            char buffer[1024];

            int len = recvfrom(sockFd, buffer, MAX_BUF_LEN, 0, (struct sockaddr *)&clientAddr, &addrLen);
            if(len < 4) {
                // Too short or something went wrong
                continue;
            }

            uint8_t version = (buffer[0] >> 6) & 0b11;
            uint8_t type = (buffer[0] >> 4) & 0b11;
            uint8_t code = buffer[1];
            uint8_t class = (code >> 5) & 0b111;
            uint8_t detail = code & 0b11111;
            uint8_t tkl = buffer[0] & 0b1111;
            uint16_t msgId = (buffer[2] << 8) | buffer[3];
            uint8_t token[8] = {0};

            if (tkl > 8 || len < 4 + tkl) {
                // Malformed request. Send 4.00 Bad Request
                uint8_t response[4];
                uint8_t resp_type = (type == TYPE_CONFIRMABLE) ? TYPE_ACK : TYPE_NON_CONFIRMABLE;
            
                response[0] = (0b01 << 6) | (resp_type << 4) | 0; // Ver=1, Type=ACK/NON, TKL=0
                response[1] = (0b100 << 5) | 0b0;                 // Code 4.00 (Bad Request)
                response[2] = msgId >> 8;
                response[3] = msgId & 0b11111111;
                int resp_len = 4;

                sendto(sockFd, response, resp_len, 0, (struct sockaddr *)&clientAddr, addrLen);
                continue;
            } 
            else if (version != 1){
                // Must be silently ignored
                continue;
            } else if (tkl > 0) {
                memcpy(token, &buffer[4], tkl);
            }

            // TODO: Ignore extended methods (send "method not allowed" response)
            // TODO: Handle requests while the client is still receiving blocks. 

            if (class == CLASS_REQUEST && detail == DETAIL_GET) {
                // TODO: If a CON (Confirmable) request, first send seperate CON response. 
                // The response does not need to be confirmable. (5.2.2 and 5.2.3)
                // Wait just before the backoff time (maybe). 

                printf("GET request from %s\n", inet_ntoa(clientAddr.sin_addr));
                struct coapClient* newClient = malloc(sizeof(struct coapClient));
                if (!newClient) {
                    fprintf(stderr, "Out of memory");
                    continue;
                }

                newClient->base.sendNext = now + delay;
                newClient->base.timeConnected = 0;
                newClient->blockNumber = 0;
                newClient->tkl = tkl;
                newClient->retransmits = 0;
                memcpy(newClient->token, token, 8);
                snprintf(newClient->base.ipaddr, INET_ADDRSTRLEN, "%s", inet_ntoa(clientAddr.sin_addr));
                queue_append(&clientQueueCoap, (struct baseClient*)newClient);
    
                char msg[256];
                snprintf(msg, sizeof(msg), "%s connect %s\n",
                    SERVER_ID, newClient->base.ipaddr);
                printf("%s", msg);
                sendMetric(msg);
            } else {
                // Logging
            }
        }
    }

    close(sockFd);
    return 0;
}