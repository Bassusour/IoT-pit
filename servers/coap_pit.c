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

// CoAP constants
// #define COAP_TYPE_CON 0x00
// #define COAP_TYPE_NON 0x10
// #define COAP_CODE_GET 0x01
#define CLASS_REQUEST 0x0
#define DETAIL_GET 0x1
#define DETAIL_POST 0x2
#define DETAIL_PUT 0x3
#define DETAIL_DELETE 0x4
#define TYPE_CONFIRMABLE 0x0
#define TYPE_NON_CONFIRMABLE 0x1
#define TYPE_ACK 0x2
#define TYPE_RST 0x3
#define CODE_CONTENT 0x45 // 2.05 in CoAP (binary: 010 0001 = 0x45)
#define MAX_BUF_LEN 1024
#define SERVER_ID "CoAP"

int port = 5683;
int timeout = -1;
int delay = 5000;
int numberOfAllowedUnacknowledgedCons = 3;

void build_coap_block_response(char *response, int *resp_len, uint16_t msg_id, uint8_t token, int block_num) {
    // Version (1) | Type (CON) | TKL (1)
    response[0] = (0b01 << 6) | (0b0 << 4) | 0b1;
    // class (2) | detail (5). Content response
    response[1] = (0b010 << 5) | (0b101);
    // TODO: Make random. Just increment from an initial value. 
    response[2] = (msg_id >> 8) & 0xFF;
    response[3] = msg_id & 0xFF;

    // Token (1 byte)
    response[4] = token;

    int opt_index = 5;

    // TODO: Make it so block_num can't exceed 20 bits (1048575)
    // Block2 Option (delta = 23, length = 1)
    // NUM(20 bits) | (M=1) | SZX=2(64 bytes)
    uint32_t block_opt_value = (block_num << 4) | (0b1 << 3) | 0x02;

    uint8_t block_len = (block_opt_value <= 0xFF) ? 1 :
                        (block_opt_value <= 0xFFFF) ? 2 : 3;

    // Option Delta 13 | Length = 1
    response[opt_index++] = (0b1101 << 4) | block_len;
    response[opt_index++] = block_opt_value;

    // Payload marker
    response[opt_index++] = 0xFF;

    // Payload
    for (int i = 0; i < 100; i++) {
        response[opt_index + i] = 'A';
    }

    *resp_len = opt_index + 100;
}

int main(int argc, char* argv[]) {
    int sockFd;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);

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
                    if(c->numberOfUnacknowledgedCons <= numberOfAllowedUnacknowledgedCons) {
                        c->base.sendNext = now + delay;
                        c->base.timeConnected += delay;
                        statsTelnet.totalWastedTime += delay;
                        queue_append(&clientQueueCoap, (struct baseClient *)c);
                    } else {
                        // Disconnect client
                    }

                }

                // Write a block
                // int out = build_coap_block_response()
                
                int out = 1;
                
                if (out == -1) {
                    long long timeTrapped = c->timeConnected;
                    char msg[256];
                    snprintf(msg, sizeof(msg), "%s disconnect %s  %lld\n",
                        SERVER_ID, c->ipaddr, timeTrapped);
                    printf("%s", msg);
                    sendMetric(msg);
                    close(c->fd);
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

            if (class == CLASS_REQUEST && detail == DETAIL_GET) {
                // TODO: If a CON (Confirmable) request, first send seperate CON response. 
                // The response does not need to be confirmable. (5.2.2 and 5.2.3)
                // Wait just before the backoff time (maybe). 

                printf("GET request from %s\n", inet_ntoa(clientAddr.sin_addr));
                struct client* newClient = malloc(sizeof(struct client));
                if (!newClient) {
                    fprintf(stderr, "Out of memory");
                    continue;
                }

                newClient->sendNext = now + delay;
                newClient->timeConnected = 0;
                snprintf(newClient->ipaddr, INET_ADDRSTRLEN, "%s", inet_ntoa(clientAddr.sin_addr));
                queue_append(&clientQueueCoap, (struct baseClient*)newClient);
    
                char msg[256];
                snprintf(msg, sizeof(msg), "%s connect %s\n",
                    SERVER_ID, newClient->ipaddr);
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