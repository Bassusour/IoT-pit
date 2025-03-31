#ifndef STRUCTS_H
#define STRUCTS_H

#include <netinet/in.h>
#include "uthash.h"

enum State { CONNECT, CONNACK, PUBLISH, PUBREC, PUBREL, PING, SUBSCRIBE, DISCONNECT, UNSUPPORTED_REQUEST };
enum MqttVersion { V5, V311 };

struct client {
    int fd;
    long long sendNext;
    struct client *next;
    long long timeConnected;
    char ipaddr[INET6_ADDRSTRLEN];
    int port;
};

struct mqttClient {
    int fd;
    long long timeConnected;
    char ipaddr[INET6_ADDRSTRLEN];
    int port;
    uint8_t buffer[1024];
    int bytesWrittenToBuffer;
    enum MqttVersion version;
    enum State state;
    UT_hash_handle hh;
};

struct queue {
    struct client *head;
    struct client *tail;
    int length;
};

extern struct queue clientQueueTelnet;
extern struct queue clientQueueUpnp;

struct telnetStatistics {
    unsigned long totalConnects;
    unsigned long long totalWastedTime;
};

struct upnpStatistics {
    unsigned long totalConnects;
    unsigned long long totalWastedTime;
    unsigned long otherRequests;
    unsigned long ssdpResponses;
};

extern struct telnetStatistics statsTelnet;
extern struct upnpStatistics statsUpnp;

/**
 * @brief Initializes a queue.
 * @param q Pointer to the queue to initialize.
 */
void queue_init(struct queue *q);

/**
 * @brief Appends a client to the queue.
 * @param q Pointer to the queue.
 * @param c Pointer to the client to append.
 */
void queue_append(struct queue *q, struct client *c);

/**
 * @brief Removes and returns the first client from the queue.
 * @param q Pointer to the queue.
 * @return Pointer to the removed client or NULL if the queue is empty.
 */
struct client *queue_pop(struct queue *q);

/**
 * @brief Creates a standard TCP server with very large backlog
 * @param port What port the server should be assigned
 * @return File descriptor for the server
 */
int createServer(int port);

/**
 * @return Returns the current time in milliseconds
 */
long long currentTimeMs();

#endif