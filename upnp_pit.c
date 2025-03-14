#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include "structs.h"

#define SSDP_PORT 1900
#define HTTP_PORT 8080
#define DELAY_MS 100
#define SSDP_MULTICAST "239.255.255.250"
#define HEARTBEAT_INTERVAL_MS 600000 // 10 minutes
    
// Can use Chunked Transfer Coding from rfc 2616 section 3.6.1
// Required to be a HTTP GET request (Section 2.1 from specifications)
const char *FAKE_DEVICE_DESCRIPTION =
    "<?xml version=\"1.0\"?>\n"
    "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\n"
    "  <specVersion>\n"
    "    <major>1</major>\n"
    "    <minor>0</minor>\n"
    "  </specVersion>\n"
    "  <device>\n"
    "    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>\n"
    "    <friendlyName>Philips Hue Smart Bulb</friendlyName>\n"
    "    <manufacturer>Philips</manufacturer>\n"
    "    <manufacturerURL>https://www.philips-hue.com</manufacturerURL>\n"
    "    <modelDescription>Philips Hue A19 White and Color Ambiance</modelDescription>\n"
    "    <modelName>Hue A19</modelName>\n"
    "    <modelNumber>9290012573A</modelNumber>\n"
    "    <modelURL>https://www.philips-hue.com/en-us/p/hue-white-and-color-ambiance-a19</modelURL>\n"
    "    <serialNumber>PHL-00256739</serialNumber>\n"
    "    <UDN>uuid:31c79c6d-7d92-4bbf-bf72-5b68591e1731</UDN>\n"
    "    <serviceList>\n";

const char *FAKE_CHUNK =
    "      <service>\n"
    "        <serviceType>urn:schemas-upnp-org:service:SwitchPower:1</serviceType>\n"
    "        <serviceId>urn:upnp-org:serviceId:SwitchPower</serviceId>\n"
    "        <controlURL>/hue_control</controlURL>\n"
    "        <eventSubURL>/hue_event</eventSubURL>\n"
    "        <SCPDURL>/hue_service.xml</SCPDURL>\n"
    "      </service>\n";

void heartbeatLog() {
    syslog(LOG_INFO, "Server is running with %d connected clients.", clientQueueUpnp.length);
    syslog(LOG_INFO, "Current statistics: wasted time: %lld ms. Total connected clients: %ld", statsUpnp.totalWastedTime, statsUpnp.totalConnects);
}

char* getLocalIpAddress(){
    char hostbuffer[256];
    struct hostent *hostEntry;
    gethostname(hostbuffer, sizeof(hostbuffer));
    hostEntry = gethostbyname(hostbuffer);
    if(hostEntry == NULL){
        syslog(LOG_ERR, "Failed getting hostname");
        exit(EXIT_FAILURE);
    }
    char *ipAddress = inet_ntoa(*((struct in_addr*)
                        hostEntry->h_addr_list[0]));

    return ipAddress;
}

char* buildSsdpResponse() {
    char *ipAddress = getLocalIpAddress();

    char *responseBuffer = (char*) malloc((512)*sizeof(char));
    snprintf(responseBuffer, 512,
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=1800\r\n"
        "EXT:\r\n"
        "LOCATION: http://%s:%d/hue-device.xml\r\n"
        "SERVER: Linux/3.14 UPnP/1.0 PhilipsHue/2.1\r\n"
        "ST: urn:schemas-upnp-org:device:Basic:1\r\n"
        "USN: uuid:bd752e88-91a9-49e4-8297-8433e05d1c22::urn:schemas-upnp-org:device:Basic:1\r\n"
        "\r\n", ipAddress, HTTP_PORT);
    return responseBuffer;
}

// Handles SSDP discovery requests and sends fake responses
void *ssdpListener(void *arg) {
    (void)arg;
    char* response = buildSsdpResponse();
    int sockFd;
    struct sockaddr_in serverAddr, client_addr;
    socklen_t addrLen = sizeof(client_addr);
    char buffer[1024];

    printf("response: %s\n", response);

    if ((sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { // works
        syslog(LOG_ERR, "SSDP Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind to all interfaces for unicast
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SSDP_PORT);

    // Join the SSDP multicast group
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(SSDP_MULTICAST);
    mreq.imr_interface.s_addr = INADDR_ANY;
    setsockopt(sockFd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)); // Maybe IPPROTO_UDP instead

    if (bind(sockFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        syslog(LOG_ERR, "SSDP Bind failed");
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "UPnP listener started on port %d\n", SSDP_PORT);

    while (1) {
        memset(buffer, 0, sizeof(buffer));

        if (recvfrom(sockFd, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&client_addr, &addrLen) <= 0) {
            syslog(LOG_ERR, "Error receiving SSDP request");
            continue;
        }

        printf("received %s", buffer);

        // Ignore all requests that are not discovery
        if (strstr(buffer, "M-SEARCH") != NULL) {
            // if(strstr(buffer, "")) // Check header values
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            syslog(LOG_INFO, "Received SSDP M-SEARCH request from %s\n", client_ip);
            sendto(sockFd, response, strlen(response), 0,
                (struct sockaddr *)&client_addr, sizeof(client_addr));
            syslog(LOG_INFO, "Sent fake SSDP response to %s\n", client_ip);
        }
    }

    free(response);
    close(sockFd);
    return NULL;
}

void *httpServer(void *arg) {
    (void)arg;
    signal(SIGPIPE, SIG_IGN);
    queue_init(&clientQueueUpnp);
    int serverSock = createServer(HTTP_PORT);
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
    while (1){
        long long now = currentTimeMs();
        int timeout = -1;

        long long res = now - lastHeartbeat;

        if (res >= HEARTBEAT_INTERVAL_MS) {
            heartbeatLog();
            lastHeartbeat = now;
        }

        while (clientQueueUpnp.head) {
            if(clientQueueUpnp.head->sendNext <= now){
                struct client *c = queue_pop(&clientQueueUpnp);

                char chunk_size[10];
                snprintf(chunk_size, sizeof(chunk_size), "%X\r\n", (int)strlen(FAKE_CHUNK));
                write(c->fd, chunk_size, strlen(chunk_size)); // sizeof is too short
                write(c->fd, FAKE_CHUNK, strlen(FAKE_CHUNK));
                ssize_t out = write(c->fd, "\r\n", 2);
                
                if (out == -1) {
                    printf("Out is %ld with errno %s\n", out, strerror(errno));
                    if (errno == EAGAIN || errno == EWOULDBLOCK) { // Avoid blocking
                        c->sendNext = now + DELAY_MS;
                        c->timeConnected += DELAY_MS;
                        statsUpnp.totalWastedTime += DELAY_MS;
                        queue_append(&clientQueueUpnp, c);
                    } else if (errno == EPIPE) {
                        printf("Logged disconnect\n");
                        long long timeTrapped = c->timeConnected;
                        syslog(LOG_INFO, "Client disconnected from IP: %s:%d with fd: %d with time %lld",
                            c->ipaddr, c->port, c->fd, timeTrapped);
                        close(c->fd);
                        free(c);
                    }
                } else {
                    c->sendNext = now + DELAY_MS;
                    c->timeConnected += DELAY_MS;
                    statsUpnp.totalWastedTime += DELAY_MS;
                    queue_append(&clientQueueUpnp, c);
                }
            } else {
                timeout = clientQueueUpnp.head->sendNext - now;
                break;
            }
        }

        int pollResult = poll(&fds, 1, timeout);
        if (pollResult < 0) {
            syslog(LOG_ERR, "Poll error with error %s", strerror(errno));
            continue;
        }

        // Accept new connections
        if (fds.revents & POLLIN) {
            int clientFd = accept(serverSock, (struct sockaddr *)&clientAddr, &addrLen);
            if (clientFd >= 0) {
                fcntl(clientFd, F_SETFL, O_NONBLOCK); // Set non-blocking mode
                struct client* newClient = malloc(sizeof(struct client));
                if (newClient == NULL) {
                    syslog(LOG_ERR, "Out of memory");
                    close(clientFd);
                    continue;
                }

                char buffer[1024];
                memset(buffer, 0, 1024);
                read(clientFd, buffer, 1024-1);
                char method[10], url[256];
                sscanf(buffer, "%9s %255s", method, url);

                if (strcmp(url, "/hue-device.xml") == 0 && strcmp(method, "GET") == 0) {
                    char responseHeader[] =
                        "HTTP/1.1 200 OK\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "Trailer: X-Checksum\r\n"
                        "\r\n";
                    
                    ssize_t out = write(clientFd, responseHeader, strlen(responseHeader));
                    if(out <= 0){
                        syslog(LOG_ERR, "failed to write response header to %s:%d\n", 
                            inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
                        close(clientFd);
                        free(newClient);
                        continue;
                    }

                    statsUpnp.totalConnects += 1;
                    newClient->fd = clientFd;
                    newClient->sendNext = now + DELAY_MS;
                    newClient->timeConnected = 0;
                    snprintf(newClient->ipaddr, sizeof(newClient->ipaddr), "%s", inet_ntoa(clientAddr.sin_addr));
                    newClient->port = ntohs(clientAddr.sin_port);
                    queue_append(&clientQueueUpnp, newClient);

                    // syslog(LOG_INFO,"Accepted GET request from from %s:%d\n",
                    //     inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
                    printf("Accepted GET request from from %s:%d\n",
                        inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
                // Ignore requests without a method or url
                // } else if (strcmp(method, "") == 0 || strcmp(url, "")) {
                //     continue;
                } else {
                    statsUpnp.otherRequests += 1;
                    // syslog(LOG_INFO, "Received %s request with %s url", method, url);
                    printf("Received %s request with %s url\n", method, url);
                    close(clientFd);
                    free(newClient);
                    continue;
                }
            }
        }
    }

    closelog();
    close(serverSock);
    return NULL;
}

void initializeStats(){
    statsUpnp.totalConnects = 0;
    statsUpnp.totalWastedTime = 0;
    statsUpnp.otherRequests = 0;
}

int main() {
    openlog("upnp_tarpit", LOG_PID | LOG_CONS, LOG_USER);
    initializeStats();
    pthread_t ssdpThread, httpThread;
    pthread_create(&ssdpThread, NULL, ssdpListener, NULL);
    pthread_create(&httpThread, NULL, httpServer, NULL);
    pthread_join(ssdpThread, NULL);
    pthread_join(httpThread, NULL);
    return 0;
}
