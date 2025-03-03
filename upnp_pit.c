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

const char *FAKE_SSDP_RESPONSE =
    "HTTP/1.1 200 OK\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "EXT:\r\n"
    "LOCATION: http://192.168.1.250:8080/hue-device.xml\r\n"
    "SERVER: Linux/3.14 UPnP/1.0 PhilipsHue/2.1\r\n"
    "ST: urn:schemas-upnp-org:device:Basic:1\r\n"
    "USN: uuid:bd752e88-91a9-49e4-8297-8433e05d1c22::urn:schemas-upnp-org:device:Basic:1\r\n"
    "\r\n";

// Corrected Fake CallStranger UPnP SUBSCRIBE Response
const char *FAKE_SUBSCRIBE_RESPONSE =
    "HTTP/1.1 200 OK\r\n"
    "SID: uuid:f28cb6c3-d723-4e28-8b22-92f570a80fd9\r\n"
    "TIMEOUT: Second-3600\r\n"
    "\r\n";

// Corrected Fake Philips Hue Bulb Device Description (XML)
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
    "    <serviceList>\n"
    "      <service>\n"
    "        <serviceType>urn:schemas-upnp-org:service:SwitchPower:1</serviceType>\n"
    "        <serviceId>urn:upnp-org:serviceId:SwitchPower</serviceId>\n"
    "        <controlURL>/hue_control</controlURL>\n"
    "        <eventSubURL>/hue_event</eventSubURL>\n"
    "        <SCPDURL>/hue_service.xml</SCPDURL>\n"
    "      </service>\n"
    "      <service>\n"
    "        <serviceType>urn:schemas-upnp-org:service:Dimming:1</serviceType>\n"
    "        <serviceId>urn:upnp-org:serviceId:Dimming</serviceId>\n"
    "        <controlURL>/dimming_control</controlURL>\n"
    "        <eventSubURL>/dimming_event</eventSubURL>\n"
    "        <SCPDURL>/dimming_service.xml</SCPDURL>\n"
    "      </service>\n"
    "    </serviceList>\n"
    "    <presentationURL>http://192.168.1.250:8080</presentationURL>\n"
    "  </device>\n"
    "</root>\n";

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
    openlog("upnp_tarpit", LOG_PID | LOG_CONS, LOG_USER);
    pthread_t ssdpThread, httpThread;
    pthread_create(&ssdpThread, NULL, ssdpListener, NULL);
    pthread_create(&httpThread, NULL, httpServer, NULL);
    pthread_join(ssdpThread, NULL);
    pthread_join(httpThread, NULL);
    return 0;
}
