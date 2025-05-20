package main

import (
	// "bufio"
	"fmt"
	"log"
	"net/netip"
	"net"
	"net/http"
	"strings"
	"os"
	"strconv"

	// "github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	telnetTotalConnects  prometheus.Counter
	telnetTotalTrappedTime prometheus.Counter
	telnetActiveClients prometheus.Gauge
	telnetClients *prometheus.CounterVec

	upnpTotalConnects prometheus.Counter
	upnpTotalTrappedTime prometheus.Counter
	upnpActiveClients prometheus.Gauge
	upnpOtherHttpRequests *prometheus.CounterVec
	upnpMSearchRequests *prometheus.CounterVec
	upnpNonMSearchRequests *prometheus.CounterVec
	upnpClients *prometheus.CounterVec

	mqttTotalConnects prometheus.Counter
	mqttTotalTrappedTime prometheus.Counter
	mqttActiveClients prometheus.Gauge
	mqttClients *prometheus.CounterVec
	mqttMalformedConnect prometheus.Counter
	mqttConnectVersions *prometheus.CounterVec
	mqttSubscribeTopics *prometheus.CounterVec
	mqttCredentials *prometheus.CounterVec
	mqttPublishTopics *prometheus.CounterVec
	mqttConacks prometheus.Counter
	mqttUnsubscribe prometheus.Counter
	mqttPubrec prometheus.Counter

	coapTotalConnects prometheus.Counter
	coapTotalTrappedTime prometheus.Counter
	coapActiveClients prometheus.Gauge
	coapClients *prometheus.CounterVec
}

// Global variable
var db *maxminddb.Reader

func NewMetrics() *metrics {
	m := &metrics{
		telnetTotalConnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "telnet_pit_total_connects",
			Help: "Total client connections for telnet",
		}),
		telnetTotalTrappedTime: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "telnet_pit_total_trapped_time_ms",
			Help: "Total time clients were trapped (ms) for telnet",
		}),
		telnetActiveClients: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "telnet_pit_current_connected_clients",
			Help: "Currently connected clients for telnet",
		}),
		telnetClients: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "telnet_pit_clients",
			Help: "Connected clients for telnet",
		}, []string{/*"ip", */"country", "latitude", "longitude"}),
		// -------------
		upnpTotalConnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "upnp_pit_total_connects",
			Help: "Total http GET requests for the fake .xml file",
		}),
		upnpTotalTrappedTime: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "upnp_pit_total_trapped_time_ms",
			Help: "Total time clients were trapped (ms) for upnp",
		}),
		upnpActiveClients: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "upnp_pit_current_connected_clients",
			Help: "Currently connected clients for upnp",
		}),
		upnpClients: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upnp_pit_clients",
			Help: "Connected clients for upnp",
		}, []string{/*"ip", */"country", "latitude", "longitude"}),
		upnpOtherHttpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upnp_other_http_requests",
			Help: "Number of http requests that are not for the .xml file",
		}, []string{"method", "url"}),
		upnpMSearchRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upnp_M-Search_requests",
			Help: "Number of M-Search requests",
		}, []string{"ip"}),
		upnpNonMSearchRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upnp_non_M-Search_requests",
			Help: "Number of SSDP requests that are not M-SEARCH",
		}, []string{"ip"}),
		// ---------------
		mqttTotalConnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_total_connects",
			Help: "Total client connections for MQTT",
		}),
		mqttTotalTrappedTime: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_total_trapped_time_ms",
			Help: "Total time clients were trapped (ms) for MQTT",
		}),
		mqttActiveClients: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mqtt_pit_current_connected_clients",
			Help: "Currently connected clients for MQTT",
		}),
		mqttClients: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_clients",
			Help: "Connected clients for MQTT",
		}, []string{/*"ip", */"country", "latitude", "longitude"}),
		mqttMalformedConnect: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_malformed_connects",
			Help: "Malformed MQTT CONNECT packets received",
		}),
		mqttConnectVersions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_connect_versions",
			Help: "MQTT CONNECT versions used by clients",
		}, []string{"version"}),
		mqttSubscribeTopics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_subscribe_topics",
			Help: "MQTT SUBSCRIBE topics and QoS",
		}, []string{"topic", "qos"}),
		mqttCredentials: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_credentials",
			Help: "MQTT credentials used",
		}, []string{"username", "password"}),
		mqttPublishTopics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_publish_topics",
			Help: "MQTT PUBLISH topic and QoS",
		}, []string{"topic", "qos"}),
		mqttConacks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_connack_counter",
			Help: "Total CONNACK requests for MQTT",
		}),
		mqttUnsubscribe: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_unsub_counter",
			Help: "Total UNSUBSCRIBE requests for MQTT",
		}),
		mqttPubrec: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_pubrec_counter",
			Help: "Total PUBREC requests for MQTT",
		}),
		// ------------------
		coapTotalConnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "coap_pit_total_connects",
			Help: "Total client connections for CoAP",
		}),
		coapTotalTrappedTime: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "coap_pit_total_trapped_time_ms",
			Help: "Total time clients were trapped (ms) for CoAP",
		}),
		coapActiveClients: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "coap_pit_current_connected_clients",
			Help: "Currently connected clients for CoAP",
		}),
		coapClients: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "coap_pit_clients",
			Help: "Connected clients for CoAP",
		}, []string{"ip", "country", "latitude", "longitude"}),
	}
	prometheus.MustRegister(m.telnetTotalConnects, m.telnetTotalTrappedTime, m.telnetActiveClients, m.telnetClients,
		m.upnpTotalConnects, m.upnpTotalTrappedTime, m.upnpActiveClients, m.upnpClients, m.upnpOtherHttpRequests, m.upnpMSearchRequests, m.upnpNonMSearchRequests,
		m.mqttTotalConnects, m.mqttTotalTrappedTime, m.mqttActiveClients, m.mqttClients, m.mqttConacks, m.mqttUnsubscribe, m.mqttPubrec,
		m.mqttMalformedConnect, m.mqttConnectVersions, m.mqttSubscribeTopics, m.mqttCredentials, m.mqttPublishTopics,
		m.coapTotalConnects, m.coapTotalTrappedTime, m.coapActiveClients, m.coapClients,)
	return m
}

func main() {
	var err error
	geoliteDbPath := os.Getenv("GEO_DB")
	// fmt.Print(geoliteDbPath+"\n")
	db, err = maxminddb.Open(geoliteDbPath)
    if err != nil {
        log.Fatal("Cannot open GeoLite2 database: ", err)
    }
    defer db.Close()

	// var server = "telnet"
	// Register metrics
	m := NewMetrics()
	// m.telnetTotalConnects.WithLabelValues(server).Add(1)
	// m.telnetTotalTrappedTime.WithLabelValues(server).Add(2)
	// m.telnetActiveClients.WithLabelValues(server).Set(3)
	// m.telnetClients.WithLabelValues(server, "82.211.212.0", "Denmark", "55.676097", "12.568337").Set(4)

	// Start socket listener
	go listenForMetrics("/tmp/tarpit_exporter.sock", m)

	// HTTP handler
	http.Handle("/metrics", promhttp.Handler())
	log.Println("Metrics available at :9101/metrics")
	log.Fatal(http.ListenAndServe(":9101", nil))
}

func listenForMetrics(socketPath string, metrics *metrics) {
	// Clean old socket
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to remove existing socket: %v", err)
	}

	conn, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		log.Fatalf("Socket bind error: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			log.Println("Read error:", err)
			continue
		}
		handleMetric(strings.TrimSpace(string(buf[:n])), metrics)
	}
}

func handleMetric(line string, metrics *metrics) {
	fields := strings.Fields(line)
	log.Println(fields)

	server := fields[0]
	command := fields[1]

	switch command {
	case "connect":
		ip := fields[2]
		country := geoLookup(ip)
		lat := CapitalCoordinates[country].Latitude
		lon := CapitalCoordinates[country].Longitude
		// Reduce cardinality by removing ip
		handleConnect(server, country, lat, lon, metrics)
	case "disconnect":
		// ip := fields[2]
		parsedTimeTrapped, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			fmt.Println("Error parsing timeTrapped:", err)
			return
		}
		timeTrapped := float64(parsedTimeTrapped)
		handleDisconnect(server, timeTrapped, metrics)
	// UPnP
	case "otherHttpRequests":
		method := fields[2]
		url := fields[3]
		metrics.upnpOtherHttpRequests.WithLabelValues(method, url).Inc()
	case "M-SEARCH":
		ip := fields[2]
		metrics.upnpMSearchRequests.WithLabelValues(ip).Inc()
	case "non-M-SEARCH":
		ip := fields[2]
		metrics.upnpNonMSearchRequests.WithLabelValues(ip).Inc()
	// MQTT
	case "CONNECT":
		version := fields[2]
		metrics.mqttConnectVersions.WithLabelValues(version).Inc()

	case "malformedConnect":
		metrics.mqttMalformedConnect.Inc()

	case "SUBSCRIBE":
		topic := fields[2]
		qos := fields[3]
		metrics.mqttSubscribeTopics.WithLabelValues(topic, qos).Inc()

	case "credentials":
		username := fields[2]
		password := fields[3]
		metrics.mqttCredentials.WithLabelValues(username, password).Inc()

	case "PUBLISH":
		topic := fields[2]
		qos := fields[3]
		metrics.mqttPublishTopics.WithLabelValues(topic, qos).Inc()

	case "CONNACK":
		metrics.mqttConacks.Inc();
	case "UNSUBSCRIBE":
		metrics.mqttUnsubscribe.Inc();
	case "PUBREC":
		metrics.mqttPubrec.Inc();
	}
}

func handleConnect(server string, country string, lat float64, lon float64, metrics *metrics) {
	switch server {
	case "Telnet":
		metrics.telnetTotalConnects.Inc()
		metrics.telnetActiveClients.Inc()
		metrics.telnetClients.WithLabelValues(country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	case "UPnP":
		metrics.upnpTotalConnects.Inc()
		metrics.upnpActiveClients.Inc()
		metrics.upnpClients.WithLabelValues(country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	case "MQTT":
		metrics.mqttTotalConnects.Inc()
		metrics.mqttActiveClients.Inc()
		metrics.mqttClients.WithLabelValues(country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	case "CoAP":
		metrics.coapTotalConnects.Inc()
		metrics.coapActiveClients.Inc()
		metrics.coapClients.WithLabelValues(country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	}
}

func handleDisconnect(server string, timeTrapped float64, metrics *metrics) {
	switch server {
	case "Telnet":
		metrics.telnetActiveClients.Dec()
		metrics.telnetTotalTrappedTime.Add(timeTrapped)
	case "UPnP":
		metrics.upnpActiveClients.Dec()
		metrics.upnpTotalTrappedTime.Add(timeTrapped)
	case "MQTT":
		metrics.mqttActiveClients.Dec()
		metrics.mqttTotalTrappedTime.Add(timeTrapped)
	case "CoAP":
		metrics.coapActiveClients.Dec()
		metrics.coapTotalTrappedTime.Add(timeTrapped)
	}
}

func parseTimeMs(s string) int64 {
	var ms int64
	_, _ = fmt.Sscanf(s, "%d", &ms)
	return ms
}

func geoLookup(ipStr string) string {
    ip := netip.MustParseAddr(ipStr)

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	} 
	err := db.Lookup(ip).Decode(&record)
	if err != nil {
		log.Panic(err)
	}
	fmt.Print(record.Country.ISOCode)

	return record.Country.ISOCode
}