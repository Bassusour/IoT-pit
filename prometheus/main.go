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
		}, []string{"ip", "country", "latitude", "longitude"}),
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
		}, []string{"ip", "country", "latitude", "longitude"}),
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
	}
	prometheus.MustRegister(m.telnetTotalConnects, m.telnetTotalTrappedTime, m.telnetActiveClients, m.telnetClients,
		m.upnpTotalConnects, m.upnpTotalTrappedTime, m.upnpActiveClients, m.upnpClients, m.upnpOtherHttpRequests, m.upnpMSearchRequests, m.upnpNonMSearchRequests)
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
		handleConnect(server, country, lat, lon, ip, metrics)
	case "disconnect":
		// ip := fields[2]
		parsedTimeTrapped, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			fmt.Println("Error parsing timeTrapped:", err)
			return
		}
		timeTrapped := float64(parsedTimeTrapped)
		handleDisconnect(server, timeTrapped, metrics)
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
	}
}

func handleConnect(server string, country string, lat float64, lon float64, ip string, metrics *metrics) {
	switch server {
	case "telnet":
		metrics.telnetTotalConnects.Inc()
		metrics.telnetActiveClients.Inc()
		metrics.telnetClients.WithLabelValues(ip, country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	case "UPnP":
		metrics.upnpTotalConnects.Inc()
		metrics.upnpActiveClients.Inc()
		metrics.upnpClients.WithLabelValues(ip, country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	}
}

func handleDisconnect(server string, timeTrapped float64, metrics *metrics) {
	switch server {
	case "telnet":
		metrics.telnetActiveClients.Dec()
		metrics.telnetTotalTrappedTime.Add(timeTrapped)
	case "upnp":
		metrics.upnpActiveClients.Dec()
		metrics.upnpTotalTrappedTime.Add(timeTrapped)
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