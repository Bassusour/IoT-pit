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

	// "github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	totalConnects  *prometheus.CounterVec
	totalTrappedTime *prometheus.CounterVec
	activeClients *prometheus.GaugeVec
	clientsByIP *prometheus.GaugeVec
}

// Global variable
var db *maxminddb.Reader

func NewMetrics() *metrics {
	m := &metrics{
		totalConnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "telnet_pit_total_connects",
			Help: "Total client connections",
		}, []string{"server"}),
		totalTrappedTime: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "telnet_pit_total_trapped_time_ms",
			Help: "Total time clients were trapped (ms)",
		}, []string{"server"}),
		activeClients: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "telnet_pit_current_connected_clients",
			Help: "Currently connected clients",
		}, []string{"server"}),
		clientsByIP: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "telnet_pit_client_connected",
			Help: "Connected clients by IP (used for geolocation)",
		}, []string{"server", "ip", "country"}),
	}
	prometheus.MustRegister(m.totalConnects, m.totalTrappedTime, m.activeClients, m.clientsByIP)
	return m
}

func main() {
	var err error
    // db, err := geoip2.Open("GeoLite2-Country.mmdb")
	db, err := maxminddb.Open("GeoLite2-Country.mmdb")
    if err != nil {
        log.Fatal("Cannot open GeoLite2 database:", err)
    }
    defer db.Close()

	var server = "telnet"
	// Register metrics
	m := NewMetrics()
	m.totalConnects.WithLabelValues(server).Add(1)
	m.totalTrappedTime.WithLabelValues(server).Add(2)
	m.activeClients.WithLabelValues(server).Set(3)
	m.clientsByIP.WithLabelValues(server, "82.211.212.0", "Denmark").Set(4)

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
	fmt.Print(fields)
	// if len(fields) < 2 {
	// 	return
	// }
	server := fields[0]

	switch fields[0] {
	case "connect":
		ip := fields[1]
		// totalConnects.Inc()
		// activeClients.Inc()
		// clientsByIP.WithLabelValues(ip).Set(1)
		gm := geoLookup(ip)
        metrics.clientsByIP.WithLabelValues(ip, server, gm).Inc()

	case "disconnect":
		// if len(fields) != 3 {
		// 	return
		// }
		ip := fields[1]
		timeMs := parseTimeMs(fields[2])
		metrics.totalTrappedTime.WithLabelValues(server).Add(float64(timeMs))
		metrics.activeClients.WithLabelValues(server).Dec()
		metrics.clientsByIP.WithLabelValues(ip).Set(0)
	}
}

func parseTimeMs(s string) int64 {
	var ms int64
	_, _ = fmt.Sscanf(s, "%d", &ms)
	return ms
}

func geoLookup(ipStr string) string {
    ip := netip.MustParseAddr(ipStr)
    // if ip == nil {
	// 	return "ip is nil"
    //     // return geoMeta{}
    // }

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

    // record, err := db.Country(ip)
    // if err != nil {
    //     return geoMeta{}
    // }

	return record.Country.ISOCode
}