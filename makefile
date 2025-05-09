CC = gcc
CFLAGS = -Wall -Wextra -g -pthread

STRUCTS = shared/structs.c

TELNET_TARGET = bin/telnet_pit
UPNP_TARGET = bin/upnp_pit
MQTT_TARGET = bin/mqtt_pit

TELNET_SRC = servers/telnet_pit.c
UPNP_SRC = servers/upnp_pit.c
MQTT_SRC = servers/mqtt_pit.c

GO_DIR = prometheus
GO_TARGET = bin/prometheus_exporter
GO_SRCS := $(wildcard prometheus/*.go)

BIN_DIR = bin

# Default Rule
all: $(TELNET_TARGET) $(UPNP_TARGET) $(MQTT_TARGET) $(GO_TARGET)

$(TELNET_TARGET): $(TELNET_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(STRUCTS)

$(UPNP_TARGET): $(UPNP_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(STRUCTS)

$(MQTT_TARGET): $(MQTT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(STRUCTS)

$(GO_TARGET): $(GO_SRCS) | $(BIN_DIR)
	cd $(GO_DIR) && go build -o ../$(GO_TARGET)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Aliases
telnet_pit: $(TELNET_TARGET)
upnp_pit:   $(UPNP_TARGET)
mqtt_pit:   $(MQTT_TARGET)
prometheus: $(GO_TARGET)

clean:
	rm -f $(TELNET_TARGET) $(UPNP_TARGET) $(MQTT_TARGET) $(GO_TARGET)

.PHONY: all clean
