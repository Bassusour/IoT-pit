CC = gcc
CFLAGS = -Wall -Wextra -g -pthread

STRUCTS = structs.c

TELNET_TARGET = telnet_pit
UPNP_TARGET = upnp_pit
MQTT_TARGET = mqtt_pit

TELNET_SRC = telnet_pit.c
UPNP_SRC = upnp_pit.c
MQTT_SRC = mqtt_pit.c

# Default Rule: Compile all programs
all: $(TELNET_TARGET) $(UPNP_TARGET) $(MQTT_TARGET)

$(TELNET_TARGET): $(TELNET_SRC)
	$(CC) $(CFLAGS) -o $(TELNET_TARGET) $(TELNET_SRC) $(STRUCTS)

$(UPNP_TARGET): $(UPNP_SRC)
	$(CC) $(CFLAGS) -o $(UPNP_TARGET) $(UPNP_SRC) $(STRUCTS)

$(MQTT_TARGET): $(MQTT_SRC)
	$(CC) $(CFLAGS) -o $(MQTT_TARGET) $(MQTT_SRC) $(STRUCTS)

clean:
	rm -f $(TELNET_TARGET) $(UPNP_TARGET) $(MQTT_TARGET)

.PHONY: all clean run_telnet run_upnp
