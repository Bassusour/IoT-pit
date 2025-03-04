CC = gcc
CFLAGS = -Wall -Wextra -g -pthread

STRUCTS = structs.c

TELNET_TARGET = telnet_pit
UPNP_TARGET = upnp_pit

TELNET_SRC = telnet_pit.c
UPNP_SRC = upnp_pit.c

# Default Rule: Compile both programs
all: $(TELNET_TARGET) $(UPNP_TARGET)

$(TELNET_TARGET): $(TELNET_SRC)
	$(CC) $(CFLAGS) -o $(TELNET_TARGET) $(TELNET_SRC) $(STRUCTS)

$(UPNP_TARGET): $(UPNP_SRC)
	$(CC) $(CFLAGS) -o $(UPNP_TARGET) $(UPNP_SRC) $(STRUCTS)

clean:
	rm -f $(TELNET_TARGET) $(UPNP_TARGET)

run_telnet: $(TELNET_TARGET)
	./$(TELNET_TARGET)

run_upnp: $(UPNP_TARGET)
	./$(UPNP_TARGET)

.PHONY: all clean run_telnet run_upnp
