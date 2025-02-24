CC = gcc
CFLAGS = -Wall -Wextra -g
TARGET = telnet_pit

all: $(TARGET)

$(TARGET): telnet_pit.c
	$(CC) $(CFLAGS) -o $(TARGET) telnet_pit.c

clean:
	rm -f $(TARGET)

run: all
	./$(TARGET)

.PHONY: all clean run
