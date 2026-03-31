CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c23 -g
LDFLAGS = -lpcap

SRC = src/*.c
TARGET = ipk-L2L3-scan

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
