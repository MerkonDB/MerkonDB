# Makefile for MerkonDB

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -ljansson -lssl -lcrypto -pthread

SRCS = server.c smt.c smt_db.c rbac.c
TARGET = server

.PHONY: all run-server run-client clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

run-server:
	@echo "Starting MerkonDB server on localhost:8080"
	./server localhost 8080

run-client:
	@echo "Launching MerkonDB client shell..."
	python3 client.py localhost 8080 admin pass

clean:
	rm -f $(TARGET)
