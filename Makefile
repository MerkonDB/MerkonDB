# Makefile for MerkonDB Server

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
LDFLAGS = -lssl -lcrypto -ljansson -pthread

# Target executable
TARGET = server

# Source files
SOURCES = server.c rbac.c smt.c

# Object files (automatically generated from sources)
OBJECTS = $(SOURCES:.c=.o)

# Header files (for dependency tracking)
HEADERS = rbac.h smt.h

# Default target
all: $(TARGET)

# Build the server executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Compile source files to object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)

# Force rebuild
rebuild: clean all

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install libssl-dev libjansson-dev build-essential

# Install dependencies (CentOS/RHEL/Fedora)
install-deps-rpm:
	sudo yum install openssl-devel jansson-devel gcc make

# Debug build with extra debugging symbols
debug: CFLAGS += -DDEBUG -O0
debug: $(TARGET)

# Release build with optimizations
release: CFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

# Run the server (example usage)
run: $(TARGET)
	./$(TARGET) 8080

# Check for memory leaks with valgrind
valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) 8080

# Static analysis with cppcheck
check:
	cppcheck --enable=all --std=c99 $(SOURCES)

# Format code with clang-format
format:
	clang-format -i $(SOURCES) $(HEADERS)

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build the server (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  rebuild      - Clean and build"
	@echo "  debug        - Build with debug symbols"
	@echo "  release      - Build optimized release version"
	@echo "  install-deps - Install dependencies (Ubuntu/Debian)"
	@echo "  install-deps-rpm - Install dependencies (CentOS/RHEL/Fedora)"
	@echo "  run          - Build and run server on port 8080"
	@echo "  valgrind     - Run with memory leak detection"
	@echo "  check        - Run static analysis"
	@echo "  format       - Format source code"
	@echo "  help         - Show this help message"

# Declare phony targets
.PHONY: all clean rebuild install-deps install-deps-rpm debug release run valgrind check format help