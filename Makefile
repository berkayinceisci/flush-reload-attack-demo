# Cache Side-Channel Attack Demo Makefile
# Builds victim and attacker programs against libgcrypt

CC = gcc
CFLAGS = -Wall -O2 -g
LDFLAGS = -Wl,-rpath,./lib

# Directories
SRCDIR = src
LIBDIR = lib
BINDIR = .

# Library flags
LIBGCRYPT_FLAGS = -L$(LIBDIR) -lgcrypt -lgpg-error
INCLUDES = -I$(SRCDIR)

# Targets
TARGETS = victim_aes attacker_aes victim_rsa attacker_rsa
VICTIM_AES_SRC = $(SRCDIR)/victim_aes.c
ATTACKER_AES_SRC = $(SRCDIR)/attacker_aes.c
VICTIM_RSA_SRC = $(SRCDIR)/victim_rsa.c
ATTACKER_RSA_SRC = $(SRCDIR)/attacker_rsa.c

# Default target
all: $(TARGETS)

# AES Victim process (uses libgcrypt)
victim_aes: $(VICTIM_AES_SRC) | check-deps
	@echo "Building victim process..."
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $(BINDIR)/victim $(VICTIM_AES_SRC) $(LIBGCRYPT_FLAGS)
	@echo "Victim built successfully!"

# AES Attacker process (uses dlopen)
attacker_aes: $(ATTACKER_AES_SRC)
	@echo "Building attacker process..."
	$(CC) $(CFLAGS) -o $(BINDIR)/attacker $(ATTACKER_AES_SRC) -ldl
	@echo "Attacker built successfully!"

# RSA Victim process (uses libgcrypt RSA)
victim_rsa: $(VICTIM_RSA_SRC) | check-deps
	@echo "Building RSA victim process..."
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $(BINDIR)/victim_rsa $(VICTIM_RSA_SRC) $(LIBGCRYPT_FLAGS)
	@echo "RSA victim built successfully!"

# RSA Attacker process (targets square/multiply operations)
attacker_rsa: $(ATTACKER_RSA_SRC)
	@echo "Building RSA attacker process..."
	$(CC) $(CFLAGS) -o $(BINDIR)/attacker_rsa $(ATTACKER_RSA_SRC) -ldl
	@echo "RSA attacker built successfully!"

check-deps:
	@if [ ! -f "$(LIBDIR)/libgcrypt.so.11.6.0" ]; then \
		echo "Error: libgcrypt.so.11.6.0 not found in $(LIBDIR)"; \
		echo "Please ensure the library file is present"; \
		exit 1; \
	fi
	@echo "Dependencies check passed"

run-victim-aes: victim_aes
	@echo "Running AES victim process (Ctrl+C to stop)..."
	@LD_LIBRARY_PATH=./lib:$$LD_LIBRARY_PATH ./victim_aes

run-attacker-aes: attacker_aes
	@echo "Running AES attacker process (requires AES victim to be running)..."
	@./attacker_aes

run-victim-rsa: victim_rsa
	@echo "Running RSA victim process (Ctrl+C to stop)..."
	@LD_LIBRARY_PATH=./lib:$$LD_LIBRARY_PATH ./victim_rsa

run-attacker-rsa: attacker_rsa
	@echo "Running RSA attacker process (requires RSA victim to be running)..."
	@./attacker_rsa

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(TARGETS)
	@echo "Clean completed!"

# Install dependencies (for Ubuntu/Debian)
install-deps:
	@echo "Installing required system packages..."
	@sudo apt-get update
	@sudo apt-get install -y build-essential libgpg-error-dev
	@echo "Dependencies installed!"

# Show library information
info:
	@echo "=== Library Information ==="
	@echo "Library path: $(LIBDIR)/libgcrypt.so.11.6.0"
	@if [ -f "$(LIBDIR)/libgcrypt.so.11.6.0" ]; then \
		echo "Library size: $$(ls -lh $(LIBDIR)/libgcrypt.so.11.6.0 | awk '{print $$5}')"; \
		echo "Library type: $$(file $(LIBDIR)/libgcrypt.so.11.6.0)"; \
		echo "Library dependencies:"; \
		ldd $(LIBDIR)/libgcrypt.so.11.6.0 2>/dev/null || echo "  (ldd not available)"; \
	else \
		echo "Library not found!"; \
	fi

# Help target
help:
	@echo "Available targets:"
	@echo "  all           		- Build all programs (AES and RSA demos)"
	@echo "  victim_aes    		- Build AES victim process only"
	@echo "  attacker_aes  		- Build AES attacker process only"
	@echo "  victim_rsa    		- Build RSA victim process only"
	@echo "  attacker_rsa  		- Build RSA attacker process only"
	@echo "  run-victim-aes		- Run AES victim process"
	@echo "  run-attacker-aes	- Run AES attacker process"
	@echo "  run-victim-rsa		- Run RSA victim process"
	@echo "  run-attacker-rsa	- Run RSA attacker process"
	@echo "  check-deps    		- Check if the required library exists"
	@echo "  clean         		- Remove build artifacts"
	@echo "  install-deps  		- Install system dependencies (Ubuntu/Debian)"
	@echo "  info          		- Show library information"
	@echo "  help          		- Show this help message"

.PHONY: all run-victim-aes run-attacker-aes run-victim-rsa run-attacker-rsa check-deps clean install-deps info help
