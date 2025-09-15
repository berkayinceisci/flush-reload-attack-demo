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
TARGETS = victim attacker victim_rsa attacker_rsa
VICTIM_SRC = $(SRCDIR)/victim.c
ATTACKER_SRC = $(SRCDIR)/attacker.c
VICTIM_RSA_SRC = $(SRCDIR)/victim_rsa.c
ATTACKER_RSA_SRC = $(SRCDIR)/attacker_rsa.c

# Default target
all: $(TARGETS)

# Victim process (uses libgcrypt)
victim: $(VICTIM_SRC) | check-deps
	@echo "Building victim process..."
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $(BINDIR)/victim $(VICTIM_SRC) $(LIBGCRYPT_FLAGS)
	@echo "Victim built successfully!"

# Attacker process (uses dlopen)
attacker: $(ATTACKER_SRC)
	@echo "Building attacker process..."
	$(CC) $(CFLAGS) -o $(BINDIR)/attacker $(ATTACKER_SRC) -ldl
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

# Check if required library exists
check-deps:
	@if [ ! -f "$(LIBDIR)/libgcrypt.so.11.6.0" ]; then \
		echo "Error: libgcrypt.so.11.6.0 not found in $(LIBDIR)"; \
		echo "Please ensure the library file is present"; \
		exit 1; \
	fi
	@echo "Dependencies check passed"

# Run the demo
demo: all
	@echo "=== Cache Side-Channel Attack Demo ==="
	@echo "Starting victim process in background..."
	@LD_LIBRARY_PATH=./lib:$$LD_LIBRARY_PATH ./victim &
	@VICTIM_PID=$$!; \
	echo "Victim started with PID: $$VICTIM_PID"; \
	sleep 2; \
	echo "Starting attacker process (will run for 10 seconds)..."; \
	timeout 10 ./attacker || true; \
	echo "Stopping victim process..."; \
	kill $$VICTIM_PID 2>/dev/null || true; \
	wait $$VICTIM_PID 2>/dev/null || true; \
	echo "Demo completed!"

# Run RSA key recovery demo
demo-rsa: victim_rsa attacker_rsa
	@echo "=== RSA Key Recovery Attack Demo ==="
	@echo "Starting RSA victim process in background..."
	@LD_LIBRARY_PATH=./lib:$$LD_LIBRARY_PATH ./victim_rsa &
	@VICTIM_PID=$$!; \
	echo "RSA victim started with PID: $$VICTIM_PID"; \
	sleep 5; \
	echo "Starting RSA attacker process (will run for 15 seconds)..."; \
	timeout 15 ./attacker_rsa || true; \
	echo "Stopping RSA victim process..."; \
	kill $$VICTIM_PID 2>/dev/null || true; \
	wait $$VICTIM_PID 2>/dev/null || true; \
	echo "RSA demo completed!"

# Test individual components
test-victim: victim
	@echo "Testing victim process (Ctrl+C to stop)..."
	@LD_LIBRARY_PATH=./lib:$$LD_LIBRARY_PATH ./victim

test-attacker: attacker
	@echo "Testing attacker process (requires victim to be running)..."
	@./attacker

# Test RSA components
test-victim-rsa: victim_rsa
	@echo "Testing RSA victim process (Ctrl+C to stop)..."
	@LD_LIBRARY_PATH=./lib:$$LD_LIBRARY_PATH ./victim_rsa

test-attacker-rsa: attacker_rsa
	@echo "Testing RSA attacker process (requires RSA victim to be running)..."
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
	@echo "  all           - Build all programs (AES and RSA demos)"
	@echo "  victim        - Build AES victim process only"
	@echo "  attacker      - Build AES attacker process only"
	@echo "  victim_rsa    - Build RSA victim process only"
	@echo "  attacker_rsa  - Build RSA attacker process only"
	@echo "  demo          - Run AES cache attack demo"
	@echo "  demo-rsa      - Run RSA key recovery attack demo"
	@echo "  test-victim   - Test AES victim process interactively"
	@echo "  test-attacker - Test AES attacker process"
	@echo "  test-victim-rsa   - Test RSA victim process interactively"
	@echo "  test-attacker-rsa - Test RSA attacker process"
	@echo "  clean         - Remove build artifacts"
	@echo "  install-deps  - Install system dependencies (Ubuntu/Debian)"
	@echo "  info          - Show library information"
	@echo "  help          - Show this help message"

.PHONY: all demo demo-rsa test-victim test-attacker test-victim-rsa test-attacker-rsa clean install-deps info help check-deps