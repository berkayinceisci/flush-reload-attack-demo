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
TARGETS = victim attacker
VICTIM_SRC = $(SRCDIR)/victim.c
ATTACKER_SRC = $(SRCDIR)/attacker.c

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

# Test individual components
test-victim: victim
	@echo "Testing victim process (Ctrl+C to stop)..."
	@LD_LIBRARY_PATH=./lib:$$LD_LIBRARY_PATH ./victim

test-attacker: attacker
	@echo "Testing attacker process (requires victim to be running)..."
	@./attacker

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
	@echo "  all          - Build both victim and attacker (default)"
	@echo "  victim       - Build victim process only"
	@echo "  attacker     - Build attacker process only"
	@echo "  demo         - Run complete automated demo"
	@echo "  test-victim  - Test victim process interactively"
	@echo "  test-attacker- Test attacker process (needs victim running)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install system dependencies (Ubuntu/Debian)"
	@echo "  info         - Show library information"
	@echo "  help         - Show this help message"

.PHONY: all demo test-victim test-attacker clean install-deps info help check-deps