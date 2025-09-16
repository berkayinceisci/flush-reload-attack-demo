# Cache Side-Channel Attack Demo

This is a complete, standalone demonstration of **Flush+Reload cache side-channel attacks** against the libgcrypt cryptographic library. The demo includes two attack scenarios:

1. **AES Cache Attack**: Generic cache monitoring of AES encryption functions
2. **RSA Key Recovery Attack**: Targeted attack on RSA square-and-multiply operations to recover private key bits

## 🚀 **Quick Start**

### Prerequisites
- Linux x86_64 system
- GCC compiler
- libgpg-error development package

Install dependencies (Ubuntu/Debian):
```bash
make install-deps
```

### Build and Run
```bash
# Build everything
make

# Run components separately:
# AES Attack:
# Terminal 1: make run-victim-aes
# Terminal 2: make run-attacker-aes

# RSA Key Recovery Attack:
# Terminal 1: make run-victim-rsa
# Terminal 2: make run-attacker-rsa
```

## 🎯 **How the Attack Works**

### Flush+Reload Technique

1. **Flush Phase**: Attacker evicts target memory lines from CPU cache using `clflush`
2. **Victim Execution**: Victim performs cryptographic operations, potentially loading flushed lines
3. **Reload Phase**: Attacker measures memory access time to detect cache hits/misses
4. **Analysis**: Fast access times indicate victim accessed that memory location
