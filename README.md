# Cache Side-Channel Attack Demo

This is a complete, standalone demonstration of **Flush+Reload cache side-channel attacks** against the libgcrypt cryptographic library. The demo includes two attack scenarios:

1. **AES Cache Attack**: Generic cache monitoring of AES encryption functions
2. **RSA Key Recovery Attack**: Targeted attack on RSA square-and-multiply operations to recover private key bits

## 🚨 **IMPORTANT DISCLAIMER**

**This demonstration is for educational and research purposes only.** It illustrates vulnerabilities in shared cache architectures and the importance of side-channel resistant cryptographic implementations. **Do not use this for malicious purposes.**

## 📁 **Directory Structure**

```
cache_attack_demo/
├── Makefile              # Build system
├── README.md            # This file
├── src/                 # Source code
│   ├── victim.c         # AES victim process
│   ├── attacker.c       # AES attacker process
│   ├── victim_rsa.c     # RSA victim process
│   ├── attacker_rsa.c   # RSA key recovery attacker
│   ├── gcrypt.h         # libgcrypt header
│   └── gcrypt-module.h  # libgcrypt module header
├── lib/                 # Shared library
│   ├── libgcrypt.so.11.6.0  # Main library file (2.2MB)
│   ├── libgcrypt.so.11      # Symbolic link
│   └── libgcrypt.so         # Symbolic link
└── docs/                # Documentation (generated)
```

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

# Run AES cache attack demo
make demo

# Run RSA key recovery attack demo
make demo-rsa

# Or run components separately:
# AES Attack:
# Terminal 1: make test-victim
# Terminal 2: make test-attacker

# RSA Key Recovery Attack:
# Terminal 1: make test-victim-rsa
# Terminal 2: make test-attacker-rsa
```

## 🔧 **Available Make Targets**

| Target | Description |
|--------|-------------|
| `make` or `make all` | Build both victim and attacker programs |
| `make demo` | Run automated 10-second demonstration |
| `make victim` | Build victim process only |
| `make attacker` | Build attacker process only |
| `make test-victim` | Run victim interactively |
| `make test-attacker` | Run attacker (needs victim running) |
| `make clean` | Remove build artifacts |
| `make install-deps` | Install system dependencies |
| `make info` | Show library information |
| `make help` | Display help message |

## 🎯 **How the Attack Works**

### Flush+Reload Technique

1. **Flush Phase**: Attacker evicts target memory lines from CPU cache using `clflush`
2. **Victim Execution**: Victim performs cryptographic operations, potentially loading flushed lines
3. **Reload Phase**: Attacker measures memory access time to detect cache hits/misses
4. **Analysis**: Fast access times indicate victim accessed that memory location

### Technical Implementation

**Victim Process** (`src/victim.c`):
- Continuously performs AES-128 ECB encryption/decryption
- Uses libgcrypt shared library functions (`gcry_cipher_encrypt/decrypt`)
- Reports progress every 10,000 iterations
- Can be controlled with Ctrl+C

**Attacker Process** (`src/attacker.c`):
- Monitors 16 cache lines (64 bytes each) around AES encryption function
- Uses `clflush` instruction for cache line eviction
- Measures access time with `rdtsc` (CPU cycle counter)
- 200-cycle threshold distinguishes cache hits from misses
- Performs 100,000+ measurements for statistical analysis

### What Gets Detected

The attacker can observe:
- **Memory access patterns** during AES encryption
- **Execution frequency** of different code paths
- **Timing correlations** with cryptographic operations
- **Potential key-dependent branches** in the implementation

## 📊 **Expected Results**

A successful attack typically shows:
- **High hit rates (>95%)** on cache lines containing active AES code
- **Low hit rates (<5%)** on unused memory regions
- **Consistent patterns** correlating with victim activity
- **Real-time detection** of cryptographic operations

Example output:
```
=== ATTACK RESULTS ===
Total measurements: 100000
Cache line activity (hits/total):
Offset   0 (addr 0x7ffff7d10df0):  99994 hits (99.99%) <- ACTIVE
Offset  64 (addr 0x7ffff7d10e30):  99995 hits (100.00%) <- ACTIVE
...
```

## 🛡️ **Security Implications**

This demonstration reveals how:
- **Shared CPU cache** creates side-channel vulnerabilities
- **Process isolation** doesn't protect against cache attacks
- **Cryptographic implementations** can leak execution patterns
- **High-precision timing** enables sophisticated attacks

### Real-World Impact
- **Key recovery attacks** on RSA, ECC, AES implementations
- **Cross-VM attacks** in cloud environments
- **Browser-based attacks** via JavaScript timing
- **Microarchitectural vulnerabilities** (Spectre, Meltdown variants)

## 🔒 **Mitigation Strategies**

1. **Constant-Time Algorithms**
   - Avoid key-dependent branches and memory accesses
   - Use bitwise operations instead of table lookups
   - Implement uniform execution paths

2. **Cache Isolation**
   - Intel CAT (Cache Allocation Technology)
   - Process/VM separation with cache partitioning
   - Dedicated cryptographic processors

3. **Noise Injection**
   - Random delays and dummy operations
   - Cache line randomization
   - Execution path obfuscation

4. **Hardware Countermeasures**
   - Intel CET (Control-flow Enforcement Technology)
   - ARM Pointer Authentication
   - Secure enclaves (Intel SGX, ARM TrustZone)

## 🧪 **Experimental Variations**

Modify the attack for research:

1. **Different Algorithms**: Change victim to use RSA, ECC, or other ciphers
2. **Timing Precision**: Adjust measurement intervals and thresholds
3. **Target Functions**: Monitor different library functions
4. **Statistical Analysis**: Implement correlation analysis and pattern recognition

## 📚 **Educational Resources**

- [Cache Attacks and Countermeasures (Springer)](https://link.springer.com/book/10.1007/978-3-319-50766-9)
- [The Last Mile: An Empirical Study of Timing Channels on seL4](https://arxiv.org/abs/1403.4635)
- [Flush+Reload: A High Resolution, Low Noise, L3 Cache Side-Channel Attack](https://eprint.iacr.org/2013/448.pdf)

## ⚖️ **Legal and Ethical Considerations**

- **Educational Use Only**: This demo is for learning about computer security
- **No Unauthorized Access**: Only use on systems you own or have permission to test
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Research Ethics**: Follow institutional guidelines for security research

## 🐛 **Troubleshooting**

### Common Issues

**"Library not found" error**:
```bash
make info  # Check library status
ls -la lib/  # Verify files exist
```

**Permission denied**:
```bash
chmod +x victim attacker  # Make executables
```

**High cache miss rates**:
- System may have cache isolation enabled
- Try running with elevated privileges
- Check if CPU supports `clflush` instruction

**Victim process fails**:
```bash
LD_LIBRARY_PATH=./lib ldd victim  # Check library dependencies
```

## 🤝 **Contributing**

To extend this demonstration:
1. Fork and modify the source code
2. Add new attack techniques or target algorithms
3. Improve statistical analysis and visualization
4. Document findings and countermeasures

## 📄 **License**

This demonstration code is provided for educational purposes. The libgcrypt library is licensed under LGPL. Use responsibly and in accordance with applicable laws and institutional policies.

---

**Built with libgcrypt 1.4.6** | **Demo created for x86_64 Linux** | **Educational use only**