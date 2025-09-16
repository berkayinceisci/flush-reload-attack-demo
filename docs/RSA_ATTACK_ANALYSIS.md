# RSA Key Recovery Attack Analysis

## Attack Overview

This implementation demonstrates a **Flush+Reload cache side-channel attack** specifically targeting RSA's square-and-multiply modular exponentiation algorithm. Unlike the generic AES cache attack, this attack directly targets the mathematical operations that expose private key bits.

## RSA Square-and-Multiply Algorithm

### How RSA Decryption Works
RSA decryption computes: `m = c^d mod n`

Where:
- `c` = ciphertext
- `d` = private key exponent
- `n` = modulus
- `m` = plaintext message

### Square-and-Multiply Implementation

The algorithm processes the private key `d` bit by bit:

```
result = 1
for each bit i in private key d (from MSB to LSB):
    result = result² mod n        // Square operation (always)
    if bit i == 1:
        result = result * c mod n // Multiply operation (conditional)
```

### Cache Attack Target

**Key Insight**: The multiply operation only occurs when processing a '1' bit in the private key.

**Attack Pattern**:
- **Bit = 0**: Square-Reduce only
- **Bit = 1**: Square-Reduce-Multiply-Reduce

By monitoring cache access to these operations, an attacker can recover the private key bit-by-bit.

## Implementation Details

### Targeted Functions

1. **`_gcry_mpih_sqr_n_basecase`** - Square operation
   - Always executed for every bit
   - High cache hit rate expected

2. **`_gcry_mpih_mul`** - Multiply operation
   - Only executed for '1' bits
   - Hit rate correlates with key bit values

3. **Modular Reduction** - Reduction operation
   - Executed after each square/multiply
   - Always present

### Attack Process

1. **Function Location**: Use `dlsym()` to find target functions in shared library
2. **Cache Flush**: Evict target cache lines using `clflush`
3. **Victim Execution**: Wait for RSA operations (100μs window)
4. **Cache Probe**: Measure access time with `rdtsc`
5. **Pattern Analysis**: Classify operations based on timing

### Timing Thresholds

- **Cache Hit**: < 200 CPU cycles
- **Cache Miss**: > 200 CPU cycles (main memory access)

## Mathematical Foundation

### Private Key Structure

1024-bit RSA private key example:
```
d = 1011010110...  (binary representation)
    ||||||||++--- Bit positions 0-7
    ||||||++------ Bit positions 8-15
    ...
```

### Execution Trace Analysis

For private key bits `1011`:

```
Bit 1 (MSB): result = result² mod n; result = result * c mod n  [Square+Multiply]
Bit 0:       result = result² mod n                             [Square only]
Bit 1:       result = result² mod n; result = result * c mod n  [Square+Multiply]
Bit 1 (LSB): result = result² mod n; result = result * c mod n  [Square+Multiply]
```

## Security Implications

### Real-World Impact

This attack demonstrates:
- **RSA implementations** vulnerable to side-channel analysis
- **Shared libraries** create attack surfaces
- **Cache isolation** critical for cryptographic security
- **Constant-time implementations** necessary

### Attack Scalability

- **Cross-process**: Works without privileged access
- **Remote timing**: Potentially exploitable over networks
- **Key recovery**: Full private key extraction possible
- **Implementation agnostic**: Targets mathematical operations
