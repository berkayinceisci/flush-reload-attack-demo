# Technical Details - Cache Side-Channel Attack

## Attack Architecture

### Memory Layout
```
┌─────────────────────────────────────────────────┐
│                  Physical RAM                   │
├─────────────────────────────────────────────────┤
│              Shared L3 Cache                    │
├─────────────────────────────────────────────────┤
│    Core 0        │        Core 1               │
│  ┌─────────┐    │      ┌─────────┐             │
│  │ L1/L2   │    │      │ L1/L2   │             │
│  │ Cache   │    │      │ Cache   │             │
│  └─────────┘    │      └─────────┘             │
│     │           │          │                   │
│  [Victim]       │      [Attacker]              │
└─────────────────────────────────────────────────┘
```

### Attack Flow
1. **Library Mapping**: Both processes map the same libgcrypt.so shared library
2. **Function Location**: Attacker locates AES encryption function via `dlsym()`
3. **Cache Line Monitoring**: Target 16 cache lines (64 bytes each) around function
4. **Flush Phase**: Use `clflush` to evict monitored lines from all cache levels
5. **Execution Phase**: Victim performs AES operations, potentially loading flushed lines
6. **Reload Phase**: Measure memory access time using `rdtsc` instruction
7. **Classification**: Times < 200 cycles indicate cache hit (victim accessed line)

## CPU Instructions Used

### CLFLUSH - Cache Line Flush
```c
static inline void flush_cache_line(void* addr) {
    asm volatile ("clflush (%0)" : : "r" (addr) : "memory");
}
```
- **Purpose**: Invalidate cache line containing specified address
- **Scope**: Affects all cache levels (L1, L2, L3)
- **Privilege**: Available in user mode
- **Serialization**: Not serializing, requires memory barrier

### RDTSC - Read Time-Stamp Counter
```c
static inline uint64_t rdtsc() {
    uint32_t low, high;
    asm volatile ("rdtsc" : "=a" (low), "=d" (high));
    return ((uint64_t)high << 32) | low;
}
```
- **Purpose**: High-precision cycle counter
- **Resolution**: CPU cycle level (~0.3ns @ 3GHz)
- **Privilege**: User mode accessible
- **Ordering**: May execute out-of-order, requires barriers

### MFENCE - Memory Fence
```c
static inline void memory_barrier() {
    asm volatile ("mfence" : : : "memory");
}
```
- **Purpose**: Serialize memory operations
- **Effect**: Ensures all prior loads/stores complete before continuing
- **Usage**: Prevents RDTSC reordering around memory accesses

## Timing Characteristics

### Cache Hit vs Miss Times (Typical x86_64)
| Location | Access Time | Cycles | Nanoseconds |
|----------|-------------|--------|-------------|
| L1 Cache | ~1 cycle | 1 | 0.3 |
| L2 Cache | ~3-4 cycles | 4 | 1.3 |
| L3 Cache | ~12-15 cycles | 15 | 5.0 |
| Main RAM | ~200+ cycles | 300 | 100+ |

### Threshold Selection
- **Conservative**: 200 cycles (clearly distinguishes RAM from cache)
- **Aggressive**: 50 cycles (distinguishes L3 from RAM)
- **System-dependent**: Varies by CPU model, frequency scaling, system load

## Statistical Analysis

### Measurement Collection
```c
for (int i = 0; i < NUM_MEASUREMENTS; i++) {
    // Flush all monitored cache lines
    for (int j = 0; j < NUM_ADDRESSES; j++) {
        flush_cache_line(monitored_addresses[j]);
    }

    usleep(OBSERVATION_WINDOW);  // Let victim execute

    // Measure reload times
    for (int j = 0; j < NUM_ADDRESSES; j++) {
        uint64_t time = time_memory_access(monitored_addresses[j]);
        if (time < THRESHOLD) {
            cache_hits[j]++;
        }
    }
}
```

### Hit Rate Calculation
```
Hit Rate = (Number of Cache Hits) / (Total Measurements) * 100%
```

### Classification Rules
- **Active Code Path**: Hit rate > 95%
- **Occasional Use**: Hit rate 10-95%
- **Unused Code**: Hit rate < 10%

## libgcrypt Function Analysis

### Target Function: gcry_cipher_encrypt
```c
// Simplified call flow:
gcry_cipher_encrypt()
├── _gcry_cipher_encrypt()
├── rijndael_encrypt()          // AES implementation
│   ├── do_encrypt()           // Main encryption loop
│   │   ├── S-box lookups      // Key-dependent memory access
│   │   ├── MixColumns()       // Table-based operations
│   │   └── AddRoundKey()      // XOR operations
│   └── key_schedule()         // Subkey generation
```

### Memory Access Patterns
1. **Code Execution**: Sequential instruction fetches
2. **S-box Lookups**: Key-dependent table accesses
3. **State Arrays**: Block cipher internal state
4. **Round Keys**: Derived key material

## Attack Variations

### Prime+Probe
- **Method**: Fill cache sets, let victim execute, measure eviction
- **Advantage**: No shared memory required
- **Disadvantage**: Lower resolution, more noise

### Evict+Time
- **Method**: Evict victim's data, measure victim's execution time
- **Advantage**: Direct timing measurement
- **Disadvantage**: Requires victim cooperation

### Branch Prediction Attacks
- **Method**: Train branch predictors, observe misprediction patterns
- **Target**: Conditional branches in cryptographic code
- **Detection**: Via timing or performance counters

## Countermeasure Evaluation

### Constant-Time Implementation
```c
// Vulnerable: Key-dependent branch
if (key[i] & 1) {
    sbox_lookup_1();
} else {
    sbox_lookup_2();
}

// Secure: Constant-time selection
int selector = key[i] & 1;
result = (selector * sbox_1[index]) + ((1-selector) * sbox_2[index]);
```

### Cache Line Randomization
```c
// Add random offset to break alignment
void* aligned_alloc_random(size_t size) {
    void* base = malloc(size + CACHE_LINE_SIZE);
    uintptr_t offset = rand() % CACHE_LINE_SIZE;
    return (void*)((uintptr_t)base + offset);
}
```

### Execution Time Normalization
```c
// Add random delay to constant total time
void normalize_execution_time(uint64_t target_cycles) {
    uint64_t start = rdtsc();
    // ... perform crypto operation ...
    uint64_t elapsed = rdtsc() - start;
    if (elapsed < target_cycles) {
        busy_wait(target_cycles - elapsed);
    }
}
```

## Platform Considerations

### Intel x86_64
- **Cache Levels**: L1D/L1I (32KB), L2 (256KB), L3 (8MB+)
- **Cache Line Size**: 64 bytes
- **Coherency**: MESI protocol
- **Special Instructions**: CLFLUSH, CLFLUSHOPT, CLWB

### AMD x86_64
- **Cache Levels**: L1D/L1I (32KB), L2 (512KB), L3 (varies)
- **Cache Line Size**: 64 bytes
- **Differences**: Slightly different timing characteristics

### ARM64
- **Cache Instructions**: DC CIVAC (clean and invalidate)
- **Timing**: CNTVCT_EL0 counter
- **Privilege**: Some operations require kernel access

## Research Applications

### Academic Studies
- **Key Recovery**: Full AES key extraction from cache patterns
- **Algorithm Recognition**: Identifying cryptographic algorithms in use
- **Cross-VM Attacks**: Cloud environment security analysis
- **Browser Security**: JavaScript-based cache attacks

### Real-World Examples
- **CVE-2016-0703**: OpenSSL cache timing attack
- **CVE-2018-0734**: RSA cache attacks in OpenSSL
- **Spectre/Meltdown**: Microarchitectural side channels

## Performance Impact

### Victim Process
- **CPU Usage**: ~5-10% overhead from frequent crypto operations
- **Memory**: Minimal additional allocation
- **I/O**: Status output every 10K operations

### Attacker Process
- **CPU Usage**: ~20-30% for timing measurements and analysis
- **Memory**: Small arrays for storing timing data
- **Precision**: Microsecond-level measurement intervals

### System Impact
- **Cache Pollution**: Frequent flushes may affect system performance
- **CPU Contention**: Both processes compete for CPU time
- **Measurement Accuracy**: System load affects timing precision