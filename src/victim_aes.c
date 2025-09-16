#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include "gcrypt.h"

volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

int main() {
    gcry_error_t err;
    gcry_cipher_hd_t handle;
    char key[16] = "0123456789ABCDEF";
    char plaintext[16] = "Hello, World!!!!";
    char ciphertext[16];
    char decrypted[16];
    size_t len = 16;

    printf("Victim process starting (PID: %d)\n", getpid());

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return 1;
    }

    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    err = gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0);
    if (err) {
        fprintf(stderr, "Failed to create cipher handle: %s\n", gcry_strerror(err));
        return 1;
    }

    err = gcry_cipher_setkey(handle, key, 16);
    if (err) {
        fprintf(stderr, "Failed to set key: %s\n", gcry_strerror(err));
        gcry_cipher_close(handle);
        return 1;
    }

    printf("Victim: Starting AES encryption loop...\n");
    printf("Victim: Press Ctrl+C to stop\n");

    int iteration = 0;
    while (running) {
        memcpy(ciphertext, plaintext, len);

        err = gcry_cipher_encrypt(handle, ciphertext, len, NULL, 0);
        if (err) {
            fprintf(stderr, "Encryption failed: %s\n", gcry_strerror(err));
            break;
        }

        memcpy(decrypted, ciphertext, len);
        err = gcry_cipher_decrypt(handle, decrypted, len, NULL, 0);
        if (err) {
            fprintf(stderr, "Decryption failed: %s\n", gcry_strerror(err));
            break;
        }

        iteration++;
        if (iteration % 10000 == 0) {
            printf("Victim: Completed %d encryption/decryption cycles\n", iteration);
        }

        usleep(100);
    }

    gcry_cipher_close(handle);
    printf("Victim: Exiting after %d iterations\n", iteration);
    return 0;
}