#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <time.h>
#include "gcrypt.h"

volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

int main() {
    gcry_error_t err;
    gcry_sexp_t rsa_keypair, rsa_pubkey, rsa_privkey;
    gcry_sexp_t data_sexp, encrypted_sexp, decrypted_sexp;
    gcry_mpi_t message, ciphertext, plaintext;
    size_t len;
    char *buffer;

    printf("RSA Victim process starting (PID: %d)\n", getpid());

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return 1;
    }

    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    printf("RSA Victim: Generating 1024-bit RSA keypair...\n");

    // Generate RSA keypair
    err = gcry_sexp_build(&rsa_keypair, NULL, "(genkey (rsa (nbits 4:1024)))");
    if (err) {
        fprintf(stderr, "Failed to build RSA genkey s-expression: %s\n", gcry_strerror(err));
        return 1;
    }

    gcry_sexp_t keypair;
    err = gcry_pk_genkey(&keypair, rsa_keypair);
    if (err) {
        fprintf(stderr, "Failed to generate RSA keypair: %s\n", gcry_strerror(err));
        gcry_sexp_release(rsa_keypair);
        return 1;
    }

    // Extract public and private keys
    rsa_pubkey = gcry_sexp_find_token(keypair, "public-key", 0);
    rsa_privkey = gcry_sexp_find_token(keypair, "private-key", 0);

    if (!rsa_pubkey || !rsa_privkey) {
        fprintf(stderr, "Failed to extract RSA keys\n");
        gcry_sexp_release(keypair);
        gcry_sexp_release(rsa_keypair);
        return 1;
    }

    printf("RSA Victim: Keypair generated successfully\n");
    printf("RSA Victim: Starting RSA encryption/decryption loop...\n");
    printf("RSA Victim: This will trigger square-and-multiply operations\n");
    printf("RSA Victim: Press Ctrl+C to stop\n");

    // Prepare test message
    const char *test_msg = "Hello, RSA World! This is a test message for side-channel analysis.";

    // Create message as MPI for direct RSA operations
    err = gcry_sexp_build(&data_sexp, NULL, "(data (flags raw) (value %s))", test_msg);
    if (err) {
        fprintf(stderr, "Failed to build data s-expression: %s\n", gcry_strerror(err));
        return 1;
    }

    // RSA ENCRYPTION (triggers modular exponentiation with public exponent)
    err = gcry_pk_encrypt(&encrypted_sexp, data_sexp, rsa_pubkey);
    if (err) {
        fprintf(stderr, "RSA encryption failed: %s\n", gcry_strerror(err));
        gcry_sexp_release(data_sexp);
        return 1;
    }

    int iteration = 0;
    while (running) {
        // RSA DECRYPTION (triggers modular exponentiation with private exponent)
        // This is the critical operation that exposes the private key bits
        err = gcry_pk_decrypt(&decrypted_sexp, encrypted_sexp, rsa_privkey);
        if (err) {
            fprintf(stderr, "RSA decryption failed: %s\n", gcry_strerror(err));
            gcry_sexp_release(data_sexp);
            gcry_sexp_release(encrypted_sexp);
            break;
        }

        // Clean up for this iteration
        gcry_sexp_release(decrypted_sexp);

        iteration++;
        if (iteration % 100 == 0) {
            printf("RSA Victim: Completed %d RSA encryption/decryption cycles\n", iteration);
        }

        // Slightly longer delay between operations for better attack stability
        usleep(1000);
    }

    // Cleanup
    gcry_sexp_release(data_sexp);
    gcry_sexp_release(encrypted_sexp);
    gcry_sexp_release(rsa_pubkey);
    gcry_sexp_release(rsa_privkey);
    gcry_sexp_release(keypair);
    gcry_sexp_release(rsa_keypair);

    printf("RSA Victim: Exiting after %d iterations\n", iteration);
    return 0;
}
