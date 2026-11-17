#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(void)
{
    const char *algorithm = OQS_KEM_alg_ml_kem_768;

    if (!OQS_KEM_alg_is_enabled(algorithm)) {
        printf("Error: ML-KEM-768 is not enabled.\n");
        return EXIT_FAILURE;
    }

    OQS_KEM *kem = OQS_KEM_new(algorithm);

    if (kem == NULL) {
        printf("Error: Could not initialize ML-KEM-768.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext ||
        !shared_secret_enc || !shared_secret_dec) {
        printf("Error: Memory allocation failed.\n");
        free(public_key);
        free(secret_key);
        free(ciphertext);
        free(shared_secret_enc);
        free(shared_secret_dec);
        OQS_KEM_free(kem);
        return EXIT_FAILURE;
    }

    printf("ML-KEM-768 demonstration started.\n");

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("Error: Key generation failed.\n");
        goto cleanup_failure;
    }

    printf("1. Keypair generation: SUCCESS\n");

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc,
                       public_key) != OQS_SUCCESS) {
        printf("Error: Encapsulation failed.\n");
        goto cleanup_failure;
    }

    printf("2. Encapsulation: SUCCESS\n");

    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext,
                       secret_key) != OQS_SUCCESS) {
        printf("Error: Decapsulation failed.\n");
        goto cleanup_failure;
    }

    printf("3. Decapsulation: SUCCESS\n");

    if (memcmp(shared_secret_enc, shared_secret_dec,
               kem->length_shared_secret) != 0) {
        printf("Error: Shared secrets do not match.\n");
        goto cleanup_failure;
    }

    printf("4. Shared secret verification: SUCCESS\n");
    printf("\nML-KEM-768 TEST PASSED!\n");

    OQS_MEM_cleanse(secret_key, kem->length_secret_key);
    OQS_MEM_cleanse(shared_secret_enc, kem->length_shared_secret);
    OQS_MEM_cleanse(shared_secret_dec, kem->length_shared_secret);

    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    OQS_KEM_free(kem);

    return EXIT_SUCCESS;

cleanup_failure:
    OQS_MEM_cleanse(secret_key, kem->length_secret_key);
    OQS_MEM_cleanse(shared_secret_enc, kem->length_shared_secret);
    OQS_MEM_cleanse(shared_secret_dec, kem->length_shared_secret);

    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    OQS_KEM_free(kem);

    return EXIT_FAILURE;
}
