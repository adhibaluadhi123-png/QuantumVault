#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* Existing FFI practice functions */
int32_t crypto_add(int32_t a, int32_t b);

int32_t crypto_xor_buffer(
    uint8_t *data,
    size_t len,
    uint8_t key
);

/* ML-KEM-768 status codes */
#define CRYPTO_SUCCESS 0
#define CRYPTO_ERROR_NULL_POINTER -1
#define CRYPTO_ERROR_INVALID_LENGTH -2
#define CRYPTO_ERROR_UNAVAILABLE -3
#define CRYPTO_ERROR_OPERATION_FAILED -4

/* Retrieve ML-KEM-768 buffer sizes */
int32_t crypto_mlkem768_get_sizes(
    size_t *public_key_len,
    size_t *secret_key_len,
    size_t *ciphertext_len,
    size_t *shared_secret_len
);

/* Generate ML-KEM-768 keypair */
int32_t crypto_mlkem768_keypair(
    uint8_t *public_key,
    size_t public_key_len,
    uint8_t *secret_key,
    size_t secret_key_len
);

/* Encapsulate using the public key */
int32_t crypto_mlkem768_encapsulate(
    uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *public_key,
    size_t public_key_len
);

/* Decapsulate using the secret key */
int32_t crypto_mlkem768_decapsulate(
    uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *secret_key,
    size_t secret_key_len
);

/* Clear sensitive memory */
void crypto_secure_cleanse(uint8_t *data, size_t len);

#endif
