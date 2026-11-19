#include "crypto.h"
#include <oqs/oqs.h>

/* Existing FFI practice functions */
int32_t crypto_add(int32_t a, int32_t b) {
    return a + b;
}

int32_t crypto_xor_buffer(
    uint8_t *data,
    size_t len,
    uint8_t key
) {
    if (data == NULL && len > 0) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }

    return CRYPTO_SUCCESS;
}

/* Retrieve ML-KEM-768 buffer sizes */
int32_t crypto_mlkem768_get_sizes(
    size_t *public_key_len,
    size_t *secret_key_len,
    size_t *ciphertext_len,
    size_t *shared_secret_len
) {
    if (public_key_len == NULL ||
        secret_key_len == NULL ||
        ciphertext_len == NULL ||
        shared_secret_len == NULL) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == NULL) {
        return CRYPTO_ERROR_UNAVAILABLE;
    }

    *public_key_len = kem->length_public_key;
    *secret_key_len = kem->length_secret_key;
    *ciphertext_len = kem->length_ciphertext;
    *shared_secret_len = kem->length_shared_secret;

    OQS_KEM_free(kem);

    return CRYPTO_SUCCESS;
}

/* Generate ML-KEM-768 keypair */
int32_t crypto_mlkem768_keypair(
    uint8_t *public_key,
    size_t public_key_len,
    uint8_t *secret_key,
    size_t secret_key_len
) {
    if (public_key == NULL || secret_key == NULL) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == NULL) {
        return CRYPTO_ERROR_UNAVAILABLE;
    }

    if (public_key_len != kem->length_public_key ||
        secret_key_len != kem->length_secret_key) {
        OQS_KEM_free(kem);
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    OQS_STATUS status = OQS_KEM_keypair(
        kem,
        public_key,
        secret_key
    );

    OQS_KEM_free(kem);

    if (status != OQS_SUCCESS) {
        OQS_MEM_cleanse(secret_key, secret_key_len);
        return CRYPTO_ERROR_OPERATION_FAILED;
    }

    return CRYPTO_SUCCESS;
}

/* Encapsulation */
int32_t crypto_mlkem768_encapsulate(
    uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *public_key,
    size_t public_key_len
) {
    if (ciphertext == NULL ||
        shared_secret == NULL ||
        public_key == NULL) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == NULL) {
        return CRYPTO_ERROR_UNAVAILABLE;
    }

    if (ciphertext_len != kem->length_ciphertext ||
        shared_secret_len != kem->length_shared_secret ||
        public_key_len != kem->length_public_key) {
        OQS_KEM_free(kem);
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    OQS_STATUS status = OQS_KEM_encaps(
        kem,
        ciphertext,
        shared_secret,
        public_key
    );

    OQS_KEM_free(kem);

    if (status != OQS_SUCCESS) {
        OQS_MEM_cleanse(shared_secret, shared_secret_len);
        return CRYPTO_ERROR_OPERATION_FAILED;
    }

    return CRYPTO_SUCCESS;
}

/* Decapsulation */
int32_t crypto_mlkem768_decapsulate(
    uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *secret_key,
    size_t secret_key_len
) {
    if (shared_secret == NULL ||
        ciphertext == NULL ||
        secret_key == NULL) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == NULL) {
        return CRYPTO_ERROR_UNAVAILABLE;
    }

    if (shared_secret_len != kem->length_shared_secret ||
        ciphertext_len != kem->length_ciphertext ||
        secret_key_len != kem->length_secret_key) {
        OQS_KEM_free(kem);
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    OQS_STATUS status = OQS_KEM_decaps(
        kem,
        shared_secret,
        ciphertext,
        secret_key
    );

    OQS_KEM_free(kem);

    if (status != OQS_SUCCESS) {
        OQS_MEM_cleanse(shared_secret, shared_secret_len);
        return CRYPTO_ERROR_OPERATION_FAILED;
    }

    return CRYPTO_SUCCESS;
}

/* Securely clear sensitive memory */
void crypto_secure_cleanse(uint8_t *data, size_t len) {
    if (data != NULL && len > 0) {
        OQS_MEM_cleanse(data, len);
    }
}
