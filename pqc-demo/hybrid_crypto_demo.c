#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16
#define MAGIC "QVHC0001"

static int derive_key(const uint8_t *secret, size_t secret_len,
                      uint8_t key[KEY_LEN])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return 0;

    int ok =
        EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx,
            (const unsigned char *)"QuantumVault", 12) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (int)secret_len) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx,
            (const unsigned char *)"FileEncryption", 14) > 0;

    size_t len = KEY_LEN;
    if (ok)
        ok = EVP_PKEY_derive(ctx, key, &len) > 0 && len == KEY_LEN;

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int aes_encrypt(const uint8_t *plain, size_t plain_len,
                       const uint8_t key[KEY_LEN],
                       uint8_t nonce[NONCE_LEN],
                       uint8_t *cipher, uint8_t tag[TAG_LEN])
{
    if (plain_len > INT_MAX) return 0;
    if (RAND_bytes(nonce, NONCE_LEN) != 1) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0, total = 0;
    int ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plain_len) == 1;

    total = len;
    if (ok) ok = EVP_EncryptFinal_ex(ctx, cipher + total, &len) == 1;
    total += len;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) == 1;

    EVP_CIPHER_CTX_free(ctx);
    return ok && (size_t)total == plain_len;
}

static int aes_decrypt(const uint8_t *cipher, size_t cipher_len,
                       const uint8_t key[KEY_LEN],
                       const uint8_t nonce[NONCE_LEN],
                       const uint8_t tag[TAG_LEN],
                       uint8_t *plain)
{
    if (cipher_len > INT_MAX) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0, total = 0;
    int ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len) == 1;

    total = len;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                 (void *)tag) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, plain + total, &len) == 1;
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return ok && (size_t)total == cipher_len;
}

static uint8_t *read_file(const char *path, size_t *size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }

    long n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    uint8_t *data = malloc((size_t)n + 1);
    if (!data) {
        fclose(f);
        return NULL;
    }

    if (fread(data, 1, (size_t)n, f) != (size_t)n) {
        free(data);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *size = (size_t)n;
    return data;
}

static int write_file(const char *path, const uint8_t *data, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) return 0;

    int ok = fwrite(data, 1, size, f) == size;
    if (fclose(f) != 0) ok = 0;
    return ok;
}

int main(void)
{
    int result = EXIT_FAILURE;
    OQS_KEM *kem = NULL;

    uint8_t *public_key = NULL, *secret_key = NULL;
    uint8_t *kem_ciphertext = NULL;
    uint8_t *shared_enc = NULL, *shared_dec = NULL;
    uint8_t key_enc[KEY_LEN] = {0}, key_dec[KEY_LEN] = {0};
    uint8_t wrong_key[KEY_LEN] = {0};
    uint8_t nonce[NONCE_LEN] = {0}, tag[TAG_LEN] = {0};

    uint8_t *message_cipher = NULL, *message_recovered = NULL;
    uint8_t *plain = NULL, *file_cipher = NULL, *file_recovered = NULL;
    uint8_t *wrong_key_output = NULL;
    size_t plain_len = 0;

    const char *input_path = "c_demo_input.txt";
    const char *encrypted_path = "c_demo_encrypted.qv";
    const char *recovered_path = "c_demo_recovered.txt";

    printf("=== QUANTUMVAULT C HYBRID ENCRYPTION DEMO ===\n");

    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        fprintf(stderr, "ERROR: ML-KEM-768 unavailable.\n");
        goto cleanup;
    }

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    kem_ciphertext = malloc(kem->length_ciphertext);
    shared_enc = malloc(kem->length_shared_secret);
    shared_dec = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !kem_ciphertext ||
        !shared_enc || !shared_dec) {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        goto cleanup;
    }

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Keypair generation failed.\n");
        goto cleanup;
    }
    printf("PASS: ML-KEM-768 keypair generated in C.\n");

    if (OQS_KEM_encaps(kem, kem_ciphertext, shared_enc, public_key) != OQS_SUCCESS ||
        OQS_KEM_decaps(kem, shared_dec, kem_ciphertext, secret_key) != OQS_SUCCESS ||
        memcmp(shared_enc, shared_dec, kem->length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: ML-KEM encapsulation/decapsulation failed.\n");
        goto cleanup;
    }
    printf("PASS: ML-KEM shared secrets match.\n");

    if (!derive_key(shared_enc, kem->length_shared_secret, key_enc) ||
        !derive_key(shared_dec, kem->length_shared_secret, key_dec)) {
        fprintf(stderr, "ERROR: HKDF key derivation failed.\n");
        goto cleanup;
    }
    printf("PASS: HKDF-SHA256 derived AES-256 keys.\n");

    /* Short-string encryption and decryption */
    const uint8_t message[] = "QuantumVault C encryption test";
    size_t message_len = sizeof(message) - 1;

    message_cipher = malloc(message_len + 16);
    message_recovered = calloc(message_len + 1, 1);
    if (!message_cipher || !message_recovered) goto cleanup;

    uint8_t message_nonce[NONCE_LEN], message_tag[TAG_LEN];

    if (!aes_encrypt(message, message_len, key_enc, message_nonce,
                     message_cipher, message_tag) ||
        !aes_decrypt(message_cipher, message_len, key_dec, message_nonce,
                     message_tag, message_recovered) ||
        memcmp(message, message_recovered, message_len) != 0) {
        fprintf(stderr, "ERROR: Short-string encryption/decryption failed.\n");
        goto cleanup;
    }
    printf("PASS: C short-string AES-256-GCM encryption/decryption.\n");

    /* Create sample input file */
    const char file_text[] =
        "QuantumVault confidential file encrypted by C using ML-KEM-768 and AES-256-GCM.\n";

    if (!write_file(input_path, (const uint8_t *)file_text, sizeof(file_text) - 1)) {
        fprintf(stderr, "ERROR: Could not create input file.\n");
        goto cleanup;
    }

    plain = read_file(input_path, &plain_len);
    if (!plain) {
        fprintf(stderr, "ERROR: Could not read input file.\n");
        goto cleanup;
    }

    file_cipher = malloc(plain_len + 16);
    file_recovered = calloc(plain_len + 1, 1);
    wrong_key_output = calloc(plain_len + 1, 1);
    if (!file_cipher || !file_recovered || !wrong_key_output) goto cleanup;

    if (!aes_encrypt(plain, plain_len, key_enc, nonce, file_cipher, tag)) {
        fprintf(stderr, "ERROR: File encryption failed.\n");
        goto cleanup;
    }

    /* Write encrypted container */
    FILE *out = fopen(encrypted_path, "wb");
    if (!out) {
        fprintf(stderr, "ERROR: Cannot create encrypted file.\n");
        goto cleanup;
    }

    int write_ok =
        fwrite(MAGIC, 1, 8, out) == 8 &&
        fwrite(kem_ciphertext, 1, kem->length_ciphertext, out) == kem->length_ciphertext &&
        fwrite(nonce, 1, NONCE_LEN, out) == NONCE_LEN &&
        fwrite(tag, 1, TAG_LEN, out) == TAG_LEN &&
        fwrite(file_cipher, 1, plain_len, out) == plain_len;

    if (fclose(out) != 0) write_ok = 0;
    if (!write_ok) {
        fprintf(stderr, "ERROR: Writing encrypted container failed.\n");
        goto cleanup;
    }
    printf("PASS: File encrypted in C using ML-KEM-768 + AES-256-GCM.\n");

    /* Recipient decapsulates the KEM ciphertext */
    uint8_t *recovered_secret = malloc(kem->length_shared_secret);
    uint8_t recovered_key[KEY_LEN] = {0};

    if (!recovered_secret ||
        OQS_KEM_decaps(kem, recovered_secret, kem_ciphertext, secret_key) != OQS_SUCCESS ||
        !derive_key(recovered_secret, kem->length_shared_secret, recovered_key)) {
        if (recovered_secret) {
            OQS_MEM_cleanse(recovered_secret, kem->length_shared_secret);
            free(recovered_secret);
        }
        fprintf(stderr, "ERROR: Recipient key recovery failed.\n");
        goto cleanup;
    }

    int decrypt_ok = aes_decrypt(file_cipher, plain_len, recovered_key,
                                 nonce, tag, file_recovered);

    /* A wrong AES key must fail GCM authentication. */
    if (RAND_bytes(wrong_key, sizeof(wrong_key)) != 1) {
        OQS_MEM_cleanse(recovered_secret, kem->length_shared_secret);
        free(recovered_secret);
        OQS_MEM_cleanse(recovered_key, sizeof(recovered_key));
        fprintf(stderr, "ERROR: Could not generate wrong test key.\n");
        goto cleanup;
    }

    int wrong_key_decrypt_ok = aes_decrypt(
        file_cipher, plain_len, wrong_key, nonce, tag, wrong_key_output);

    OQS_MEM_cleanse(recovered_secret, kem->length_shared_secret);
    free(recovered_secret);
    OQS_MEM_cleanse(recovered_key, sizeof(recovered_key));

    if (!decrypt_ok || memcmp(plain, file_recovered, plain_len) != 0) {
        fprintf(stderr, "ERROR: File decryption or comparison failed.\n");
        goto cleanup;
    }

    if (wrong_key_decrypt_ok) {
        fprintf(stderr, "ERROR: Wrong key unexpectedly decrypted the file.\n");
        goto cleanup;
    }
    printf("PASS: Wrong AES key rejected by GCM authentication.\n");

    if (!write_file(recovered_path, file_recovered, plain_len)) {
        fprintf(stderr, "ERROR: Could not write recovered file.\n");
        goto cleanup;
    }

    printf("PASS: Recipient decrypted file successfully.\n");
    printf("PASS: Original and recovered file contents match.\n");
    printf("Encrypted file: %s\n", encrypted_path);
    printf("Recovered file: %s\n", recovered_path);
    printf("\nC HYBRID ENCRYPTION DEMO PASSED.\n");

    result = EXIT_SUCCESS;

cleanup:
    if (secret_key) OQS_MEM_cleanse(secret_key, kem ? kem->length_secret_key : 0);
    if (shared_enc) OQS_MEM_cleanse(shared_enc, kem ? kem->length_shared_secret : 0);
    if (shared_dec) OQS_MEM_cleanse(shared_dec, kem ? kem->length_shared_secret : 0);

    OQS_MEM_cleanse(key_enc, sizeof(key_enc));
    OQS_MEM_cleanse(key_dec, sizeof(key_dec));
    OQS_MEM_cleanse(wrong_key, sizeof(wrong_key));

    free(public_key);
    free(secret_key);
    free(kem_ciphertext);
    free(shared_enc);
    free(shared_dec);
    free(message_cipher);
    free(message_recovered);
    free(plain);
    free(file_cipher);
    free(file_recovered);
    free(wrong_key_output);
    OQS_KEM_free(kem);

    return result;
}
