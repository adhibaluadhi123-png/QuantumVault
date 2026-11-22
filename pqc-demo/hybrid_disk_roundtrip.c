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
    if (plain_len > INT_MAX || RAND_bytes(nonce, NONCE_LEN) != 1)
        return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0, total = 0;
    int ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            NONCE_LEN, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plain_len) == 1;

    total = len;
    if (ok) ok = EVP_EncryptFinal_ex(ctx, cipher + total, &len) == 1;
    total += len;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                 TAG_LEN, tag) == 1;

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
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            NONCE_LEN, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len) == 1;

    total = len;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 TAG_LEN, (void *)tag) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, plain + total, &len) == 1;
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return ok && (size_t)total == cipher_len;
}

int main(void)
{
    const char *container_path = "c_disk_roundtrip.qv";
    const char *recovered_path = "c_disk_recovered.txt";

    const uint8_t original[] =
        "QuantumVault disk-based hybrid encryption round-trip test.\n";
    const size_t original_len = sizeof(original) - 1;

    int result = EXIT_FAILURE;
    OQS_KEM *kem = NULL;

    uint8_t *public_key = NULL, *secret_key = NULL;
    uint8_t *kem_ciphertext = NULL, *shared_secret = NULL;
    uint8_t *disk_kem_ciphertext = NULL;
    uint8_t *ciphertext = NULL, *disk_ciphertext = NULL;
    uint8_t *recovered = NULL, *wrong_output = NULL;

    uint8_t key[KEY_LEN] = {0}, recovered_key[KEY_LEN] = {0};
    uint8_t wrong_key[KEY_LEN] = {0};
    uint8_t nonce[NONCE_LEN] = {0}, tag[TAG_LEN] = {0};
    uint8_t disk_nonce[NONCE_LEN] = {0}, disk_tag[TAG_LEN] = {0};

    FILE *file = NULL;
    long file_size = 0;
    size_t disk_cipher_len = 0;

    printf("=== QUANTUMVAULT DISK ROUND-TRIP TEST ===\n");

    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        fprintf(stderr, "ERROR: ML-KEM-768 unavailable.\n");
        goto cleanup;
    }

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    kem_ciphertext = malloc(kem->length_ciphertext);
    disk_kem_ciphertext = malloc(kem->length_ciphertext);
    shared_secret = malloc(kem->length_shared_secret);
    ciphertext = malloc(original_len + 16);
    recovered = calloc(original_len + 1, 1);
    wrong_output = calloc(original_len + 1, 1);

    if (!public_key || !secret_key || !kem_ciphertext ||
        !disk_kem_ciphertext || !shared_secret || !ciphertext ||
        !recovered || !wrong_output) {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        goto cleanup;
    }

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS ||
        OQS_KEM_encaps(kem, kem_ciphertext, shared_secret,
                       public_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: ML-KEM operation failed.\n");
        goto cleanup;
    }
    printf("PASS: ML-KEM-768 keypair and encapsulation.\n");

    if (!derive_key(shared_secret, kem->length_shared_secret, key)) {
        fprintf(stderr, "ERROR: HKDF derivation failed.\n");
        goto cleanup;
    }

    if (!aes_encrypt(original, original_len, key, nonce,
                     ciphertext, tag)) {
        fprintf(stderr, "ERROR: AES-GCM encryption failed.\n");
        goto cleanup;
    }
    printf("PASS: File encrypted using AES-256-GCM.\n");

    /* Save the complete container to disk. */
    file = fopen(container_path, "wb");
    if (!file) {
        fprintf(stderr, "ERROR: Cannot create container.\n");
        goto cleanup;
    }

  int write_ok =
        fwrite(MAGIC, 1, 8, file) == 8 &&
        fwrite(kem_ciphertext, 1, kem->length_ciphertext, file)
            == kem->length_ciphertext &&
        fwrite(nonce, 1, NONCE_LEN, file) == NONCE_LEN &&
        fwrite(tag, 1, TAG_LEN, file) == TAG_LEN &&
        fwrite(ciphertext, 1, original_len, file) == original_len;

    if (fclose(file) != 0) write_ok = 0;
    file = NULL;

    if (!write_ok) {
        fprintf(stderr, "ERROR: Container write failed.\n");
        goto cleanup;
    }
    printf("PASS: Encrypted container written to disk.\n");

    /* Reopen and parse the container from disk. */
    file = fopen(container_path, "rb");
    if (!file) {
        fprintf(stderr, "ERROR: Cannot reopen container.\n");
        goto cleanup;
    }

    char magic[8];
    if (fread(magic, 1, 8, file) != 8 ||
        memcmp(magic, MAGIC, 8) != 0) {
        fprintf(stderr, "ERROR: Invalid container header.\n");
        goto cleanup;
    }

    if (fread(disk_kem_ciphertext, 1, kem->length_ciphertext, file)
            != kem->length_ciphertext ||
        fread(disk_nonce, 1, NONCE_LEN, file) != NONCE_LEN ||
        fread(disk_tag, 1, TAG_LEN, file) != TAG_LEN) {
        fprintf(stderr, "ERROR: Container metadata is incomplete.\n");
        goto cleanup;
    }

    if (fseek(file, 0, SEEK_END) != 0 ||
        (file_size = ftell(file)) < 0) {
        fprintf(stderr, "ERROR: Cannot determine container size.\n");
        goto cleanup;
    }

    long header_size = 8 + (long)kem->length_ciphertext +
                       NONCE_LEN + TAG_LEN;

    if (file_size < header_size ||
        fseek(file, header_size, SEEK_SET) != 0) {
        fprintf(stderr, "ERROR: Invalid container size.\n");
        goto cleanup;
    }

    disk_cipher_len = (size_t)(file_size - header_size);
    if (disk_cipher_len != original_len) {
        fprintf(stderr, "ERROR: Unexpected ciphertext length.\n");
        goto cleanup;
    }

    disk_ciphertext = malloc(disk_cipher_len + 1);
    if (!disk_ciphertext) {
        fprintf(stderr, "ERROR: Disk ciphertext allocation failed.\n");
        goto cleanup;
    }

    if (fread(disk_ciphertext, 1, disk_cipher_len, file)
            != disk_cipher_len) {
        fprintf(stderr, "ERROR: Cannot read ciphertext from disk.\n");
        goto cleanup;
    }

    if (fclose(file) != 0) {
        file = NULL;
        fprintf(stderr, "ERROR: Container close failed.\n");
        goto cleanup;
    }
    file = NULL;
    printf("PASS: Container reopened and ciphertext read from disk.\n");

    /* Recover the shared secret using the recipient's private key. */
    if (OQS_KEM_decaps(kem, shared_secret, disk_kem_ciphertext,
                       secret_key) != OQS_SUCCESS ||
        !derive_key(shared_secret, kem->length_shared_secret,
                    recovered_key)) {
        fprintf(stderr, "ERROR: Recipient key recovery failed.\n");
        goto cleanup;
    }

    if (!aes_decrypt(disk_ciphertext, disk_cipher_len, recovered_key,
                     disk_nonce, disk_tag, recovered)) {
        fprintf(stderr, "ERROR: Disk-based decryption failed.\n");
        goto cleanup;
    }

if (memcmp(original, recovered, original_len) != 0) {
        fprintf(stderr, "ERROR: Recovered data does not match original.\n");
        goto cleanup;
    }
    printf("PASS: Disk-based recipient decryption.\n");
    printf("PASS: Original and recovered data match.\n");

    if (RAND_bytes(wrong_key, KEY_LEN) != 1) {
        fprintf(stderr, "ERROR: Wrong-key generation failed.\n");
        goto cleanup;
    }

    if (aes_decrypt(disk_ciphertext, disk_cipher_len, wrong_key,
                    disk_nonce, disk_tag, wrong_output)) {
        fprintf(stderr, "ERROR: Wrong key unexpectedly decrypted data.\n");
        goto cleanup;
    }
    printf("PASS: Wrong key rejected after disk read.\n");

    file = fopen(recovered_path, "wb");
    if (!file ||
        fwrite(recovered, 1, original_len, file) != original_len) {
        fprintf(stderr, "ERROR: Cannot save recovered file.\n");
        goto cleanup;
    }

    if (fclose(file) != 0) {
        file = NULL;
        fprintf(stderr, "ERROR: Recovered file close failed.\n");
        goto cleanup;
    }
    file = NULL;

    printf("Recovered file: %s\n", recovered_path);
    printf("Encrypted container: %s\n", container_path);
    printf("\nDISK ROUND-TRIP TEST PASSED.\n");
    result = EXIT_SUCCESS;

cleanup:
    if (file) fclose(file);

    if (secret_key)
        OQS_MEM_cleanse(secret_key, kem ? kem->length_secret_key : 0);
    if (shared_secret)
        OQS_MEM_cleanse(shared_secret,
                        kem ? kem->length_shared_secret : 0);

    OQS_MEM_cleanse(key, sizeof(key));
    OQS_MEM_cleanse(recovered_key, sizeof(recovered_key));
    OQS_MEM_cleanse(wrong_key, sizeof(wrong_key));

    free(public_key);
    free(secret_key);
    free(kem_ciphertext);
    free(disk_kem_ciphertext);
    free(shared_secret);
    free(ciphertext);
    free(disk_ciphertext);
    free(recovered);
    free(wrong_output);
    OQS_KEM_free(kem);

    return result;
}
