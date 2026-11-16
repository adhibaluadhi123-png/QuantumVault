#include "crypto.h"

int32_t crypto_add(int32_t a, int32_t b) {
    return a + b;
}

// Practice function for C buffer handling
int32_t crypto_xor_buffer(
    uint8_t *data,
    size_t len,
    uint8_t key
) {
    if (data == NULL && len > 0) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }

    return 0;
}
