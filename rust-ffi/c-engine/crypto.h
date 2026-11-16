#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

int32_t crypto_add(int32_t a, int32_t b);

int32_t crypto_xor_buffer(
    uint8_t *data,
    size_t len,
    uint8_t key
);

#endif
