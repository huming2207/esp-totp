#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t hotp_generate(uint8_t *key, size_t key_len, uint64_t interval, size_t digits);
uint32_t totp_hash_token(uint8_t *key, size_t key_len, uint64_t time, size_t digits);
uint32_t totp_generate(uint8_t *key, size_t key_len);

#ifdef __cplusplus
}
#endif
