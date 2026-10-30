#ifndef SM4_H
#define SM4_H
#include <stdint.h>
void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32], int encrypt);
void sm4_crypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]);
#endif
