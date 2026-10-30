#ifndef SM3_H
#define SM3_H
#include <stddef.h>
#include <stdint.h>
void sm3(const uint8_t *msg, size_t len, uint8_t out[32]);
#endif
