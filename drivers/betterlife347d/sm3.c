/* SM3 hash (GM/T 0004-2012). Minimal, from the standard. Self-test in main under -DSM3_TEST. */
#include <stdint.h>
#include <string.h>
#include "sm3.h"

static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sm3_compress(uint32_t v[8], const uint8_t b[64]) {
    uint32_t w[68], w1[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4*i]<<24 | (uint32_t)b[4*i+1]<<16 | (uint32_t)b[4*i+2]<<8 | b[4*i+3];
    for (int i = 16; i < 68; i++) {
        uint32_t x = w[i-16] ^ w[i-9] ^ rol(w[i-3], 15);
        w[i] = (x ^ rol(x, 15) ^ rol(x, 23)) ^ rol(w[i-13], 7) ^ w[i-6];
    }
    for (int i = 0; i < 64; i++) w1[i] = w[i] ^ w[i+4];
    uint32_t a=v[0],bb=v[1],c=v[2],d=v[3],e=v[4],f=v[5],g=v[6],h=v[7];
    for (int i = 0; i < 64; i++) {
        uint32_t tj = i < 16 ? 0x79cc4519 : 0x7a879d8a;
        uint32_t ss1 = rol(rol(a,12) + e + rol(tj, i % 32), 7);
        uint32_t ss2 = ss1 ^ rol(a, 12);
        uint32_t ff = i < 16 ? (a^bb^c) : ((a&bb)|(a&c)|(bb&c));
        uint32_t gg = i < 16 ? (e^f^g) : ((e&f)|(~e&g));
        uint32_t tt1 = ff + d + ss2 + w1[i];
        uint32_t tt2 = gg + h + ss1 + w[i];
        d=c; c=rol(bb,9); bb=a; a=tt1;
        h=g; g=rol(f,19); f=e; e=tt2 ^ rol(tt2,9) ^ rol(tt2,17);
    }
    v[0]^=a; v[1]^=bb; v[2]^=c; v[3]^=d; v[4]^=e; v[5]^=f; v[6]^=g; v[7]^=h;
}

void sm3(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t v[8] = {0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e};
    uint8_t blk[64];
    size_t n = len;
    const uint8_t *p = msg;
    while (n >= 64) { sm3_compress(v, p); p += 64; n -= 64; }
    memset(blk, 0, 64);
    memcpy(blk, p, n);
    blk[n] = 0x80;
    if (n >= 56) { sm3_compress(v, blk); memset(blk, 0, 64); }
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) blk[63-i] = bits >> (8*i);
    sm3_compress(v, blk);
    for (int i = 0; i < 8; i++) { out[4*i]=v[i]>>24; out[4*i+1]=v[i]>>16; out[4*i+2]=v[i]>>8; out[4*i+3]=v[i]; }
}

#ifdef SM3_TEST
#include <stdio.h>
int main(void) {
    uint8_t h[32];
    sm3((const uint8_t*)"abc", 3, h);
    const char *want = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    char got[65]; for (int i=0;i<32;i++) sprintf(got+2*i, "%02x", h[i]);
    printf("SM3(abc)=%s\n%s\n", got, strcmp(got,want)?"FAIL":"PASS");
    return strcmp(got, want) != 0;
}
#endif
