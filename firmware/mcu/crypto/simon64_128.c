#include "simon64_128.h"

#define N 32
#define M 4
#define T 44

const uint64_t z = 0b0011011011101011000110010111100000010010001010011100110100001111;
uint32_t expandedKey[44];

inline uint32_t rot_left(uint32_t word, uint8_t shift);
inline uint32_t rot_right(uint32_t word, uint8_t shift);
inline uint32_t get_round_constant(uint8_t i);


void simon64_128_init(uint8_t* k)
{
    uint32_t tmp;
    uint32_t z_i;

    expandedKey[0] = k[12] << 24 | k[13] << 16 | k[14] << 8 | k[15];
    expandedKey[1] = k[8] << 24 | k[9] << 16 | k[10] << 8 | k[11];
    expandedKey[2] = k[4] << 24 | k[5] << 16 | k[6] << 8 | k[7];
    expandedKey[3] = k[0] << 24 | k[1] << 16 | k[2] << 8 | k[3];

    for(uint8_t i = M; i < T; i++) 
    {
        tmp = rot_right(expandedKey[i- 1], 3) ^ expandedKey[i - 3];
        tmp ^= rot_right(tmp, 1);
        z_i = get_round_constant(i - M);
        expandedKey[i] = ~expandedKey[i - M] ^ tmp ^ z_i ^ 0x3;
    }
}

void simon64_128_encrypt(uint8_t* pt, uint8_t* ct)
{
    uint32_t tmp;
    uint32_t x = pt[0] << 24 | pt[1] << 16 | pt[2] << 8 | pt[3];
    uint32_t y = pt[4] << 24 | pt[5] << 16 | pt[6] << 8 | pt[7];
    trigger_high();
    for(uint8_t i = 0; i < T; i++) 
    {
        tmp = x;
        x = y ^ (rot_left(x, 1) & rot_left(x, 8)) ^ rot_left(x, 2) ^ expandedKey[i];
        y = tmp;
    }

    ct[0] = (x >> 24);
    ct[1] = (x >> 16) & 0xFF;
    ct[2] = (x >> 8) & 0xFF;
    ct[3] = x & 0xFF;
    ct[4] = (y >> 24);
    ct[5] = (y >> 16) & 0xFF;
    ct[6] = (y >> 8) & 0xFF;
    ct[7] = y & 0xFF;
    trigger_low();
}


inline uint32_t rot_left(uint32_t word, uint8_t shift)
{
    return (word << shift) | (word >> (N - shift));
}

inline uint32_t rot_right(uint32_t word, uint8_t shift)
{
    return (word >> shift) | (word << (N - shift));
}

inline uint32_t get_round_constant(uint8_t i)
{
    return (uint32_t)(z >> (61 - i)) & 0x1;
}
