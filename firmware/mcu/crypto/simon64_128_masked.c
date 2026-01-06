#include "simon64_128_masked.h"
#include "hdrbg.h"

#define N 32
#define M 4
#define T 44

const uint64_t z = 0b0011011011101011000110010111100000010010001010011100110100001111;
uint32_t expandedKey[T];

static inline uint32_t masked_and(uint32_t a, uint32_t ma, uint32_t b, uint32_t mb, uint32_t mc);
static inline uint32_t rot_left(uint32_t word, uint8_t shift);
static inline uint32_t rot_right(uint32_t word, uint8_t shift);
static inline uint32_t get_round_constant(uint8_t i);

void simon64_128_seed(uint8_t *seed)
{
    hdrbg_init(seed);
}

void simon64_128_set_key(uint8_t *k)
{
    uint32_t tmp;
    uint32_t z_i;

    expandedKey[0] = k[12] << 24 | k[13] << 16 | k[14] << 8 | k[15];
    expandedKey[1] = k[8] << 24 | k[9] << 16 | k[10] << 8 | k[11];
    expandedKey[2] = k[4] << 24 | k[5] << 16 | k[6] << 8 | k[7];
    expandedKey[3] = k[0] << 24 | k[1] << 16 | k[2] << 8 | k[3];

    for (uint8_t i = M; i < T; i++)
    {
        tmp = rot_right(expandedKey[i - 1], 3) ^ expandedKey[i - 3];
        tmp ^= rot_right(tmp, 1);
        z_i = get_round_constant(i - M);
        expandedKey[i] = ~expandedKey[i - M] ^ tmp ^ z_i ^ 0x3;
    }
}

void simon64_128_encrypt(uint8_t *pt, uint8_t *ct)
{
    uint32_t tmp, m_tmp, tmp2, m_tmp2;

    /* Initialize 1 mask for x, one for y and one mask for each and-operation per round. */
    uint32_t masks[T + 2];
    hdrbg_fill((uint8_t *)masks, (T + 2) * 4);

    uint32_t x = pt[0] << 24 | pt[1] << 16 | pt[2] << 8 | pt[3];
    uint32_t y = pt[4] << 24 | pt[5] << 16 | pt[6] << 8 | pt[7];
    uint32_t mx = masks[0];
    uint32_t my = masks[1];

    /* Apply mask */
    x ^= mx;
    y ^= my;

    trigger_high();
    for (uint8_t i = 0; i < T; i++)
    {
        tmp = x;
        m_tmp = mx;

        m_tmp2 = masks[i + 2];
        tmp2 = masked_and(
            rot_left(x, 1),
            rot_left(mx, 1),
            rot_left(x, 8),
            rot_left(mx, 8),
            m_tmp2);

        x = y ^ tmp2 ^ rot_left(x, 2) ^ expandedKey[i];
        mx = my ^ m_tmp2 ^ rot_left(mx, 2);

        y = tmp;
        my = m_tmp;
    }

    /* Unmask the result */
    x ^= mx;
    y ^= my;

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

static inline uint32_t masked_and(uint32_t a, uint32_t ma, uint32_t b, uint32_t mb, uint32_t mc)
{
    return ((((a & b) ^ mc) ^ (a & mb)) ^ (b & ma)) ^ (ma & mb);
}

static inline uint32_t rot_left(uint32_t word, uint8_t shift)
{
    return (word << shift) | (word >> (N - shift));
}

static inline uint32_t rot_right(uint32_t word, uint8_t shift)
{
    return (word >> shift) | (word << (N - shift));
}

static inline uint32_t get_round_constant(uint8_t i)
{
    return (uint32_t)(z >> (61 - i)) & 0x1;
}
