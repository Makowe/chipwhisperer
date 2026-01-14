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
    uint32_t tmp, tmp2, tmp3, tmp4;
    uint32_t m_tmp, m_tmp2, m_tmp3, m_tmp4;

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

        /* Perform masked AND operation of (x <<< 1) and (x <<< 8).
        The result c will be available in the variable tmp2.
        Step 1: a  = x <<< 1
                ma = mx <<< 1
        Step 2: b  = x <<< 8
                mb = mx <<< 8
        Step 3: c = ((((a & b) ^ mc) ^ (a & mb)) ^ (b & ma)) ^ (ma & mb)
                          |    |     |    |      |    |      |     |
                          1    2     4    3      6    5      8     7
        */
        asm volatile(
            // Step 1
            "ROR %[a], %[x], #31     \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "ROR %[ma], %[mx], #31   \n\t"
            // Step 2
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"

            "ROR %[b], %[x], #24     \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"

            "ROR %[mb], %[mx], #24   \n\t"
            // Step 3
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"

            "AND %[c],  %[a],  %[b]  \n\t" // 3.1
            "EOR %[c],  %[c],  %[mc] \n\t" // 3.2
            "AND %[a],  %[a],  %[mb] \n\t" // 3.3 (a is not required anymore)
            "EOR %[c],  %[c],  %[a]  \n\t" // 3.4
            "AND %[b],  %[b],  %[ma] \n\t" // 3.5 (b is not required anymore)
            "EOR %[c],  %[c],  %[b]  \n\t" // 3.6
            "AND %[ma], %[ma], %[mb] \n\t" // 3.7 (ma is not required anymore)
            "EOR %[c],  %[c],  %[ma] \n\t" // 3.8
            : [c] "=r"(tmp2),
              [a] "=r"(tmp3), [ma] "=r"(m_tmp3),
              [b] "=r"(tmp4), [mb] "=r"(m_tmp4)
            : [x] "r"(x), [mx] "r"(mx), [mc] "r"(m_tmp2)
            : "memory");

        asm volatile(
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t" :::);

        x = y ^ tmp2 ^ rot_left(x, 2) ^ expandedKey[i];
        y = tmp;
        asm volatile(
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t"
            "NOP \n\t" :::);
        mx = my ^ m_tmp2 ^ rot_left(mx, 2);
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
