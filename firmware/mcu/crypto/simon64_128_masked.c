#include "simon64_128_masked.h"
#include "hdrbg.h"

#define N 32
#define M 4
#define T 44

const uint64_t z = 0b0011011011101011000110010111100000010010001010011100110100001111;
uint32_t expandedKey[T];

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

/* __attribute__((optimize("O0"))) */
void simon64_128_encrypt(uint8_t *pt, uint8_t *ct)
{
    uint32_t x, y, mx, my;

    /* Initialize 1 mask for x, 1 for y and 44 masks for the AND-Gates in each round. */
    uint32_t masks[T + 2];
    hdrbg_fill((uint8_t *)masks, (T + 2) * 4);

    x = pt[0] << 24 | pt[1] << 16 | pt[2] << 8 | pt[3];
    y = pt[4] << 24 | pt[5] << 16 | pt[6] << 8 | pt[7];

    mx = masks[0];
    my = masks[1];

    x ^= mx;
    y ^= my;

    trigger_high();
    for (uint8_t i = 0; i < T; i++)
    {
        uint32_t key = expandedKey[i];
        uint32_t mc = masks[i + 2];

        /* Perform Simon Round Function with masked AND-Gate.
        Step 1: a  = x <<< 1
                b  = x <<< 8
        Step 2: ma = mx <<< 1
                mb = mx <<< 8
        Step 3: c = ((((a & b) ^ mc) ^ (a & mb)) ^ (b & ma)) ^ (ma & mb)
                          |    |     |    |      |    |      |     |
                          1    2     4    3      6    5      8     7
        Step 4: tmp = x
                x = x <<< 2

        Step 5: m_tmp = mx
                mx = mx <<< 2

        Step 6: x = y ^ c ^ x ^ round_key
                y = tmp

        Step 7: mx = my ^ mc ^ mx
                my = m_tmp
        */
        asm volatile(
            // TODO: Clear registers from previous round
            // TODO: insert Dummy opertations
            // Step 1
            "ROR r4, %[x], #31     \n\t"
            "ROR r6, %[x], #24     \n\t"
            /* Register values:
             * r4 = a
             * r6 = b
             */
            // TODO: insert Dummy opertations
            // Step 2
            "ROR r5, %[mx], #31   \n\t"
            "ROR r11, %[mx], #24   \n\t"
            /* Register values:
             * r5 = ma
             * r11 = mb
             */

            // TODO: insert Dummy opertations

            // Step 3
            "AND r8, r4, r6  \n\t" // 3.1
            // TODO: insert Dummy opertations
            "EOR r8,  r8,  %[mc] \n\t" // 3.2
            "AND r4,  r4,  r11 \n\t"   // 3.3
            // TODO: insert Dummy opertations
            "EOR r8,  r8,  r4  \n\t" // 3.4
            // TODO: insert Dummy opertations
            "AND r6,  r6,  r5 \n\t" // 3.5
            // TODO: insert Dummy opertations
            "EOR r8,  r8,  r6  \n\t" // 3.6
            // TODO: insert Dummy opertations
            "AND r5, r5, r11 \n\t" // 3.7
            // TODO: insert Dummy opertations
            "EOR r8,  r8,  r5 \n\t" // 3.8

            // TODO: insert Dummy opertations

            // Step 4
            "MOV r4, %[x]        \n\t"
            "ROR %[x], %[x], #30   \n\t"

            // TODO: insert Dummy opertations

            // Step 5
            "MOV r5, %[mx]       \n\t"
            "ROR %[mx], %[mx], #30   \n\t"

            // TODO: insert Dummy opertations

            // Step 6
            "EOR %[y], %[y], r8    \n\t"
            "EOR %[x], %[x], %[key]   \n\t"
            "EOR %[x], %[x], %[y]    \n\t"
            "MOV %[y], r4        \n\t"

            // TODO: insert Dummy opertations

            // Step 7
            "EOR %[my], %[my], %[mc]    \n\t"
            "EOR %[mx], %[mx], %[my]    \n\t"
            "MOV %[my], r5        \n\t"
            : [x] "+r"(x), [y] "+r"(y), [mx] "+r"(mx), [my] "+r"(my)
            : [key] "r"(key), [mc] "r"(mc)
            : "r4", "r5", "r6", "r11", "r8", "cc", "memory");
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

static inline uint32_t rot_right(uint32_t word, uint8_t shift)
{
    return (word >> shift) | (word << (N - shift));
}

static inline uint32_t get_round_constant(uint8_t i)
{
    return (uint32_t)(z >> (61 - i)) & 0x1;
}
