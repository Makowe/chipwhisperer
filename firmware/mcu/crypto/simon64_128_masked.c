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

    /* Pointers required for asm */
    uint32_t *keys = expandedKey;
    uint32_t *mc = masks + 2;

    /* Perform Simon Round Function with masked AND-Gate. */
    asm volatile(
        /* Initialize Loop */
        "MOV r0, 0                  \n\t"
        /* Keep r10 constant as 0. */
        "EOR r10, r10, r10          \n\t"
        "EOR r4,  r10, r10          \n\t"
        "EOR r5,  r10, r10          \n\t"
        "EOR r6,  r10, r10          \n\t"
        "EOR r8,  r10, r10          \n\t"
        "EOR r11, r10, r10          \n\t"
        "simon_round:               \n\t"

        /* Load round mask mc */
        "LDR r9, [%[mc]], #4        \n\t"
        "EOR r10, r10, r10          \n\t"

        /* a  = x <<< 1
         * b  = x <<< 8 */
        "ROR r4, %[x], #31          \n\t"
        "ROR r6, %[x], #24          \n\t"
        "EOR r10, r10, r10          \n\t"

        /* ma = mx <<< 1
         * mb = mx <<< 8 */
        "ROR r5,  %[mx], #31        \n\t"
        "ROR r11, %[mx], #24        \n\t"
        "EOR r10, r10, r10          \n\t"

        /* Masked AND-Gate
         * c = ((((a & b) ^ mc) ^ (a & mb)) ^ (b & ma)) ^ (ma & mb)
         *           |    |     |    |      |    |      |     |
         *           1    2     4    3      6    5      8     7 */

        "AND r8, r4, r6             \n\t" // 3.1
        "EOR r10, r10, r10          \n\t"
        "EOR r8, r8, r9             \n\t" // 3.2
        "AND r4, r4, r11            \n\t" // 3.3
        "EOR r10, r10, r10          \n\t"
        "EOR r8, r8, r4             \n\t" // 3.4
        "EOR r10, r10, r10          \n\t"
        "AND r6, r6, r5             \n\t" // 3.5
        "EOR r10, r10, r10          \n\t"
        "EOR r8, r8, r6             \n\t" // 3.6
        "EOR r10, r10, r10          \n\t"
        "AND r5, r5, r11            \n\t" // 3.7
        "EOR r10, r10, r10          \n\t"
        "EOR r8, r8, r5             \n\t" // 3.8
        /* Clear temporary registers except r8 */
        "EOR r4, r10, r10           \n\t"
        "EOR r5, r10, r10           \n\t"
        "EOR r6, r10, r10           \n\t"
        "EOR r11, r10, r10          \n\t"

        /* Load round key */
        "LDR r11, [%[keys]], #4     \n\t"

        /* tmp = x
         * x = x <<< 2 */
        "MOV r4,   %[x]             \n\t"
        "ROR %[x], %[x], #30        \n\t"
        "EOR r10, r10, r10          \n\t"

        /* m_tmp = mx
         * mx = mx <<< 2 */
        "MOV r5,    %[mx]           \n\t"
        "ROR %[mx], %[mx], #30      \n\t"
        "EOR r10, r10, r10          \n\t"

        /* x = y ^ c ^ x ^ round_key
         * y = tmp */
        "EOR %[y], %[y], r11        \n\t"
        "EOR %[x], %[x], r8         \n\t"
        "EOR %[x], %[x], %[y]       \n\t"
        "MOV %[y], r4               \n\t"
        /* clear r4 and r8 */
        "EOR r4, r10, r10           \n\t"
        "EOR r8, r10, r10           \n\t"

        /* mx = my ^ mc ^ mx
         * my = m_tmp */
        "EOR %[my], %[my], r9       \n\t"
        "EOR %[mx], %[mx], %[my]    \n\t"
        "MOV %[my], r5              \n\t"
        /* clear r5 */
        "EOR r5, r10, r10           \n\t"

        "ADD r0, r0, #1             \n\t"
        "CMP r0, #44                \n\t"
        "BNE simon_round            \n\t"

        : [x] "+r"(x), [y] "+r"(y), [mx] "+r"(mx), [my] "+r"(my)
        : [keys] "r"(keys), [mc] "r"(mc)
        : "r0", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "cc", "memory");

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
