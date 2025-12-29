/* Taken from https://github.com/tfpf/hash-drbg and modified. */

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "extras.h"
#include "hdrbg.h"
#include "sha.h"

#define HDRBG_SEED_LENGTH 55
#define HDRBG_SECURITY_STRENGTH 32
#define HDRBG_NONCE_LENGTH 16
#define HDRBG_OUTPUT_LENGTH 32

struct hdrbg_t
{
    // The first member is prepended with a byte whenever it is processed, so
    // keep an extra byte.
    uint8_t V[1 + HDRBG_SEED_LENGTH];
    uint8_t C[HDRBG_SEED_LENGTH];
    uint64_t gen_count;
};

static struct hdrbg_t hdrbg;

/******************************************************************************
 * Add two numbers. Overwrite the first number with the result, disregarding
 * any carried bytes.
 *
 * @param a_bytes Array of bytes of the first number in big-endian order.
 * @param a_length Number of bytes of the first number.
 * @param b_bytes Array of bytes of the second number in big-endian order.
 * @param b_length Number of bytes of the second number. Must be less than or
 *     equal to `a_length`.
 *****************************************************************************/
static void add_accumulate(uint8_t *a_bytes, size_t a_length, uint8_t const *b_bytes, size_t b_length)
{
    int unsigned carry = 0;
    for (; a_length > 0 && b_length > 0; --a_length, --b_length)
    {
        carry = a_bytes[a_length - 1] + carry + b_bytes[b_length - 1];
        a_bytes[a_length - 1] = carry;
        carry >>= 8;
    }
    for (; a_length > 0; --a_length)
    {
        carry += a_bytes[a_length - 1];
        a_bytes[a_length - 1] = carry;
        carry >>= 8;
    }
}

/******************************************************************************
 * Hash derivation function. Transform the input bytes into the required number
 * of output bytes using a hash function.
 *
 * @param m_bytes_ Input bytes.
 * @param m_length_ Number of input bytes.
 * @param h_bytes Array to store the output bytes in. (It must have sufficient
 *     space for `h_length` elements.)
 * @param h_length Number of output bytes required.
 *****************************************************************************/
static void hash_df(uint8_t const *m_bytes_, size_t m_length_, uint8_t *h_bytes, size_t h_length)
{
    // Construct the data to be hashed in a sufficiently large array.
    size_t m_length = 5 + m_length_;
    uint8_t m_bytes[93];
    uint32_t nbits = (uint32_t)h_length << 3;
    memdecompose(m_bytes + 1, 4, nbits);
    memcpy(m_bytes + 5, m_bytes_, m_length_ * sizeof *m_bytes_);

    // Hash repeatedly.
    size_t iterations = (h_length - 1) / HDRBG_OUTPUT_LENGTH + 1;
    for (size_t i = 1; i <= iterations; ++i)
    {
        m_bytes[0] = i;
        uint8_t tmp[HDRBG_OUTPUT_LENGTH];
        sha256(m_bytes, m_length, tmp);
        size_t len = h_length >= HDRBG_OUTPUT_LENGTH ? HDRBG_OUTPUT_LENGTH : h_length;
        memcpy(h_bytes, tmp, len * sizeof *h_bytes);
        h_length -= len;
        h_bytes += len;
    }
}

/******************************************************************************
 * Hash generator. Transform the input bytes into the required number of output
 * bytes using a hash function.
 *
 * @param m_bytes_ Input bytes. Must be an array of length `HDRBG_SEED_LENGTH`.
 * @param h_bytes Array to store the output bytes in. (It must have sufficient
 *     space for `h_length` elements.)
 * @param h_length Number of output bytes required.
 *****************************************************************************/
static void hash_gen(uint8_t const *m_bytes_, uint8_t *h_bytes, size_t h_length)
{
    // Construct the data to be hashed.
    uint8_t m_bytes[HDRBG_SEED_LENGTH];
    memcpy(m_bytes, m_bytes_, sizeof m_bytes);

    // Hash repeatedly.
    size_t iterations = (h_length - 1) / HDRBG_OUTPUT_LENGTH + 1;
    for (size_t i = 0; i < iterations; ++i)
    {
        uint8_t tmp[HDRBG_OUTPUT_LENGTH];
        sha256(m_bytes, HDRBG_SEED_LENGTH, tmp);
        size_t len = h_length >= HDRBG_OUTPUT_LENGTH ? HDRBG_OUTPUT_LENGTH : h_length;
        memcpy(h_bytes, tmp, len * sizeof *h_bytes);
        h_length -= len;
        h_bytes += len;
        uint8_t one = 1;
        add_accumulate(m_bytes, HDRBG_SEED_LENGTH, &one, 1);
    }
}

/******************************************************************************
 * Set the members of an HDRBG object.
 *
 * @param hd HDRBG object.
 * @param s_bytes Array to derive the values of the members from.
 * @param s_length Number of elements in the array.
 *****************************************************************************/
static void hdrbg_seed(uint8_t *s_bytes, size_t s_length)
{
    hdrbg.V[0] = 0x00U;
    hash_df(s_bytes, s_length, hdrbg.V + 1, HDRBG_SEED_LENGTH);
    hash_df(hdrbg.V, HDRBG_SEED_LENGTH + 1, hdrbg.C, HDRBG_SEED_LENGTH);
    hdrbg.gen_count = 0;
}

/******************************************************************************
 * Create and/or initialise (seed) an HDRBG object.
 *****************************************************************************/
void hdrbg_init(uint8_t *entropy)
{
    uint8_t seedmaterial[HDRBG_SECURITY_STRENGTH + HDRBG_NONCE_LENGTH];
    memcpy(seedmaterial, entropy, HDRBG_SECURITY_STRENGTH + HDRBG_NONCE_LENGTH);
    hdrbg_seed(seedmaterial, HDRBG_SECURITY_STRENGTH + HDRBG_NONCE_LENGTH);
}

/******************************************************************************
 * Generate cryptographically secure pseudorandom bytes.
 *****************************************************************************/
int hdrbg_fill(uint8_t *r_bytes, uint32_t r_length)
{
    if (r_length > 0)
    {
        hash_gen(hdrbg.V + 1, r_bytes, r_length);
    }

    // Mutate the state.
    hdrbg.V[0] = 0x03U;
    uint8_t tmp[HDRBG_OUTPUT_LENGTH];
    sha256(hdrbg.V, HDRBG_SEED_LENGTH + 1, tmp);
    uint8_t gen_count[8];
    memdecompose(gen_count, 8, ++hdrbg.gen_count);
    add_accumulate(hdrbg.V + 1, HDRBG_SEED_LENGTH, tmp, HDRBG_OUTPUT_LENGTH);
    add_accumulate(hdrbg.V + 1, HDRBG_SEED_LENGTH, hdrbg.C, HDRBG_SEED_LENGTH);
    add_accumulate(hdrbg.V + 1, HDRBG_SEED_LENGTH, gen_count, 8);
    return 0;
}

/******************************************************************************
 * Display the given data in hexadecimal form.
 *****************************************************************************/
void hdrbg_dump(uint8_t const *m_bytes, size_t m_length)
{
    while (m_length-- > 0)
    {
        fprintf(stdout, "%02" PRIx8, *m_bytes++);
    }
    fprintf(stdout, "\n");
}
