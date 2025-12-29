/* Taken from https://github.com/tfpf/hash-drbg and modified. */

#ifndef TFPF_HASH_DRBG_INCLUDE_HDRBG_H_
#define TFPF_HASH_DRBG_INCLUDE_HDRBG_H_

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

struct hdrbg_t;

void hdrbg_init(uint8_t *entropy);
int hdrbg_fill(uint8_t *r_bytes, uint32_t r_length);
void hdrbg_dump(uint8_t const *m_bytes, size_t m_length);

#endif // TFPF_HASH_DRBG_INCLUDE_HDRBG_H_
