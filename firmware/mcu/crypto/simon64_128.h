#include "hal.h"
#include <stdint.h>
#include <stdlib.h>

#include "simpleserial.h"

extern uint32_t expandedKey[];

void simon64_128_set_key(uint8_t *k);
void simon64_128_encrypt(uint8_t *pt, uint8_t *ct);