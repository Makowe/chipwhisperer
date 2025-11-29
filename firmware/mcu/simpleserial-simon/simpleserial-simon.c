
#include "hal.h"
#include <stdint.h>
#include <stdlib.h>

#include "simpleserial.h"
#include "simon64_128.h"

#define N 32
#define M 4
#define T 44

uint8_t get_key(uint8_t* k, uint8_t len)
{
    uint8_t ke[32];
	simon64_128_init(k);

    ke[0] = (expandedKey[0] >> 24) & 0xFF;
    ke[1] = (expandedKey[0] >> 16) & 0xFF;
    ke[2] = (expandedKey[0] >> 8) & 0xFF;
    ke[3] = expandedKey[0] & 0xFF;
    ke[4] = (expandedKey[1] >> 24) & 0xFF;
    ke[5] = (expandedKey[1] >> 16) & 0xFF;
    ke[6] = (expandedKey[1] >> 8) & 0xFF;
    ke[7] = expandedKey[1] & 0xFF;
    ke[8] = (expandedKey[2] >> 24) & 0xFF;
    ke[9] = (expandedKey[2] >> 16) & 0xFF;
    ke[10] = (expandedKey[2] >> 8) & 0xFF;
    ke[11] = expandedKey[2] & 0xFF;
    ke[12] = (expandedKey[3] >> 24) & 0xFF;
    ke[13] = (expandedKey[3] >> 16) & 0xFF;
    ke[14] = (expandedKey[3] >> 8) & 0xFF;
    ke[15] = expandedKey[3] & 0xFF;
    ke[16] = (expandedKey[4] >> 24) & 0xFF;
    ke[17] = (expandedKey[4] >> 16) & 0xFF;
    ke[18] = (expandedKey[4] >> 8) & 0xFF;
    ke[19] = expandedKey[4] & 0xFF;
    ke[20] = (expandedKey[5] >> 24) & 0xFF;
    ke[21] = (expandedKey[5] >> 16) & 0xFF;
    ke[22] = (expandedKey[5] >> 8) & 0xFF;
    ke[23] = expandedKey[5] & 0xFF;
    ke[24] = (expandedKey[6] >> 24) & 0xFF;
    ke[25] = (expandedKey[6] >> 16) & 0xFF;
    ke[26] = (expandedKey[6] >> 8) & 0xFF;
    ke[27] = expandedKey[6] & 0xFF;
    ke[28] = (expandedKey[7] >> 24) & 0xFF;
    ke[29] = (expandedKey[7] >> 16) & 0xFF;
    ke[30] = (expandedKey[7] >> 8) & 0xFF;
    ke[31] = expandedKey[7] & 0xFF;

    simpleserial_put('r', 32, ke);
    return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
	uint8_t ct[8];
    simon64_128_encrypt(pt, ct);
	simpleserial_put('r', 8, ct);
	return 0x00;
}

int main(void)
{
    platform_init();
	init_uart();
	trigger_setup();

	simpleserial_init();
	simpleserial_addcmd('p', 8, get_pt);
	simpleserial_addcmd('k', 8, get_key);

	while(1)
		simpleserial_get();
}
