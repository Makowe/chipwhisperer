
#include "hal.h"
#include <stdint.h>
#include <stdlib.h>

#include "simpleserial.h"
#include "simon64_128_masked.h"

uint8_t get_seed(uint8_t *s, uint8_t len)
{
	simon64_128_seed(s);
	return 0;
}

/* Generate 8 random bytes and output them. This is used for testing the random number generator. */
uint8_t rand_gen(uint8_t *r, uint8_t len)
{
	uint8_t rand[8];
	get_rand(rand, 8);
	simpleserial_put('r', 8, rand);
	return 0;
}

uint8_t get_key(uint8_t *k, uint8_t len)
{
	simon64_128_set_key(k);
	return 0;
}

uint8_t get_pt(uint8_t *pt, uint8_t len)
{
	uint8_t ct[8];
	simon64_128_encrypt(pt, ct);
	simpleserial_put('r', 8, ct);
	return 0;
}

int main(void)
{
	platform_init();
	init_uart();
	trigger_setup();

	simpleserial_init();
	simpleserial_addcmd('p', 8, get_pt);
	simpleserial_addcmd('r', 0, rand_gen);
	simpleserial_addcmd('k', 16, get_key);
	simpleserial_addcmd('s', 48, get_seed);

	while (1)
		simpleserial_get();
}
