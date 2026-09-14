#include <stdint.h>

static const uint8_t primary_message[] = "zkCFA64 authenticated scope boundary";
static const uint8_t alternate_message[] = "independently provisioned CRC32 branch";

/*
 * The functional device leaves this at zero.  Volatile prevents the compiler
 * from deleting the independently provisioned alternate path, so the static
 * typed CFG contains legal edges that the measured execution does not take.
 */
static volatile uint32_t provider_mode;

__attribute__((noinline))
static uint32_t crc32_byte(uint32_t crc, uint8_t byte)
{
	crc ^= byte;
	for (unsigned bit = 0; bit < 8; bit++) {
		uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);

		crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
	}
	return crc;
}

__attribute__((noinline, used))
static uint32_t crc32_primary(void)
{
	uint32_t crc = UINT32_C(0xffffffff);

	for (unsigned i = 0; i < sizeof(primary_message) - 1; i++)
		crc = crc32_byte(crc, primary_message[i]);
	return ~crc;
}

__attribute__((noinline, used))
static uint32_t crc32_alternate(void)
{
	uint32_t crc = UINT32_C(0xffffffff);

	for (unsigned i = 0; i < sizeof(alternate_message) - 1; i++)
		crc = crc32_byte(crc, alternate_message[i]);
	return ~crc;
}

/* This named function is the statically provisioned attested region. */
__attribute__((noinline, used))
uint32_t crc32_scope(void)
{
	if (provider_mode)
		return crc32_alternate();
	return crc32_primary();
}
