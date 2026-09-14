/* SPDX-License-Identifier: BSD-2-Clause */
/* Actual-QEMU negative fixture for an out-of-closure primary-ELF re-entry. */

#include <string.h>

__attribute__((noinline, visibility("default")))
void outside_scope_gadget(void)
{
	__asm__ volatile("" ::: "memory");
}

int main(void)
{
	static const unsigned char left[1] = {0x5a};
	static const unsigned char right[1] = {0x5a};

	/* -fno-builtin-memcmp keeps this as an admitted libc PLT call. */
	return memcmp(left, right, sizeof(left));
}
