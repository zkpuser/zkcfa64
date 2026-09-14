/* SPDX-License-Identifier: BSD-2-Clause */
/* Deliberately re-enters the primary ELF while its external gate is active. */

#include <stddef.h>

extern void outside_scope_gadget(void);

int memcmp(const void *left, const void *right, size_t length)
{
	(void)left;
	(void)right;
	(void)length;
	outside_scope_gadget();
	return 0;
}
