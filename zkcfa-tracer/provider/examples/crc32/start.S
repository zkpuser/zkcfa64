	.text
	.align 2
	.global _start
	.type _start, %function
_start:
	bl crc32_scope
	/* The instruction immediately after BL is the authenticated scope return. */
	mov w0, #0
	mov x8, #93
	svc #0
	b .
	.size _start, .-_start
