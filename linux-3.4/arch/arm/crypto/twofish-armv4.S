#define __ARM_ARCH__ __LINUX_ARM_ARCH__
@
@ Twofish Cipher 1-way algorithm (ARM)
@
@ Based on cipher/twofish-arm.S written for Libgcrypt project by
@  Copyright (C) 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi> 
@
@ This program is free software; you can redistribute it and/or modify
@ it under the terms of the GNU General Public License as published by
@ the Free Software Foundation; either version 2 of the License, or
@ (at your option) any later version.
@
@ This program is distributed in the hope that it will be useful,
@ but WITHOUT ANY WARRANTY; without even the implied warranty of
@ MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
@ GNU General Public License for more details.
@
@ You should have received a copy of the GNU General Public License
@ along with this program; if not, write to the Free Software
@ Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
@ USA
@

#include <linux/linkage.h>
#include <asm/assembler.h>

.text

@ Structure of twofish_ctx
#define s0 0
#define s1 ((s0) + 4 * 256)
#define s2 ((s1) + 4 * 256)
#define s3 ((s2) + 4 * 256)
#define w  ((s3) + 4 * 256)
#define k  ((w) + 4 * 8)

@ Register macros
#define CTX   %r0
#define CTXs0 %r0
#define CTXs1 %r1
#define CTXs2 %r2
#define CTXs3 %r3

#define RA    %r4
#define RB    %r5
#define RC    %r6
#define RD    %r7

#define RT0   %r8
#define RT1   %r9
#define RT2   %r10
#define RT3   %r11

#define RT4   %ip
#define RT5   %lr

@ Helper macros

@ Load input data in endian-neutral manner
#define ldr_unaligned_le(rin, s0, s1, s2, s3, t1, t2, t3) \
	ldrb	s0, [rin, #0]; \
	ldrb	t1, [rin, #1]; \
	ldrb	t2, [rin, #2]; \
	ldrb	t3, [rin, #3]; \
	orr	s0, s0, t1, lsl#8; \
	ldrb	s1, [rin, #4]; \
	orr	s0, s0, t2, lsl#16; \
	ldrb	t1, [rin, #5]; \
	orr	s0, s0, t3, lsl#24; \
	ldrb	t2, [rin, #6]; \
	ldrb	t3, [rin, #7]; \
	orr	s1, s1, t1, lsl#8; \
	ldrb	s2, [rin, #8]; \
	orr	s1, s1, t2, lsl#16; \
	ldrb	t1, [rin, #9]; \
	orr	s1, s1, t3, lsl#24; \
	ldrb	t2, [rin, #10]; \
	ldrb	t3, [rin, #11]; \
	orr	s2, s2, t1, lsl#8; \
	ldrb	s3, [rin, #12]; \
	orr	s2, s2, t2, lsl#16; \
	ldrb	t1, [rin, #13]; \
	orr	s2, s2, t3, lsl#24; \
	ldrb	t2, [rin, #14]; \
	ldrb	t3, [rin, #15]; \
	orr	s3, s3, t1, lsl#8; \
	orr	s3, s3, t2, lsl#16; \
	orr	s3, s3, t3, lsl#24;

#define ldr_input_le(rin, s0, s1, s2, s3) \
	ldr	s0, [rin, #0]; \
	ldr	s1, [rin, #4]; \
	ldr	s2, [rin, #8]; \
	ldr	s3, [rin, #12];

@ Write output in endian-neutral manner
#define str_unaligned_le(rout, s0, s1, s2, s3, t1, t2, t3) \
	mov	t1, s0, lsr#24; \
	mov	t2, s0, lsr#16; \
	mov	t3, s0, lsr#8; \
	strb	t1, [rout, #3]; \
	strb	t2, [rout, #2]; \
	mov	t1, s1, lsr#24; \
	strb	t3, [rout, #1]; \
	mov	t2, s1, lsr#16; \
	strb	s0, [rout, #0]; \
	mov	t3, s1, lsr#8; \
	strb	t1, [rout, #7]; \
	strb	t2, [rout, #6]; \
	mov	t1, s2, lsr#24; \
	strb	t3, [rout, #5]; \
	mov	t2, s2, lsr#16; \
	strb	s1, [rout, #4]; \
	mov	t3, s2, lsr#8; \
	strb	t1, [rout, #11]; \
	strb	t2, [rout, #10]; \
	mov	t1, s3, lsr#24; \
	strb	t3, [rout, #9]; \
	mov	t2, s3, lsr#16; \
	strb	s2, [rout, #8]; \
	mov	t3, s3, lsr#8; \
	strb	t1, [rout, #15]; \
	strb	t2, [rout, #14]; \
	strb	t3, [rout, #13]; \
	strb	s3, [rout, #12];

#define str_output_le(rout, s0, s1, s2, s3) \
	str	s0, [rout, #0]; \
	str	s1, [rout, #4]; \
	str	s2, [rout, #8]; \
	str	s3, [rout, #12];

@ **********************************************************************
@  1-way twofish
@
@ Some rotations are removed in favor of merging rotations with arithmetic
@ operations on ARM. On ARM, the second operand of arithmetic instruction
@ can be shifted or rotated by arbitrary distance without extra CPU cycles.
@ The rotations inside encrypt_round and decrypt_round rotate the results
@ of arithemtic instruction instead of one the inputs:
@ c = (c ^ (x + ctx->k[2*n])) >> 1
@ This is easily decomposed into two instructions:
@ c = c ^ (x + ctx->k[2*n])
@ c = c >> 1
@ This implementation only computes the first of the first instructions and
@ rotates c by 1 the next time c is used as input.
@
@ See the paper "SHA-3 on ARM11 processors" by P. Schwabe, B-Y. Yang and
@ S-Y. Yang for discussion on merging rotations and arithmetic operations.
@ ***********************************************************************

@ Note that c from round n is used as input in and after round n+2 so we need to rotate it.
@ Final rotation "ror c, c, #1" is removed.

#define encrypt_round(a, b, c, d, x, y, mask, t1, t2, t3, n, rota, rotc) \
	and	y, mask, b, lsr#(16 - 2); \
	and	t3, mask, b, lsr#(8 - 2); \
	ldr	y, [CTXs3, y]; \
	and	t1, mask, b, lsr#(24 - 2); \
	and	t2, mask, b, lsl#(2); \
	ldr	t1, [CTXs0, t1]; \
	and	x, mask, a, ror#(8 + rota - 2); \
	eor	y, y, t1; \
	ldr	t2, [CTXs1, t2]; \
	and	t1, mask, a, ror#(16 + rota - 2); \
	ldr	x, [CTXs1, x]; \
	eor	y, y, t2; \
	\
	ldr	t1, [CTXs2, t1]; \
	and	t2, mask, a, ror#(24 + rota - 2); \
	ldr	t3, [CTXs2, t3]; \
	eor	x, x, t1; \
	\
	ldr	t2, [CTXs3, t2]; \
	and	t1, mask, a, ror#(32 + rota - 2); \
	eor	y, y, t3; \
	ldr	t1, [CTXs0, t1]; \
	eor	x, x, t2; \
	\
	ldr	t3, [CTXs3, #(k - s3 + 8 * (n))]; \
	eor	x, x, t1; \
	ldr	t2, [CTXs3, #(k - s3 + 8 * (n) + 4)]; \
	\
	add	t3, t3, x; \
	add	t1, x, y, lsl#1; \
	add	t3, t3, y; \
	add	t1, t1, t2; \
	eor	c, t3, c, ror#(rotc); \
	eor	d, t1, d, ror#31;

@ Note that d from round n is used as input in and after round n-2 so we need to rotate it.
@ Final rotation "ror d, d, #1" is removed.

#define decrypt_round(a, b, c, d, x, y, mask, t1, t2, t3, n, rotb, rotd) \
	and	x, mask, a, ror#(32 - 2); \
	and	y, mask, b, ror#(32 + rotb - 2); \
	and	t1, mask, b, ror#(8 + rotb - 2); \
	\
	ldr	y, [CTXs1, y]; \
	and	t3, mask, a, lsr#(8 - 2); \
	ldr	t1, [CTXs2, t1]; \
	and	t2, mask, a, lsr#(16 - 2); \
	ldr	t3, [CTXs1, t3]; \
	eor	y, y, t1; \
	ldr	x, [CTXs0, x]; \
	and	t1, mask, b, ror#(16 + rotb - 2); \
	eor	x, x, t3; \
	ldr	t1, [CTXs3, t1]; \
	and	t3, mask, a, lsr#(24 - 2); \
	eor	y, y, t1; \
	\
	ldr	t3, [CTXs3, t3]; \
	and	t1, mask, b, ror#(24 + rotb - 2); \
	ldr	t2, [CTXs2, t2]; \
	eor	x, x, t3; \
	ldr	t1, [CTXs0, t1]; \
	eor	x, x, t2; \
	\
	ldr	t3, [CTXs3, #(k - s3 + 8 * (n) + 4)]; \
	eor	y, y, t1; \
	ldr	t2, [CTXs3, #(k - s3 + 8 * (n))]; \
	\
	add	t1, x, y, lsl #1; \
	add	x, x, y; \
	add	t1, t1, t3; \
	add	x, x, t2; \
	eor	d, t1, d, ror#(rotd); \
	eor	c, x, c, ror#31;

@ void twofish_enc_blk(const twofish_ctx *ctx, u8 *dst, const u8 *src)
.align	3
ENTRY(twofish_enc_blk)
	stmdb	sp!, {r1, r4-r11, ip, lr};

	add	RT4, CTXs0, #(w - s0);

#if __ARM_ARCH__<7
	ldr_unaligned_le(%r2, RA, RB, RC, RD, RT1, RT2, RT3);
#else
	ldr_input_le(%r2, RA, RB, RC, RD);
#ifndef __ARMEL__
	rev	RA, RA;
	rev	RB, RB;
	rev	RC, RC;
	rev	RD, RD;
#endif
#endif

	ldm	RT4, {RT0, RT1, RT2, RT3};		@ Input whitening
	add	CTXs1, CTXs0, #(s1 - s0);
	add	CTXs3, CTXs0, #(s3 - s0);
	eor	RA, RA, RT0;
	eor	RB, RB, RT1;
	mov	RT0, #(0xff << 2);			@ RT0 can be used to store mask
	eor	RC, RC, RT2;				@ because encrypt_round does not modify RT0
	eor	RD, RD, RT3;
	add	CTXs2, CTXs0, #(s2 - s0);

	encrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  0, 0, 0);
	encrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  1, 1, 0);
	encrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  2, 1, 1);
	encrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  3, 1, 1);
	encrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  4, 1, 1);
	encrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  5, 1, 1);
	encrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  6, 1, 1);
	encrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  7, 1, 1);
	encrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  8, 1, 1);
	encrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  9, 1, 1);
	encrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3, 10, 1, 1);
	encrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3, 11, 1, 1);
	encrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3, 12, 1, 1);
	encrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3, 13, 1, 1);
	encrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3, 14, 1, 1);
	encrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3, 15, 1, 1);

	add	RT4, CTXs3, #(w + 4*4 - s3);
	pop	{r1};					@ out

	ldm	RT4, {RT0, RT1, RT2, RT3};		@ Output whitening
	eor	RC, RT0, RC, ror#1;			@ Final rotation of a
	eor	RD, RD, RT1;
	eor	RA, RT2, RA, ror#1;			@ Final rotation of c
	eor	RB, RB, RT3;

#if __ARM_ARCH__<7
	str_unaligned_le(%r1, RC, RD, RA, RB, RT1, RT2, RT3);
#else
#ifndef __ARMEL__
	rev	RC, RC;
	rev	RD, RD;
	rev	RA, RA;
	rev	RB, RB;
#endif
	str_output_le(%r1, RC, RD, RA, RB);
#endif

	pop	{r4-r11, ip, pc};
ENDPROC(twofish_enc_blk)

@ void twofish_dec_blk(const twofish_ctx *ctx, u8 *dst, const u8 *src)

ENTRY(twofish_dec_blk)
	stmdb	sp!, {r1, r4-r11, ip, lr};

	add	CTXs3, CTXs0, #(s3 - s0);

#if __ARM_ARCH__<7
	ldr_unaligned_le(%r2, RC, RD, RA, RB, RT1, RT2, RT3);
#else
	ldr_input_le(%r2, RC, RD, RA, RB);
#ifndef __ARMEL__
	rev	RC, RC;
	rev	RD, RD;
	rev	RA, RA;
	rev	RB, RB;
#endif
#endif

	add	RT4, CTXs3, #(w + 4*4 - s3);
	add	CTXs1, CTXs0, #(s1 - s0);

	ldm	RT4, {RT0, RT1, RT2, RT3};		@ Input whitening
	add	CTXs2, CTXs0, #(s2 - s0);
	eor	RC, RC, RT0;
	eor	RD, RD, RT1;
	mov	RT0, #(0xff << 2);			@ RT0 can be used to store mask
	eor	RA, RA, RT2;				@ because decrypt_round does not modify RT0
	eor	RB, RB, RT3;

	decrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3, 15, 0, 0);
	decrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3, 14, 1, 0);
	decrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3, 13, 1, 1);
	decrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3, 12, 1, 1);
	decrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3, 11, 1, 1);
	decrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3, 10, 1, 1);
	decrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  9, 1, 1);
	decrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  8, 1, 1);
	decrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  7, 1, 1);
	decrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  6, 1, 1);
	decrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  5, 1, 1);
	decrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  4, 1, 1);
	decrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  3, 1, 1);
	decrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  2, 1, 1);
	decrypt_round(RC, RD, RA, RB, RT4, RT5, RT0, RT1, RT2, RT3,  1, 1, 1);
	decrypt_round(RA, RB, RC, RD, RT4, RT5, RT0, RT1, RT2, RT3,  0, 1, 1);

	add	RT4, CTXs0, #(w - s0);
	pop	{r1};					@ out

	ldm	RT4, {RT0, RT1, RT2, RT3};		@ Output whitening
	eor	RA, RA, RT0;
	eor	RB, RT1, RB, ror#1;			@ Final rotation of b
	eor	RC, RC, RT2;
	eor	RD, RT3, RD, ror#1;			@ Final rotation of d

#if __ARM_ARCH__<7
	str_unaligned_le(%r1, RA, RB, RC, RD, RT1, RT2, RT3);
#else
#ifndef __ARMEL__
	rev	RA, RA;
	rev	RB, RB;
	rev	RC, RC;
	rev	RD, RD;
#endif
	str_output_le(%r1, RA, RB, RC, RD);
#endif

	pop	{r4-r11, ip, pc};
ENDPROC(twofish_dec_blk)
