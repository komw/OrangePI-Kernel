#define __ARM_ARCH__ __LINUX_ARM_ARCH__
@
@ Serpent Cipher 1-way algorithm (ARM)
@
@ Based on crypto/serpent.c by
@  Copyright (C) 2002 Dag Arne Osvik <osvik@ii.uib.no>
@                2003 Herbert Valerio Riedel <hvr@gnu.org>
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

@**********************************************************************
@  1-way serpent
@
@ Some rotations are removed in favor of merging rotations with arithmetic
@ operations on ARM. On ARM, the second operand of arithmetic instruction
@ can be shifted or rotated by arbitrary distance without extra CPU cycles.
@ The rotations inside linear transformations rotate the results of arithmetic
@ instruction instead of one the inputs:
@ a = (b ^ c) >> n
@ This is easily decomposed into two instructions:
@ a = b ^ c
@ a = a >> n
@ Similarly,
@ a = (b >> n1) ^ (c >> n2)
@ that is easily decomposed into two instructions:
@ a = b ^ (c >> (n2 - n1))
@ a = a >> n1
@
@ This implementation only computes the first of the first instructions and
@ rotates a by, respectively, n or n1 the next time a is used as input.
@
@ See the paper "SHA-3 on ARM11 processors" by P. Schwabe, B-Y. Yang and
@ S-Y. Yang for discussion on merging rotations and arithmetic operations.
@**********************************************************************

#define RK  %r0

#define RA  %r3
#define RB  %r4
#define RC  %r5
#define RD  %r6

#define RE  %r7
#define RT1 %r7

#define RK0 %r8
#define RK1 %r9
#define RK2 %r10
#define RK3 %r11

#define RF  %r12
#define RT2 %r12

#define RT3 %r14

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

#define LK(x0, x1, x2, x3, x4, rk, k0, k1, k2, k3) \
	ldmia	rk!, {k0, k1, k2, k3}; \
	ror	x0, x0, #(32 - 13); \
	eor	x1, x1, x0; \
	ror	x2, x2, #(32 - 3); \
	eor	x3, x3, x2; \
	eor	x1, x1, x2; \
	eor	x3, x3, x0, lsl#3; \
	ror	x1, x1, #(32 - 1); \
	eor	x0, x0, x1; \
	eor	x2, x2, x3, ror#(32 - 7); \
	eor	x0, x0, x3, ror#(32 - 7); \
	eor	x2, x2, x1, lsl#7; \
	eor	x1, x1, k1; \
	eor	x3, k3, x3, ror#(32 - 7); \
	eor	x0, k0, x0, ror#(32 - 5); \
	eor 	x2, k2, x2, ror#(32 - 22);

#define KL(x0, x1, x2, x3, x4, rk, k0, k1, k2, k3) \
	eor	x0, x0, k0; \
	eor	x1, x1, k1; \
	eor	x2, x2, k2; \
	eor	x3, x3, k3; \
	eor	x2, x3, x2, ror#22; \
	eor	x0, x3, x0, ror#5; \
	eor	x2, x2, x1, lsl#7; \
	eor	x0, x0, x1; \
	ror	x3, x3, #7; \
	eor	x1, x0, x1, ror#1; \
	eor	x3, x3, x0, lsl#3; \
	eor	x1, x1, x2; \
	eor	x3, x3, x2; \
	ldmdb	rk!, {k0, k1, k2, k3};

#define S0(x0, x1, x2, x3, x4, x5) \
	orr	x5, x3, x0; \
	eor	x0, x0, x3; \
	eor	x4, x3, x2; \
	eor	x3, x5, x1; \
	mvn	x4, x4; \
	and	x1, x1, x0; \
	eor	x2, x2, x0; \
	eor	x1, x1, x4; \
	eor	x0, x0, x3; \
	orr	x4, x4, x0; \
	eor	x0, x0, x2; \
	and	x2, x2, x1; \
	eor	x3, x3, x2; \
	mvn	x1, x1; \
	eor	x2, x2, x4; \
	eor	x1, x1, x2;

#define S1(x0, x1, x2, x3, x4, x5) \
	eor	x5, x1, x0; \
	eor	x0, x0, x3; \
	mvn	x3, x3; \
	and	x4, x1, x5; \
	orr	x0, x0, x5; \
	eor	x3, x3, x2; \
	eor	x0, x0, x3; \
	eor	x1, x5, x3; \
	eor	x3, x3, x4; \
	orr	x1, x1, x4; \
	eor	x4, x4, x2; \
	and	x2, x2, x0; \
	eor	x2, x2, x1; \
	orr	x1, x1, x0; \
	mvn	x0, x0; \
	eor	x0, x0, x2; \
	eor	x4, x4, x1;

#define S2(x0, x1, x2, x3, x4, x5) \
	mvn	x3, x3; \
	eor	x1, x1, x0; \
	and	x5, x0, x2; \
	eor	x5, x5, x3; \
	orr	x3, x3, x0; \
	eor	x2, x2, x1; \
	eor	x3, x3, x1; \
	and	x1, x1, x5; \
	eor	x5, x5, x2; \
	and	x2, x2, x3; \
	orr	x3, x3, x1; \
	mvn	x5, x5; \
	eor	x3, x3, x5; \
	eor	x4, x0, x5; \
	eor	x0, x5, x2; \
	orr	x1, x1, x2;

#define S3(x0, x1, x2, x3, x4, x5) \
	eor	x5, x1, x3; \
	orr	x3, x3, x0; \
	and	x4, x1, x0; \
	eor	x0, x0, x2; \
	eor	x2, x2, x5; \
	and	x1, x5, x3; \
	eor	x2, x2, x3; \
	orr	x0, x0, x4; \
	eor	x4, x4, x3; \
	eor	x1, x1, x0; \
	and	x0, x0, x3; \
	and	x3, x3, x4; \
	eor	x3, x3, x2; \
	orr	x4, x4, x1; \
	and	x2, x2, x1; \
	eor	x4, x4, x3; \
	eor	x0, x0, x3; \
	eor	x3, x3, x2;

#define S4(x0, x1, x2, x3, x4, x5) \
	and	x5, x3, x0; \
	eor	x0, x0, x3; \
	eor	x5, x5, x2; \
	orr	x2, x2, x3; \
	eor	x0, x0, x1; \
	eor	x4, x3, x5; \
	orr	x2, x2, x0; \
	eor	x2, x2, x1; \
	and	x1, x1, x0; \
	eor	x1, x1, x4; \
	and	x4, x4, x2; \
	eor	x2, x2, x5; \
	eor	x4, x4, x0; \
	orr	x3, x5, x1; \
	mvn	x1, x1; \
	eor	x3, x3, x0;

#define S5(x0, x1, x2, x3, x4, x5) \
	orr	x5, x1, x0; \
	mvn	x3, x3; \
	eor	x2, x2, x5; \
	eor	x4, x1, x0; \
	eor	x0, x0, x2; \
	and	x1, x5, x4; \
	orr	x4, x4, x3; \
	eor	x1, x1, x3; \
	eor	x4, x4, x0; \
	and	x0, x0, x3; \
	eor	x3, x3, x2; \
	and	x2, x2, x4; \
	eor	x0, x0, x1; \
	eor	x1, x1, x2; \
	and	x2, x2, x0; \
	eor	x3, x3, x2;

#define S6(x0, x1, x2, x3, x4, x5) \
	eor	x3, x3, x0; \
	eor	x5, x1, x2; \
	eor	x2, x2, x0; \
	and	x0, x0, x3; \
	orr	x5, x5, x3; \
	mvn	x4, x1; \
	eor	x0, x0, x5; \
	eor	x1, x5, x2; \
	eor	x3, x3, x4; \
	eor	x4, x4, x0; \
	and	x2, x2, x0; \
	eor	x4, x4, x1; \
	eor	x2, x2, x3; \
	and	x3, x3, x1; \
	eor	x3, x3, x0; \
	eor	x1, x1, x2;

#define S7(x0, x1, x2, x3, x4, x5) \
	mvn	x4, x1; \
	mvn	x0, x0; \
	and	x1, x4, x2; \
	eor	x1, x1, x3; \
	orr	x3, x3, x4; \
	eor	x4, x4, x2; \
	eor	x2, x2, x3; \
	eor	x3, x3, x0; \
	orr	x0, x0, x1; \
	and	x2, x2, x0; \
	eor	x0, x0, x4; \
	eor	x4, x4, x3; \
	and	x3, x3, x0; \
	eor	x4, x4, x1; \
	eor	x2, x2, x4; \
	eor	x3, x3, x1; \
	orr	x4, x4, x0; \
	eor	x4, x4, x1;

#define SI0(x0, x1, x2, x3, x4, x5) \
	eor	x1, x1, x0, ror#13; \
	orr	x5, x3, x1; \
	eor	x4, x3, x1; \
	mvn	x0, x0; \
	eor	x2, x5, x2, ror#3; \
	eor	x3, x5, x0, ror#13; \
	and	x0, x1, x0, ror#13; \
	eor	x0, x0, x2; \
	and	x2, x2, x3; \
	eor	x3, x3, x4; \
	eor	x2, x2, x3; \
	eor	x1, x1, x3; \
	and	x3, x3, x0; \
	eor	x1, x1, x0; \
	eor	x0, x0, x2; \
	eor	x4, x4, x3;

#define SI1(x0, x1, x2, x3, x4, x5) \
	eor	x1, x1, x3; \
	eor	x5, x2, x0, ror#10; \
	mvn	x2, x2; \
	orr	x4, x1, x0, ror#13; \
	eor	x4, x4, x3; \
	and	x3, x3, x1; \
	eor	x1, x1, x2, ror#3; \
	and	x2, x4, x2, ror#3; \
	eor	x4, x4, x1; \
	orr	x1, x1, x3; \
	eor	x3, x3, x5, ror#3; \
	eor	x2, x2, x5, ror#3; \
	orr	x0, x4, x5, ror#3; \
	eor	x2, x2, x4; \
	eor	x1, x1, x0; \
	eor	x4, x4, x1;

#define SI2(x0, x1, x2, x3, x4, x5) \
	eor	x2, x1, x2, ror#3; \
	mvn	x5, x3; \
	orr	x5, x5, x2; \
	eor	x2, x2, x3; \
	eor	x4, x3, x0, ror#13; \
	eor	x3, x5, x1; \
	orr	x1, x1, x2; \
	eor	x2, x2, x0, ror#13; \
	eor	x1, x1, x4; \
	orr	x4, x4, x3; \
	eor	x2, x2, x3; \
	eor	x4, x4, x2; \
	and	x2, x2, x1; \
	eor	x2, x2, x3; \
	eor	x3, x3, x4; \
	eor	x4, x4, x0, ror#13;

#define SI3(x0, x1, x2, x3, x4, x5) \
	eor	x2, x1, x2, ror#3; \
	and	x5, x1, x2; \
	eor	x5, x5, x0, ror#13; \
	orr	x0, x1, x0, ror#13; \
	eor	x4, x1, x3; \
	eor	x0, x0, x3; \
	orr	x3, x3, x5; \
	eor	x1, x5, x2; \
	eor	x1, x1, x3; \
	eor	x0, x0, x2; \
	eor	x2, x2, x3; \
	and	x3, x3, x1; \
	eor	x1, x1, x0; \
	and	x0, x0, x2; \
	eor	x4, x4, x3; \
	eor	x3, x3, x0; \
	eor	x0, x0, x1;

#define SI4(x0, x1, x2, x3, x4, x5) \
	eor	x2, x3, x2, ror#3; \
	and	x5, x1, x0, ror#13; \
	eor	x5, x5, x2; \
	orr	x2, x2, x3; \
	mvn	x4, x0; \
	eor	x1, x1, x5; \
	eor	x0, x5, x2; \
	and	x2, x2, x4, ror#13; \
	eor	x2, x2, x0; \
	orr	x0, x0, x4, ror#13; \
	eor	x0, x0, x3; \
	and	x3, x3, x2; \
	eor	x4, x3, x4, ror#13; \
	eor	x3, x3, x1; \
	and	x1, x1, x0; \
	eor	x4, x4, x1; \
	eor	x0, x0, x3;

#define SI5(x0, x1, x2, x3, x4, x5) \
	orr	x5, x1, x2, ror#3; \
	eor	x2, x1, x2, ror#3; \
	eor	x5, x5, x3; \
	and	x3, x3, x1; \
	eor	x2, x2, x3; \
	orr	x3, x3, x0, ror#13; \
	mvn	x0, x0; \
	eor	x3, x3, x2; \
	orr	x2, x2, x0, ror#13; \
	eor	x4, x1, x5; \
	eor	x2, x2, x4; \
	and	x4, x4, x0, ror#13; \
	eor	x0, x5, x0, ror#13; \
	eor	x1, x5, x3; \
	and	x0, x0, x2; \
	eor	x2, x2, x3; \
	eor	x0, x0, x2; \
	eor	x2, x2, x4; \
	eor	x4, x4, x3;

#define SI6(x0, x1, x2, x3, x4, x5) \
	eor	x0, x2, x0, ror#10; \
	and	x5, x3, x0, ror#3; \
	eor	x2, x3, x2, ror#3; \
	eor	x5, x5, x2; \
	eor	x3, x3, x1; \
	orr	x2, x2, x0, ror#3; \
	eor	x2, x2, x3; \
	and	x3, x3, x5; \
	mvn	x5, x5; \
	eor	x3, x3, x1; \
	and	x1, x1, x2; \
	eor	x4, x5, x0, ror#3; \
	eor	x3, x3, x4; \
	eor	x4, x4, x2; \
	eor	x0, x5, x1; \
	eor	x2, x2, x0;

#define SI7(x0, x1, x2, x3, x4, x5) \
	and	x5, x3, x0, ror#13; \
	eor	x0, x2, x0, ror#10; \
	orr	x2, x3, x2, ror#3; \
	eor	x4, x3, x1; \
	mvn	x0, x0; \
	orr	x1, x1, x5; \
	eor	x4, x4, x0, ror#3; \
	and	x0, x2, x0, ror#3; \
	eor	x0, x0, x1; \
	and	x1, x1, x2; \
	eor	x3, x5, x2; \
	eor	x4, x4, x3; \
	and	x2, x2, x3; \
	orr	x3, x3, x0; \
	eor	x1, x1, x4; \
	eor	x3, x3, x4; \
	and	x4, x4, x0; \
	eor	x4, x4, x2;

#define SI8(x0, x1, x2, x3, x4, x5) \
	and	x5, x3, x0; \
	eor	x0, x0, x2; \
	orr	x2, x2, x3; \
	eor	x4, x3, x1; \
	mvn	x0, x0; \
	orr	x1, x1, x5; \
	eor	x4, x4, x0; \
	and	x0, x0, x2; \
	eor	x0, x0, x1; \
	and	x1, x1, x2; \
	eor	x3, x5, x2; \
	eor	x4, x4, x3; \
	and	x2, x2, x3; \
	orr	x3, x3, x0; \
	eor	x1, x1, x4; \
	eor	x3, x3, x4; \
	and	x4, x4, x0; \
	eor	x4, x4, x2;

ENTRY(serpent_enc_blk)
	stmdb	sp!, {r4-r11, ip, lr};

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

	ldmia	RK!, {RK0, RK1, RK2, RK3};
	eor	RA, RA, RK0;
	eor	RB, RB, RK1;
	eor	RC, RC, RK2;
	eor	RD, RD, RK3;

	S0(RA, RB, RC, RD, RE, RF);		LK(RC, RB, RD, RA, RE, RK, RK0, RK1, RK2, RK3);
	S1(RC, RB, RD, RA, RE, RF);		LK(RE, RD, RA, RC, RB, RK, RK0, RK1, RK2, RK3);
	S2(RE, RD, RA, RC, RB, RF);		LK(RB, RD, RE, RC, RA, RK, RK0, RK1, RK2, RK3);
	S3(RB, RD, RE, RC, RA, RF);		LK(RC, RA, RD, RB, RE, RK, RK0, RK1, RK2, RK3);
	S4(RC, RA, RD, RB, RE, RF);		LK(RA, RD, RB, RE, RC, RK, RK0, RK1, RK2, RK3);
	S5(RA, RD, RB, RE, RC, RF);		LK(RC, RA, RD, RE, RB, RK, RK0, RK1, RK2, RK3);
	S6(RC, RA, RD, RE, RB, RF);		LK(RD, RB, RA, RE, RC, RK, RK0, RK1, RK2, RK3);
	S7(RD, RB, RA, RE, RC, RF);		LK(RC, RA, RE, RD, RB, RK, RK0, RK1, RK2, RK3);
	S0(RC, RA, RE, RD, RB, RF);		LK(RE, RA, RD, RC, RB, RK, RK0, RK1, RK2, RK3);
	S1(RE, RA, RD, RC, RB, RF);		LK(RB, RD, RC, RE, RA, RK, RK0, RK1, RK2, RK3);
	S2(RB, RD, RC, RE, RA, RF);		LK(RA, RD, RB, RE, RC, RK, RK0, RK1, RK2, RK3);
	S3(RA, RD, RB, RE, RC, RF);		LK(RE, RC, RD, RA, RB, RK, RK0, RK1, RK2, RK3);
	S4(RE, RC, RD, RA, RB, RF);		LK(RC, RD, RA, RB, RE, RK, RK0, RK1, RK2, RK3);
	S5(RC, RD, RA, RB, RE, RF);		LK(RE, RC, RD, RB, RA, RK, RK0, RK1, RK2, RK3);
	S6(RE, RC, RD, RB, RA, RF);		LK(RD, RA, RC, RB, RE, RK, RK0, RK1, RK2, RK3);
	S7(RD, RA, RC, RB, RE, RF);		LK(RE, RC, RB, RD, RA, RK, RK0, RK1, RK2, RK3);
	S0(RE, RC, RB, RD, RA, RF);		LK(RB, RC, RD, RE, RA, RK, RK0, RK1, RK2, RK3);
	S1(RB, RC, RD, RE, RA, RF);		LK(RA, RD, RE, RB, RC, RK, RK0, RK1, RK2, RK3);
	S2(RA, RD, RE, RB, RC, RF);		LK(RC, RD, RA, RB, RE, RK, RK0, RK1, RK2, RK3);
	S3(RC, RD, RA, RB, RE, RF);		LK(RB, RE, RD, RC, RA, RK, RK0, RK1, RK2, RK3);
	S4(RB, RE, RD, RC, RA, RF);		LK(RE, RD, RC, RA, RB, RK, RK0, RK1, RK2, RK3);
	S5(RE, RD, RC, RA, RB, RF);		LK(RB, RE, RD, RA, RC, RK, RK0, RK1, RK2, RK3);
	S6(RB, RE, RD, RA, RC, RF);		LK(RD, RC, RE, RA, RB, RK, RK0, RK1, RK2, RK3);
	S7(RD, RC, RE, RA, RB, RF);		LK(RB, RE, RA, RD, RC, RK, RK0, RK1, RK2, RK3);
	S0(RB, RE, RA, RD, RC, RF);		LK(RA, RE, RD, RB, RC, RK, RK0, RK1, RK2, RK3);
	S1(RA, RE, RD, RB, RC, RF);		LK(RC, RD, RB, RA, RE, RK, RK0, RK1, RK2, RK3);
	S2(RC, RD, RB, RA, RE, RF);		LK(RE, RD, RC, RA, RB, RK, RK0, RK1, RK2, RK3);
	S3(RE, RD, RC, RA, RB, RF);		LK(RA, RB, RD, RE, RC, RK, RK0, RK1, RK2, RK3);
	S4(RA, RB, RD, RE, RC, RF);		LK(RB, RD, RE, RC, RA, RK, RK0, RK1, RK2, RK3);
	S5(RB, RD, RE, RC, RA, RF);		LK(RA, RB, RD, RC, RE, RK, RK0, RK1, RK2, RK3);
	S6(RA, RB, RD, RC, RE, RF);		LK(RD, RE, RB, RC, RA, RK, RK0, RK1, RK2, RK3);
	S7(RD, RE, RB, RC, RA, RF);

	ldmia	RK!, {RK0, RK1, RK2, RK3};
	eor	RA, RA, RK0;
	eor	RB, RB, RK1;
	eor	RC, RC, RK2;
	eor	RD, RD, RK3;

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
ENDPROC(serpent_enc_blk)

ENTRY(serpent_dec_blk)
	stmdb	sp!, {r4-r11, ip, lr};

	add	RK, RK, #(33*4*4);			@ Point to the end of table

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

	ldmdb	RK!, {RK0, RK1, RK2, RK3};
	eor	RA, RA, RK0;
	eor	RB, RB, RK1;
	eor	RC, RC, RK2;
	eor	RD, RD, RK3;

	ldmdb	RK!, {RK0, RK1, RK2, RK3};		@Prefetch key for the next round

	SI8(RA, RB, RC, RD, RE, RF);	KL(RB, RD, RA, RE, RC, RK, RK0, RK1, RK2, RK3);
	SI6(RB, RD, RA, RE, RC, RF);	KL(RA, RC, RE, RB, RD, RK, RK0, RK1, RK2, RK3);
	SI5(RA, RC, RE, RB, RD, RF);	KL(RC, RD, RA, RE, RB, RK, RK0, RK1, RK2, RK3);
	SI4(RC, RD, RA, RE, RB, RF);	KL(RC, RA, RB, RE, RD, RK, RK0, RK1, RK2, RK3);
	SI3(RC, RA, RB, RE, RD, RF);	KL(RB, RC, RD, RE, RA, RK, RK0, RK1, RK2, RK3);
	SI2(RB, RC, RD, RE, RA, RF);	KL(RC, RA, RE, RD, RB, RK, RK0, RK1, RK2, RK3);
	SI1(RC, RA, RE, RD, RB, RF);	KL(RB, RA, RE, RD, RC, RK, RK0, RK1, RK2, RK3);
	SI0(RB, RA, RE, RD, RC, RF);	KL(RE, RC, RA, RB, RD, RK, RK0, RK1, RK2, RK3);
	SI7(RE, RC, RA, RB, RD, RF);	KL(RC, RB, RE, RD, RA, RK, RK0, RK1, RK2, RK3);
	SI6(RC, RB, RE, RD, RA, RF);	KL(RE, RA, RD, RC, RB, RK, RK0, RK1, RK2, RK3);
	SI5(RE, RA, RD, RC, RB, RF);	KL(RA, RB, RE, RD, RC, RK, RK0, RK1, RK2, RK3);
	SI4(RA, RB, RE, RD, RC, RF);	KL(RA, RE, RC, RD, RB, RK, RK0, RK1, RK2, RK3);
	SI3(RA, RE, RC, RD, RB, RF);	KL(RC, RA, RB, RD, RE, RK, RK0, RK1, RK2, RK3);
	SI2(RC, RA, RB, RD, RE, RF);	KL(RA, RE, RD, RB, RC, RK, RK0, RK1, RK2, RK3);
	SI1(RA, RE, RD, RB, RC, RF);	KL(RC, RE, RD, RB, RA, RK, RK0, RK1, RK2, RK3);
	SI0(RC, RE, RD, RB, RA, RF);	KL(RD, RA, RE, RC, RB, RK, RK0, RK1, RK2, RK3);
	SI7(RD, RA, RE, RC, RB, RF);	KL(RA, RC, RD, RB, RE, RK, RK0, RK1, RK2, RK3);
	SI6(RA, RC, RD, RB, RE, RF);	KL(RD, RE, RB, RA, RC, RK, RK0, RK1, RK2, RK3);
	SI5(RD, RE, RB, RA, RC, RF);	KL(RE, RC, RD, RB, RA, RK, RK0, RK1, RK2, RK3);
	SI4(RE, RC, RD, RB, RA, RF);	KL(RE, RD, RA, RB, RC, RK, RK0, RK1, RK2, RK3);
	SI3(RE, RD, RA, RB, RC, RF);	KL(RA, RE, RC, RB, RD, RK, RK0, RK1, RK2, RK3);
	SI2(RA, RE, RC, RB, RD, RF);	KL(RE, RD, RB, RC, RA, RK, RK0, RK1, RK2, RK3);
	SI1(RE, RD, RB, RC, RA, RF);	KL(RA, RD, RB, RC, RE, RK, RK0, RK1, RK2, RK3);
	SI0(RA, RD, RB, RC, RE, RF);	KL(RB, RE, RD, RA, RC, RK, RK0, RK1, RK2, RK3);
	SI7(RB, RE, RD, RA, RC, RF);	KL(RE, RA, RB, RC, RD, RK, RK0, RK1, RK2, RK3);
	SI6(RE, RA, RB, RC, RD, RF);	KL(RB, RD, RC, RE, RA, RK, RK0, RK1, RK2, RK3);
	SI5(RB, RD, RC, RE, RA, RF);	KL(RD, RA, RB, RC, RE, RK, RK0, RK1, RK2, RK3);
	SI4(RD, RA, RB, RC, RE, RF);	KL(RD, RB, RE, RC, RA, RK, RK0, RK1, RK2, RK3);
	SI3(RD, RB, RE, RC, RA, RF);	KL(RE, RD, RA, RC, RB, RK, RK0, RK1, RK2, RK3);
	SI2(RE, RD, RA, RC, RB, RF);	KL(RD, RB, RC, RA, RE, RK, RK0, RK1, RK2, RK3);
	SI1(RD, RB, RC, RA, RE, RF);	KL(RE, RB, RC, RA, RD, RK, RK0, RK1, RK2, RK3);
	SI0(RE, RB, RC, RA, RD, RF);

	eor	RC, RC, RK0;
	eor	RD, RD, RK1;
	eor	RB, RB, RK2;
	eor	RE, RE, RK3;

#if __ARM_ARCH__<7
	str_unaligned_le(%r1, RC, RD, RB, RE, RT1, RT2, RT3);
#else
#ifndef __ARMEL__
	rev	RC, RC;
	rev	RD, RD;
	rev	RB, RB;
	rev	RE, RE;
#endif
	str_output_le(%r1, RC, RD, RB, RE);
#endif

	pop	{r4-r11, ip, pc};
ENDPROC(serpent_dec_blk)
