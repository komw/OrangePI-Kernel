/* twofish-armv7-neon.S  -  ARM/NEON assembly implementation of Twofish cipher
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/cache.h>

#include "glue_helper-asm-neon.S"

.text
.align 4
.fpu neon

/* Structure of twofish_ctx */
#define s0 0
#define s1 ((s0) + 4 * 256)
#define s2 ((s1) + 4 * 256)
#define s3 ((s2) + 4 * 256)
#define w  ((s3) + 4 * 256)
#define k  ((w) + 4 * 8)

/* ARM registers */
#define CTX    r0
#define CTXs0  r0
#define CTXs1  r1
#define CTXs2  r2
#define CTXs3  r3

#define RROUND lr

/* NEON vector registers */
#define RA0 q0
#define RA1 q1
#define RA2 q2
#define RA3 q3

#define RB0 q4
#define RB1 q5
#define RB2 q6
#define RB3 q7

#define RX  q8
#define RY  q9

#define RT0 q10
#define RT1 q11
#define RT2 q12
#define RT3 q13
#define RT4 q14
#define RT5 q15

#define RA0d0 d0
#define RA0d1 d1
#define RA1d0 d2
#define RA1d1 d3
#define RA2d0 d4
#define RA2d1 d5
#define RA3d0 d6
#define RA3d1 d7
#define RB0d0 d8
#define RB0d1 d9
#define RB1d0 d10
#define RB1d1 d11
#define RB2d0 d12
#define RB2d1 d13
#define RB3d0 d14
#define RB3d1 d15
#define RXd0  d16
#define RXd1  d17
#define RYd0  d18
#define RYd1  d19
#define RT0d0 d20
#define RT0d1 d21
#define RT1d0 d22
#define RT1d1 d23
#define RT2d0 d24
#define RT2d1 d25
#define RT3d0 d26
#define RT3d1 d27
#define RT4d0 d28
#define RT4d1 d29
#define RT5d0 d30
#define RT5d1 d31

/**********************************************************************
  8-way twofish
 **********************************************************************/

#ifdef __ARMEL__
#define T_TABLE_LOOKUP(rt, a, b, rv1, rv2, x, y, na, nb, t0, t1, t2, t3) \
	/* Load a and right rotate rv1 */ \
	ldrb r4, [rt, #0]; \
	ldrb r5, [rt, #1]; \
	ldrb r6, [rt, #4]; \
	ldrb r7, [rt, #5];		add r4, CTXs0, r4, lsl #2; \
	ldrb r8, [rt, #2];		add r5, CTXs1, r5, lsl #2; \
	ldrb r9, [rt, #3];		add r6, CTXs0, r6, lsl #2; \
	ldrb r10, [rt, #6];		add r7, CTXs1, r7, lsl #2; \
	ldrb r11, [rt, #7];		add r8, CTXs2, r8, lsl #2; \
	vld1.32 {t0##d0[0]}, [r4,:32];	add r9, CTXs3, r9, lsl #2; \
	vld1.32 {t1##d0[0]}, [r5,:32];	add r10, CTXs2, r10, lsl #2; \
	vld1.32 {t0##d0[1]}, [r6,:32];	add r11, CTXs3, r11, lsl #2; \
	vld1.32 {t1##d0[1]}, [r7,:32];	vshl.u32 x, rv1, #(32 - 1); \
	vld1.32 {t2##d0[0]}, [r8,:32];	vshr.u32 rv1, rv1, #1; \
	vld1.32 {t3##d0[0]}, [r9,:32];	ldrb r4, [rt, #8]; \
	vld1.32 {t2##d0[1]}, [r10,:32];	ldrb r5, [rt, #9]; \
	vld1.32 {t3##d0[1]}, [r11,:32];	ldrb r6, [rt, #12]; \
	\
	ldrb r7, [rt, #13];		add r4, CTXs0, r4, lsl #2; \
	ldrb r8, [rt, #10];		add r5, CTXs1, r5, lsl #2; \
	ldrb r9, [rt, #11];		add r6, CTXs0, r6, lsl #2; \
	ldrb r10, [rt, #14];		add r7, CTXs1, r7, lsl #2; \
	ldrb r11, [rt, #15];		add r8, CTXs2, r8, lsl #2; \
	vld1.32 {t0##d1[0]}, [r4,:32];	add r9, CTXs3, r9, lsl #2; \
	vld1.32 {t1##d1[0]}, [r5,:32];	add r10, CTXs2, r10, lsl #2; \
	vld1.32 {t0##d1[1]}, [r6,:32];	add r11, CTXs3, r11, lsl #2; \
	vld1.32 {t1##d1[1]}, [r7,:32];	ldrb r4, [rt, #16]; \
	vld1.32 {t2##d1[0]}, [r8,:32];	veor rv1, rv1, x; \
	vld1.32 {t3##d1[0]}, [r9,:32];	veor x, t0, t1;\
	vld1.32 {t2##d1[1]}, [r10,:32];	ldrb r5, [rt, #17]; \
	vld1.32 {t3##d1[1]}, [r11,:32];	ldrb r6, [rt, #20]; \
	\
	/* Store next a */ \
	vst1.32 {na}, [rt, :128];	veor x,  x, t2; \
	\
	/* Load b and left rotate rv */ \
	ldrb r7, [rt, #21];		add r4, CTXs1, r4, lsl #2; \
	ldrb r8, [rt, #18];		add r5, CTXs2, r5, lsl #2; \
	ldrb r9, [rt, #19];		add r6, CTXs1, r6, lsl #2; \
	ldrb r10, [rt, #22];		add r7, CTXs2, r7, lsl #2; \
	ldrb r11, [rt, #23];		add r8, CTXs3, r8, lsl #2; \
	vld1.32 {t0##d0[0]}, [r4,:32];	add r9, CTXs0, r9, lsl #2; \
	vld1.32 {t1##d0[0]}, [r5,:32];	add r10, CTXs3, r10, lsl #2; \
	vld1.32 {t0##d0[1]}, [r6,:32];	add r11, CTXs0, r11, lsl #2; \
	vld1.32 {t1##d0[1]}, [r7,:32]; \
	vld1.32 {t2##d0[0]}, [r8,:32];	veor x,  x, t3; \
	vld1.32 {t3##d0[0]}, [r9,:32];	ldrb r4, [rt, #24]; \
	vld1.32 {t2##d0[1]}, [r10,:32];	ldrb r5, [rt, #25]; \
	vld1.32 {t3##d0[1]}, [r11,:32];	ldrb r6, [rt, #28]; \
	\
	ldrb r7, [rt, #29];		add r4, CTXs1, r4, lsl #2; \
	ldrb r8, [rt, #26];		add r5, CTXs2, r5, lsl #2; \
	ldrb r9, [rt, #27];		add r6, CTXs1, r6, lsl #2; \
	ldrb r10, [rt, #30];		add r7, CTXs2, r7, lsl #2; \
	ldrb r11, [rt, #31];		add r8, CTXs3, r8, lsl #2; \
	vld1.32 {t0##d1[0]}, [r4,:32];	add r9, CTXs0, r9, lsl #2; \
	vld1.32 {t1##d1[0]}, [r5,:32];	add r10, CTXs3, r10, lsl #2; \
	vld1.32 {t0##d1[1]}, [r6,:32];	add r11, CTXs0, r11, lsl #2; \
	vld1.32 {t1##d1[1]}, [r7,:32];	add r4, rt, #16; \
	vld1.32 {t2##d1[0]}, [r8,:32]; \
	vld1.32 {t3##d1[0]}, [r9,:32]; \
	vld1.32 {t2##d1[1]}, [r10,:32];	veor y, t0, t1;\
					vshr.u32 t0, rv2, #(32 - 1); \
	vld1.32 {t3##d1[1]}, [r11,:32];	vshl.u32 rv2, rv2, #1; \
	\
	/* Store next b */ \
	veor y,  y, t2; \
	vst1.32 {nb}, [r4, :128]; \
	veor rv2, rv2, t0;		veor y,  y, t3;
#else
#define T_TABLE_LOOKUP(rt, a, b, rv1, rv2, x, y, na, nb, t0, t1, t2, t3) \
	/* Load a and right rotate rv1 */ \
	ldrb r4, [rt, #0]; \
	ldrb r5, [rt, #1]; \
	ldrb r6, [rt, #4]; \
	ldrb r7, [rt, #5];		add r4, CTXs3, r4, lsl #2; \
	ldrb r8, [rt, #2];		add r5, CTXs2, r5, lsl #2; \
	ldrb r9, [rt, #3];		add r6, CTXs3, r6, lsl #2; \
	ldrb r10, [rt, #6];		add r7, CTXs2, r7, lsl #2; \
	ldrb r11, [rt, #7];		add r8, CTXs1, r8, lsl #2; \
	vld1.32 {t0##d0[0]}, [r4,:32];	add r9, CTXs0, r9, lsl #2; \
	vld1.32 {t1##d0[0]}, [r5,:32];	add r10, CTXs1, r10, lsl #2; \
	vld1.32 {t0##d0[1]}, [r6,:32];	add r11, CTXs0, r11, lsl #2; \
	vld1.32 {t1##d0[1]}, [r7,:32];	vshl.u32 x, rv1, #(32 - 1); \
	vld1.32 {t2##d0[0]}, [r8,:32];	vshr.u32 rv1, rv1, #1; \
	vld1.32 {t3##d0[0]}, [r9,:32];	ldrb r4, [rt, #8]; \
	vld1.32 {t2##d0[1]}, [r10,:32];	ldrb r5, [rt, #9]; \
	vld1.32 {t3##d0[1]}, [r11,:32];	ldrb r6, [rt, #12]; \
	\
	ldrb r7, [rt, #13];		add r4, CTXs3, r4, lsl #2; \
	ldrb r8, [rt, #10];		add r5, CTXs2, r5, lsl #2; \
	ldrb r9, [rt, #11];		add r6, CTXs3, r6, lsl #2; \
	ldrb r10, [rt, #14];		add r7, CTXs2, r7, lsl #2; \
	ldrb r11, [rt, #15];		add r8, CTXs1, r8, lsl #2; \
	vld1.32 {t0##d1[0]}, [r4,:32];	add r9, CTXs0, r9, lsl #2; \
	vld1.32 {t1##d1[0]}, [r5,:32];	add r10, CTXs1, r10, lsl #2; \
	vld1.32 {t0##d1[1]}, [r6,:32];	add r11, CTXs0, r11, lsl #2; \
	vld1.32 {t1##d1[1]}, [r7,:32];	ldrb r4, [rt, #16]; \
	vld1.32 {t2##d1[0]}, [r8,:32];	veor rv1, rv1, x; \
	vld1.32 {t3##d1[0]}, [r9,:32];	veor x, t0, t1;\
	vld1.32 {t2##d1[1]}, [r10,:32];	ldrb r5, [rt, #17]; \
	vld1.32 {t3##d1[1]}, [r11,:32];	ldrb r6, [rt, #20]; \
	\
	/* Store next a */ \
	vst1.32 {na}, [rt, :128];	veor x,  x, t2; \
	\
	/* Load b and left rotate rv */ \
	ldrb r7, [rt, #21];		add r4, CTXs0, r4, lsl #2; \
	ldrb r8, [rt, #18];		add r5, CTXs3, r5, lsl #2; \
	ldrb r9, [rt, #19];		add r6, CTXs0, r6, lsl #2; \
	ldrb r10, [rt, #22];		add r7, CTXs3, r7, lsl #2; \
	ldrb r11, [rt, #23];		add r8, CTXs2, r8, lsl #2; \
	vld1.32 {t0##d0[0]}, [r4,:32];	add r9, CTXs1, r9, lsl #2; \
	vld1.32 {t1##d0[0]}, [r5,:32];	add r10, CTXs2, r10, lsl #2; \
	vld1.32 {t0##d0[1]}, [r6,:32];	add r11, CTXs1, r11, lsl #2; \
	vld1.32 {t1##d0[1]}, [r7,:32]; \
	vld1.32 {t2##d0[0]}, [r8,:32];	veor x,  x, t3; \
	vld1.32 {t3##d0[0]}, [r9,:32];	ldrb r4, [rt, #24]; \
	vld1.32 {t2##d0[1]}, [r10,:32];	ldrb r5, [rt, #25]; \
	vld1.32 {t3##d0[1]}, [r11,:32];	ldrb r6, [rt, #28]; \
	\
	ldrb r7, [rt, #29];		add r4, CTXs0, r4, lsl #2; \
	ldrb r8, [rt, #26];		add r5, CTXs3, r5, lsl #2; \
	ldrb r9, [rt, #27];		add r6, CTXs0, r6, lsl #2; \
	ldrb r10, [rt, #30];		add r7, CTXs3, r7, lsl #2; \
	ldrb r11, [rt, #31];		add r8, CTXs2, r8, lsl #2; \
	vld1.32 {t0##d1[0]}, [r4,:32];	add r9, CTXs1, r9, lsl #2; \
	vld1.32 {t1##d1[0]}, [r5,:32];	add r10, CTXs2, r10, lsl #2; \
	vld1.32 {t0##d1[1]}, [r6,:32];	add r11, CTXs1, r11, lsl #2; \
	vld1.32 {t1##d1[1]}, [r7,:32];	add r4, rt, #16; \
	vld1.32 {t2##d1[0]}, [r8,:32]; \
	vld1.32 {t3##d1[0]}, [r9,:32]; \
	vld1.32 {t2##d1[1]}, [r10,:32];	veor y, t0, t1;\
					vshr.u32 t0, rv2, #(32 - 1); \
	vld1.32 {t3##d1[1]}, [r11,:32];	vshl.u32 rv2, rv2, #1; \
	\
	/* Store next b */ \
	veor y,  y, t2; \
	vst1.32 {nb}, [r4, :128]; \
	veor rv2, rv2, t0;		veor y,  y, t3;
#endif

/* Apply a Twofish round to eight parallel blocks */
#define ENCRYPT_ROUND(n, x, y, c, d, rk, t0, t1, t2, t3) \
	/* k[2*n + 1] */ \
	vdup.32 t2, rk[1]; \
	/* x += y */ \
	vadd.u32 x, x, y; \
	/* k[2*n] */ \
	vdup.32 t1, rk[0]; \
	/* x + k[2*n + 1] */ \
	vadd.u32 t2, t2, x; \
	/* x + k[2*n] */ \
	vadd.u32 t1, t1, x; \
	/* y += x + k[2*n + 1] */ \
	vadd.u32 y, y, t2; \
	/* c ^= x + k[2*n] */ \
	veor c, c, t1; \
	/* d ^= y */ \
	veor d, d, y;

/* Apply an inverse Twofish round to eight parallel blocks */
#define DECRYPT_ROUND(n, x, y, c, d, rk, t0, t1, t2, t3) \
	/* k[2*n + 1] */ \
	vdup.32 t2, rk[1]; \
	/* x += y */ \
	vadd.u32 x, x, y; \
	/* k[2*n] */ \
	vdup.32 t1, rk[0]; \
	/* x + k[2*n + 1] */ \
	vadd.u32 t2, t2, x; \
	/* x + k[2*n] */ \
	vadd.u32 t1, t1, x; \
	/* y += x + k[2*n + 1] */ \
	vadd.u32 y, y, t2; \
	/* c ^= x + k[2*n] */ \
	veor c, c, t1; \
	/* d ^= y */ \
	veor d, d, y;

.type __twofish_enc_blk8_neon,%function
.align 4
__twofish_enc_blk8_neon:
	/* input:
	 *	r0: twofish_ctx pointer
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel plaintext
	 *						blocks
	 * output:
	 *	RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1: eight parallel
	 * 						ciphertext blocks
	 */

	str	lr,[sp,#-4]!;
	mov	r12, sp;

	/* Allocate space for a and b */
	sub	sp, sp, #2*4*4;
	bic	sp, #0x0f;

	/* Calculate table pointers */
	add	CTXs3, CTXs0, #(s3 - s0);
	add	CTXs1, CTXs0, #(s1 - s0);
	add	CTXs2, CTXs0, #(s2 - s0);

#ifndef __ARMEL__
	vrev32.8 RA0, RA0;	vrev32.8 RB0, RB0;
	vrev32.8 RA1, RA1;	vrev32.8 RB1, RB1;
	vrev32.8 RA2, RA2;	vrev32.8 RB2, RB2;
	vrev32.8 RA3, RA3;	vrev32.8 RB3, RB3;
#endif

	add	r9, sp, #0;
	add	r10, CTXs3, #(w - s3);
	add	r11, sp, #16;
	add	RROUND, CTXs3, #(k - s3);

	/* Load whitening key */
	vld1.32 {RT0}, [r10, :64];

	/* Store zero value in RT5 */
	veor RT5, RT4, RT4;

	/* Input whitening */
	veor RA0, RA0, RT0;	veor RB0, RB0, RT0;
	veor RA1, RA1, RT0;	veor RB1, RB1, RT0;
	veor RA2, RA2, RT0;	veor RB2, RB2, RT0;
	veor RA3, RA3, RT0;	veor RB3, RB3, RT0;

	/* Transpose 4x4 */
	vtrn.32 RA0, RA1;	vtrn.32 RB0, RB1;
	vtrn.32 RA2, RA3;	vtrn.32 RB2, RB3;
	vswp RA0d1, RA2d0;	vswp RB0d1, RB2d0;
	vswp RA1d1, RA3d0;	vswp RB1d1, RB3d0;

	/* Store a and b */
	vst1.32 {RA0}, [r9, :128];
	vst1.32 {RA1}, [r11, :128];

	/* Rounds */
	vld1.32 {RT4}, [RROUND, :64]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RT5, RA3, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(0, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA2, RB3, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(0, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RB2, RA1, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(1, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA0, RB1, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(1, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB0, RA3, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(2, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA2, RB3, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(2, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RB2, RA1, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(3, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA0, RB1, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(3, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB0, RA3, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(4, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA2, RB3, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(4, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RB2, RA1, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(5, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA0, RB1, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(5, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB0, RA3, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(6, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA2, RB3, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(6, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RB2, RA1, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(7, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA0, RB1, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(7, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB0, RA3, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(8, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA2, RB3, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(8, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RB2, RA1, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(9, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA0, RB1, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(9, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB0, RA3, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(10, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA2, RB3, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(10, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RB2, RA1, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(11, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA0, RB1, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(11, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB0, RA3, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(12, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA2, RB3, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(12, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RB2, RA1, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(13, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA0, RB1, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(13, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA0, RA1, RB0, RA3, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(14, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA2, RB3, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(14, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	/* Load pointer to whitening key */
	add	RROUND, CTXs3, #(w + 4*4 - s3);

	/* During last round we wipe data on stack using RT5 */
	T_TABLE_LOOKUP(sp, RA2, RA3, RB2, RA1, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(15, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA0, RB1, RX, RY, RT5, RT5, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(15, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	/* Load whitening key */
	vld1.32 {RT0}, [RROUND, :64];

	/* Right rotate final c */
	vshl.u32 RX, RB0, #(32 - 1);
	vshr.u32 RB0, RB0, #1;
	veor RB0, RB0, RX;

	/* Transpose 4x4 */
	vtrn.32 RA2, RA3;	vtrn.32 RB2, RB3;
	vtrn.32 RA0, RA1;	vtrn.32 RB0, RB1;
	vswp RA2d1, RA0d0;	vswp RB2d1, RB0d0;
	vswp RA3d1, RA1d0;	vswp RB3d1, RB1d0;

	/* Output whitening */
	veor RA2, RA2, RT0;	veor RB2, RB2, RT0;
	veor RA3, RA3, RT0;	veor RB3, RB3, RT0;
	veor RA0, RA0, RT0;	veor RB0, RB0, RT0;
	veor RA1, RA1, RT0;	veor RB1, RB1, RT0;

#ifndef __ARMEL__
	vrev32.8 RA2, RA2;	vrev32.8 RB2, RB2;
	vrev32.8 RA3, RA3;	vrev32.8 RB3, RB3;
	vrev32.8 RA0, RA0;	vrev32.8 RB0, RB0;
	vrev32.8 RA1, RA1;	vrev32.8 RB1, RB1;
#endif

	/* Restore stack pointer */
	mov	sp, r12;
	pop	{lr};

	bx lr;
.size __twofish_enc_blk8_neon,.-__twofish_enc_blk8_neon

.type __twofish_dec_blk8_neon,%function
.align 4
__twofish_dec_blk8_neon:
	/* input:
	 *	r0: twofish_ctx pointer
	 *	RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1: eight parallel
	 * 						ciphertext blocks
	 * output:
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel plaintext
	 *						blocks
	 */

	str	lr,[sp,#-4]!;
	mov	r12, sp;

	/* Allocate space for a and b */
	sub	sp, sp, #2*4*4;
	bic	sp, #0x0f;

	/* Calculate table pointers */
	add	CTXs3, CTXs0, #(s3 - s0);
	add	CTXs1, CTXs0, #(s1 - s0);
	add	CTXs2, CTXs0, #(s2 - s0);

#ifndef __ARMEL__
	vrev32.8 RA2, RA2;	vrev32.8 RB2, RB2;
	vrev32.8 RA3, RA3;	vrev32.8 RB3, RB3;
	vrev32.8 RA0, RA0;	vrev32.8 RB0, RB0;
	vrev32.8 RA1, RA1;	vrev32.8 RB1, RB1;
#endif

	add	r9, sp, #0;
	add	r10, CTXs3, #(w + 4*4 - s3);
	add	r11, sp, #16;
	add	RROUND, CTXs3, #(k - s3 + 8 * 14);

	/* Load whitening key */
	vld1.32 {RT0}, [r10, :64];

	/* Store zero value in RT5 */
	veor RT5, RT4, RT4;

	veor RA2, RA2, RT0;	veor RB2, RB2, RT0;
	veor RA3, RA3, RT0;	veor RB3, RB3, RT0;
	veor RA0, RA0, RT0;	veor RB0, RB0, RT0;
	veor RA1, RA1, RT0;	veor RB1, RB1, RT0;

	/* Transpose 4x4 */
	vtrn.32 RA2, RA3;	vtrn.32 RB2, RB3;
	vtrn.32 RA0, RA1;	vtrn.32 RB0, RB1;
	vswp RA2d1, RA0d0;	vswp RB2d1, RB0d0;
	vswp RA3d1, RA1d0;	vswp RB3d1, RB1d0;

	/* Store a and b */
	vst1.32 {RA2}, [r9, :128];
	vst1.32 {RA3}, [r11, :128];

	/* Rounds */
	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA2, RA3, RT5, RA0, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(15, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA1, RB0, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(15, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB1, RA2, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(14, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA3, RB2, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(14, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA2, RA3, RB3, RA0, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(13, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA1, RB0, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(13, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB1, RA2, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(12, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA3, RB2, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(12, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA2, RA3, RB3, RA0, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(11, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA1, RB0, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(11, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB1, RA2, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(10, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA3, RB2, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(10, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA2, RA3, RB3, RA0, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(9, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA1, RB0, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(9, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB1, RA2, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(8, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA3, RB2, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(8, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA2, RA3, RB3, RA0, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(7, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA1, RB0, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(7, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB1, RA2, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(6, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA3, RB2, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(6, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA2, RA3, RB3, RA0, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(5, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA1, RB0, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(5, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB1, RA2, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(4, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA3, RB2, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(4, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA2, RA3, RB3, RA0, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(3, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA1, RB0, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(3, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RB1, RA2, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(2, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA3, RB2, RX, RY, RA2, RA3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(2, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND, :64];

	T_TABLE_LOOKUP(sp, RA2, RA3, RB3, RA0, RX, RY, RB2, RB3, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(1, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RA1, RB0, RX, RY, RA0, RA1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(1, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	/* Load pointer to whitening key */
	add	RROUND, CTXs3, #(w - s3);

	/* During last round we wipe data on stack using RT5 */
	T_TABLE_LOOKUP(sp, RA0, RA1, RB1, RA2, RX, RY, RB0, RB1, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(0, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RA3, RB2, RX, RY, RT5, RT5, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(0, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	/* Load whitening key */
	vld1.32 {RT0}, [RROUND, :64];

	/* Right rotate final d */
	vshl.u32 RX, RB3, #(32 - 1);
	vshr.u32 RB3, RB3, #1;
	veor RB3, RB3, RX;

	/* Transpose 4x4 */
	vtrn.32 RA0, RA1;	vtrn.32 RB0, RB1;
	vtrn.32 RA2, RA3;	vtrn.32 RB2, RB3;
	vswp RA0d1, RA2d0;	vswp RB0d1, RB2d0;
	vswp RA1d1, RA3d0;	vswp RB1d1, RB3d0;

	/* Output whitening */
	veor RA0, RA0, RT0;	veor RB0, RB0, RT0;
	veor RA1, RA1, RT0;	veor RB1, RB1, RT0;
	veor RA2, RA2, RT0;	veor RB2, RB2, RT0;
	veor RA3, RA3, RT0;	veor RB3, RB3, RT0;

#ifndef __ARMEL__
	vrev32.8 RA0, RA0;	vrev32.8 RB0, RB0;
	vrev32.8 RA1, RA1;	vrev32.8 RB1, RB1;
	vrev32.8 RA2, RA2;	vrev32.8 RB2, RB2;
	vrev32.8 RA3, RA3;	vrev32.8 RB3, RB3;
#endif

	/* Restore stack pointer */
	mov	sp, r12;
	pop	{lr};

	bx lr;
.size __twofish_dec_blk8_neon,.-__twofish_dec_blk8_neon

ENTRY(twofish_ecb_enc_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r1, r4-r12, lr};

	load_8way(%r2, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3);

	bl __twofish_enc_blk8_neon;

	pop {r1};

	store_8way(%r1, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1);

	pop {r4-r12, pc};
ENDPROC(twofish_ecb_enc_8way_neon)

ENTRY(twofish_ecb_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r1, r4-r12, lr};

	load_8way(%r2, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1);

	bl __twofish_dec_blk8_neon;

	pop {r1};

	store_8way(%r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3);

	pop {r4-r12, pc};
ENDPROC(twofish_ecb_dec_8way_neon)

ENTRY(twofish_cbc_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r1, r2, r4-r12, lr};

	load_8way(%r2, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1);

	bl __twofish_dec_blk8_neon;

	pop {r1, r2};

	store_cbc_8way(%r2, %r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3, RT0, RT1, RT2, RT3);

	pop {r4-r12, pc};
ENDPROC(twofish_cbc_dec_8way_neon)

ENTRY(twofish_ctr_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv (little endian, 128bit)
	 */

	stmdb sp!, {r1, r2, r4-r12, lr};

	load_ctr_8way(%r3, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		      RT0, RT1, RT2);

	bl __twofish_enc_blk8_neon;

	pop {r1, r2};

	store_ctr_8way(%r2, %r1, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1,
		       RT0, RT1, RT2, RT3);

	pop {r4-r12, pc};
ENDPROC(twofish_ctr_8way_neon)

ENTRY(twofish_xts_enc_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv
	 */

	stmdb sp!, {r1, r4-r12, lr};

	/* regs <= src, dst <= IVs, regs <= regs xor IVs */
	load_xts_8way(%r3, %r4, %r2, %r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		      RX, RY,
		      RT0, RT1, RT2, .Lxts_gf128mul_and_shl1_mask);

	bl __twofish_enc_blk8_neon;

	pop {r1};

	/* dst <= regs xor IVs(in dst) */
	store_xts_8way(%r1, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1,
		       RT0, RT1, RT2, RT3);

	pop {r4-r12, pc};
ENDPROC(twofish_xts_enc_8way_neon)

ENTRY(twofish_xts_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv
	 */

	stmdb sp!, {r1, r4-r12, lr};

	/* regs <= src, dst <= IVs, regs <= regs xor IVs */
	load_xts_8way(%r3, %r4, %r2, %r1, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1,
		      RX, RY,
		      RT0, RT1, RT2, .Lxts_gf128mul_and_shl1_mask);

	bl __twofish_dec_blk8_neon;

	pop {r1};

	/* dst <= regs xor IVs(in dst) */
	store_xts_8way(%r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		       RT0, RT1, RT2, RT3);

	pop {r4-r12, pc};
ENDPROC(twofish_xts_dec_8way_neon)

.align 6

.Lxts_gf128mul_and_shl1_mask:
	.byte 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
