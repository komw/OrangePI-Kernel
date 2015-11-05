/* serpent-armv7-neon.S  -  ARM/NEON assembly implementation of Serpent cipher
 *
 * Baes on cipher/serpent-armv7-neon.S written for Libgcrypt project by
 *  Copyright (C) 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#include "glue_helper-asm-neon.S"

.text
.align 4
.fpu neon

/* ARM registers */
#define RROUND r0

/* NEON vector registers */
#define RA0 q0
#define RA1 q1
#define RA2 q2
#define RA3 q3
#define RA4 q4
#define RB0 q5
#define RB1 q6
#define RB2 q7
#define RB3 q8
#define RB4 q9

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
#define RA4d0 d8
#define RA4d1 d9
#define RB0d0 d10
#define RB0d1 d11
#define RB1d0 d12
#define RB1d1 d13
#define RB2d0 d14
#define RB2d1 d15
#define RB3d0 d16
#define RB3d1 d17
#define RB4d0 d18
#define RB4d1 d19
#define RT0d0 d20
#define RT0d1 d21
#define RT1d0 d22
#define RT1d1 d23
#define RT2d0 d24
#define RT2d1 d25

/**********************************************************************
  helper macros
 **********************************************************************/

#define transpose_4x4(_q0, _q1, _q2, _q3) \
	vtrn.32 _q0, _q1;	\
	vtrn.32 _q2, _q3;	\
	vswp _q0##d1, _q2##d0;	\
	vswp _q1##d1, _q3##d0;

/**********************************************************************
  8-way serpent
 **********************************************************************/

/*
 * These are the S-Boxes of Serpent from crypto/serpent_generic.c.
 *
 */
#define SBOX0(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	vorr	a5, a3, a0;	vorr	b5, b3, b0;	veor	a0, a0, a3;	veor	b0, b0, b3; \
	veor	a4, a3, a2;	veor	b4, b3, b2;	veor	a3, a5, a1;	veor	b3, b5, b1; \
	vmvn	a4, a4;		vmvn	b4, b4;		vand	a1, a1, a0;	vand	b1, b1, b0; \
	veor	a2, a2, a0;	veor	b2, b2, b0;	veor	a1, a1, a4;	veor	b1, b1, b4; \
	veor	a0, a0, a3;	veor	b0, b0, b3;	vorr	a4, a4, a0;	vorr	b4, b4, b0; \
	veor	a0, a0, a2;	veor	b0, b0, b2;	vand	a2, a2, a1;	vand	b2, b2, b1; \
	veor	a3, a3, a2;	veor	b3, b3, b2;	vmvn	a1, a1;		vmvn	b1, b1; \
	veor	a2, a2, a4;	veor	b2, b2, b4;	veor	a1, a1, a2;	veor	b1, b1, b2;

#define SBOX0_INVERSE(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a1, a1, a0;	veor	b1, b1, b0;	vorr	a5, a3, a1;	vorr	b5, b3, b1; \
	veor	a4, a3, a1;	veor	b4, b3, b1;	vmvn	a0, a0;		vmvn	b0, b0; \
	veor	a2, a5, a2;	veor	b2, b5, b2;	veor	a3, a5, a0;	veor	b3, b5, b0; \
	vand	a0, a1, a0;	vand	b0, b1, b0;	veor	a0, a0, a2;	veor	b0, b0, b2; \
	vand	a2, a2, a3;	vand	b2, b2, b3;	veor	a3, a3, a4;	veor	b3, b3, b4; \
	veor	a2, a2, a3;	veor	b2, b2, b3;	veor	a1, a1, a3;	veor	b1, b1, b3; \
	vand	a3, a3, a0;	vand	b3, b3, b0;	veor	a1, a1, a0;	veor	b1, b1, b0; \
	veor	a0, a0, a2;	veor	b0, b0, b2;	veor	a4, a4, a3;	veor	b4, b4, b3;

#define SBOX1(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a5, a1, a0;	veor	b5, b1, b0;	veor	a0, a0, a3;	veor	b0, b0, b3; \
	vmvn	a3, a3;		vmvn	b3, b3;		vand	a4, a1, a5;	vand	b4, b1, b5; \
	vorr	a0, a0, a5;	vorr	b0, b0, b5;	veor	a3, a3, a2;	veor	b3, b3, b2; \
	veor	a0, a0, a3;	veor	b0, b0, b3;	veor	a1, a5, a3;	veor	b1, b5, b3; \
	veor	a3, a3, a4;	veor	b3, b3, b4;	vorr	a1, a1, a4;	vorr	b1, b1, b4; \
	veor	a4, a4, a2;	veor	b4, b4, b2;	vand	a2, a2, a0;	vand	b2, b2, b0; \
	veor	a2, a2, a1;	veor	b2, b2, b1;	vorr	a1, a1, a0;	vorr	b1, b1, b0; \
	vmvn	a0, a0;		vmvn	b0, b0;		veor	a0, a0, a2;	veor	b0, b0, b2; \
	veor	a4, a4, a1;	veor	b4, b4, b1;

#define SBOX1_INVERSE(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a1, a1, a3;	veor	b1, b1, b3;	veor	a5, a2, a0;	veor	b5, b2, b0; \
	vmvn	a2, a2;		vmvn	b2, b2;		vorr	a4, a1, a0;	vorr	b4, b1, b0; \
	veor	a4, a4, a3;	veor	b4, b4, b3;	vand	a3, a3, a1;	vand	b3, b3, b1; \
	veor	a1, a1, a2;	veor	b1, b1, b2;	vand	a2, a4, a2;	vand	b2, b4, b2; \
	veor	a4, a4, a1;	veor	b4, b4, b1;	vorr	a1, a1, a3;	vorr	b1, b1, b3; \
	veor	a3, a3, a5;	veor	b3, b3, b5;	veor	a2, a2, a5;	veor	b2, b2, b5; \
	vorr	a0, a4, a5;	vorr	b0, b4, b5;	veor	a2, a2, a4;	veor	b2, b2, b4; \
	veor	a1, a1, a0;	veor	b1, b1, b0;	veor	a4, a4, a1;	veor	b4, b4, b1;

#define SBOX2(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	vmvn	a3, a3;		vmvn	b3, b3;		veor	a1, a1, a0;	veor	b1, b1, b0; \
	vand	a5, a0, a2;	vand	b5, b0, b2;	veor	a5, a5, a3;	veor	b5, b5, b3; \
	vorr	a3, a3, a0;	vorr	b3, b3, b0;	veor	a2, a2, a1;	veor	b2, b2, b1; \
	veor	a3, a3, a1;	veor	b3, b3, b1;	vand	a1, a1, a5;	vand	b1, b1, b5; \
	veor	a5, a5, a2;	veor	b5, b5, b2;	vand	a2, a2, a3;	vand	b2, b2, b3; \
	vorr	a3, a3, a1;	vorr	b3, b3, b1;	vmvn	a5, a5;		vmvn	b5, b5; \
	veor	a3, a3, a5;	veor	b3, b3, b5;	veor	a4, a0, a5;	veor	b4, b0, b5; \
	veor	a0, a5, a2;	veor	b0, b5, b2;	vorr	a1, a1, a2;	vorr	b1, b1, b2;

#define SBOX2_INVERSE(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a2, a1, a2;	veor	b2, b1, b2;	vmvn	a5, a3;		vmvn	b5, b3; \
	vorr	a5, a5, a2;	vorr	b5, b5, b2;	veor	a2, a2, a3;	veor	b2, b2, b3; \
	veor	a4, a3, a0;	veor	b4, b3, b0;	veor	a3, a5, a1;	veor	b3, b5, b1; \
	vorr	a1, a1, a2;	vorr	b1, b1, b2;	veor	a2, a2, a0;	veor	b2, b2, b0; \
	veor	a1, a1, a4;	veor	b1, b1, b4;	vorr	a4, a4, a3;	vorr	b4, b4, b3; \
	veor	a2, a2, a3;	veor	b2, b2, b3;	veor	a4, a4, a2;	veor	b4, b4, b2; \
	vand	a2, a2, a1;	vand	b2, b2, b1;	veor	a2, a2, a3;	veor	b2, b2, b3; \
	veor	a3, a3, a4;	veor	b3, b3, b4;	veor	a4, a4, a0;	veor	b4, b4, b0;

#define SBOX3(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a5, a1, a3;	veor	b5, b1, b3;	vorr	a3, a3, a0;	vorr	b3, b3, b0; \
	vand	a4, a1, a0;	vand	b4, b1, b0;	veor	a0, a0, a2;	veor	b0, b0, b2; \
	veor	a2, a2, a5;	veor	b2, b2, b5;	vand	a1, a5, a3;	vand	b1, b5, b3; \
	veor	a2, a2, a3;	veor	b2, b2, b3;	vorr	a0, a0, a4;	vorr	b0, b0, b4; \
	veor	a4, a4, a3;	veor	b4, b4, b3;	veor	a1, a1, a0;	veor	b1, b1, b0; \
	vand	a0, a0, a3;	vand	b0, b0, b3;	vand	a3, a3, a4;	vand	b3, b3, b4; \
	veor	a3, a3, a2;	veor	b3, b3, b2;	vorr	a4, a4, a1;	vorr	b4, b4, b1; \
	vand	a2, a2, a1;	vand	b2, b2, b1;	veor	a4, a4, a3;	veor	b4, b4, b3; \
	veor	a0, a0, a3;	veor	b0, b0, b3;	veor	a3, a3, a2;	veor	b3, b3, b2;

#define SBOX3_INVERSE(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a2, a1, a2;	veor	b2, b1, b2;	vand	a5, a1, a2;	vand	b5, b1, b2; \
	veor	a5, a5, a0;	veor	b5, b5, b0;	vorr	a0, a1, a0;	vorr	b0, b1, b0; \
	veor	a4, a1, a3;	veor	b4, b1, b3;	veor	a0, a0, a3;	veor	b0, b0, b3; \
	vorr	a3, a3, a5;	vorr	b3, b3, b5;	veor	a1, a5, a2;	veor	b1, b5, b2; \
	veor	a1, a1, a3;	veor	b1, b1, b3;	veor	a0, a0, a2;	veor	b0, b0, b2; \
	veor	a2, a2, a3;	veor	b2, b2, b3;	vand	a3, a3, a1;	vand	b3, b3, b1; \
	veor	a1, a1, a0;	veor	b1, b1, b0;	vand	a0, a0, a2;	vand	b0, b0, b2; \
	veor	a4, a4, a3;	veor	b4, b4, b3;	veor	a3, a3, a0;	veor	b3, b3, b0; \
	veor	a0, a0, a1;	veor	b0, b0, b1;

#define SBOX4(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	vand	a5, a3, a0;	vand	b5, b3, b0;	veor	a0, a0, a3;	veor	b0, b0, b3; \
	veor	a5, a5, a2;	veor	b5, b5, b2;	vorr	a2, a2, a3;	vorr	b2, b2, b3; \
	veor	a0, a0, a1;	veor	b0, b0, b1;	veor	a4, a3, a5;	veor	b4, b3, b5; \
	vorr	a2, a2, a0;	vorr	b2, b2, b0;	veor	a2, a2, a1;	veor	b2, b2, b1; \
	vand	a1, a1, a0;	vand	b1, b1, b0;	veor	a1, a1, a4;	veor	b1, b1, b4; \
	vand	a4, a4, a2;	vand	b4, b4, b2;	veor	a2, a2, a5;	veor	b2, b2, b5; \
	veor	a4, a4, a0;	veor	b4, b4, b0;	vorr	a3, a5, a1;	vorr	b3, b5, b1; \
	vmvn	a1, a1;		vmvn	b1, b1;		veor	a3, a3, a0;	veor	b3, b3, b0;

#define SBOX4_INVERSE(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a2, a3, a2;	veor	b2, b3, b2;	vand	a5, a1, a0;	vand	b5, b1, b0; \
	veor	a5, a5, a2;	veor	b5, b5, b2;	vorr	a2, a2, a3;	vorr	b2, b2, b3; \
	vmvn	a4, a0;		vmvn	b4, b0;		veor	a1, a1, a5;	veor	b1, b1, b5; \
	veor	a0, a5, a2;	veor	b0, b5, b2;	vand	a2, a2, a4;	vand	b2, b2, b4; \
	veor	a2, a2, a0;	veor	b2, b2, b0;	vorr	a0, a0, a4;	vorr	b0, b0, b4; \
	veor	a0, a0, a3;	veor	b0, b0, b3;	vand	a3, a3, a2;	vand	b3, b3, b2; \
	veor	a4, a3, a4;	veor	b4, b3, b4;	veor	a3, a3, a1;	veor	b3, b3, b1; \
	vand	a1, a1, a0;	vand	b1, b1, b0;	veor	a4, a4, a1;	veor	b4, b4, b1; \
	veor	a0, a0, a3;	veor	b0, b0, b3;

#define SBOX5(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	vorr	a5, a1, a0;	vorr	b5, b1, b0;	vmvn	a3, a3;		vmvn	b3, b3; \
	veor	a2, a2, a5;	veor	b2, b2, b5;	veor	a4, a1, a0;	veor	b4, b1, b0; \
	veor	a0, a0, a2;	veor	b0, b0, b2;	vand	a1, a5, a4;	vand	b1, b5, b4; \
	vorr	a4, a4, a3;	vorr	b4, b4, b3;	veor	a1, a1, a3;	veor	b1, b1, b3; \
	veor	a4, a4, a0;	veor	b4, b4, b0;	vand	a0, a0, a3;	vand	b0, b0, b3; \
	veor	a3, a3, a2;	veor	b3, b3, b2;	vand	a2, a2, a4;	vand	b2, b2, b4; \
	veor	a0, a0, a1;	veor	b0, b0, b1;	veor	a1, a1, a2;	veor	b1, b1, b2; \
	vand	a2, a2, a0;	vand	b2, b2, b0;	veor	a3, a3, a2;	veor	b3, b3, b2;

#define SBOX5_INVERSE(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	vorr	a5, a1, a2;	vorr	b5, b1, b2;	veor	a2, a1, a2;	veor	b2, b1, b2; \
	veor	a5, a5, a3;	veor	b5, b5, b3;	vand	a3, a3, a1;	vand	b3, b3, b1; \
	veor	a2, a2, a3;	veor	b2, b2, b3;	vorr	a3, a3, a0;	vorr	b3, b3, b0; \
	vmvn	a0, a0;		vmvn	b0, b0;		veor	a3, a3, a2;	veor	b3, b3, b2; \
	vorr	a2, a2, a0;	vorr	b2, b2, b0;	veor	a4, a1, a5;	veor	b4, b1, b5; \
	veor	a2, a2, a4;	veor	b2, b2, b4;	vand	a4, a4, a0;	vand	b4, b4, b0; \
	veor	a0, a5, a0;	veor	b0, b5, b0;	veor	a1, a5, a3;	veor	b1, b5, b3; \
	vand	a0, a0, a2;	vand	b0, b0, b2;	veor	a2, a2, a3;	veor	b2, b2, b3; \
	veor	a0, a0, a2;	veor	b0, b0, b2;	veor	a2, a2, a4;	veor	b2, b2, b4; \
	veor	a4, a4, a3;	veor	b4, b4, b3;

#define SBOX6(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a3, a3, a0;	veor	b3, b3, b0;	veor	a5, a1, a2;	veor	b5, b1, b2; \
	veor	a2, a2, a0;	veor	b2, b2, b0;	vand	a0, a0, a3;	vand	b0, b0, b3; \
	vorr	a5, a5, a3;	vorr	b5, b5, b3;	vmvn	a4, a1;		vmvn	b4, b1; \
	veor	a0, a0, a5;	veor	b0, b0, b5;	veor	a1, a5, a2;	veor	b1, b5, b2; \
	veor	a3, a3, a4;	veor	b3, b3, b4;	veor	a4, a4, a0;	veor	b4, b4, b0; \
	vand	a2, a2, a0;	vand	b2, b2, b0;	veor	a4, a4, a1;	veor	b4, b4, b1; \
	veor	a2, a2, a3;	veor	b2, b2, b3;	vand	a3, a3, a1;	vand	b3, b3, b1; \
	veor	a3, a3, a0;	veor	b3, b3, b0;	veor	a1, a1, a2;	veor	b1, b1, b2;

#define SBOX6_INVERSE(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	veor	a0, a2, a0;	veor	b0, b2, b0;	vand	a5, a3, a0;	vand	b5, b3, b0; \
	veor	a2, a3, a2;	veor	b2, b3, b2;	veor	a5, a5, a2;	veor	b5, b5, b2; \
	veor	a3, a3, a1;	veor	b3, b3, b1;	vorr	a2, a2, a0;	vorr	b2, b2, b0; \
	veor	a2, a2, a3;	veor	b2, b2, b3;	vand	a3, a3, a5;	vand	b3, b3, b5; \
	vmvn	a5, a5;		vmvn	b5, b5;		veor	a3, a3, a1;	veor	b3, b3, b1; \
	vand	a1, a1, a2;	vand	b1, b1, b2;	veor	a4, a5, a0;	veor	b4, b5, b0; \
	veor	a3, a3, a4;	veor	b3, b3, b4;	veor	a4, a4, a2;	veor	b4, b4, b2; \
	veor	a0, a5, a1;	veor	b0, b5, b1;	veor	a2, a2, a0;	veor	b2, b2, b0;

#define SBOX7(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	vmvn	a4, a1;		vmvn	b4, b1;		vmvn	a0, a0;		vmvn	b0, b0; \
	vand	a1, a4, a2;	vand	b1, b4, b2;	veor	a1, a1, a3;	veor	b1, b1, b3; \
	vorr	a3, a3, a4;	vorr	b3, b3, b4;	veor	a4, a4, a2;	veor	b4, b4, b2; \
	veor	a2, a2, a3;	veor	b2, b2, b3;	veor	a3, a3, a0;	veor	b3, b3, b0; \
	vorr	a0, a0, a1;	vorr	b0, b0, b1;	vand	a2, a2, a0;	vand	b2, b2, b0; \
	veor	a0, a0, a4;	veor	b0, b0, b4;	veor	a4, a4, a3;	veor	b4, b4, b3; \
	vand	a3, a3, a0;	vand	b3, b3, b0;	veor	a4, a4, a1;	veor	b4, b4, b1; \
	veor	a2, a2, a4;	veor	b2, b2, b4;	veor	a3, a3, a1;	veor	b3, b3, b1; \
	vorr	a4, a4, a0;	vorr	b4, b4, b0;	veor	a4, a4, a1;	veor	b4, b4, b1;

#define SBOX7_INVERSE(a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	vand	a5, a3, a0;	vand	b5, b3, b0;	veor	a0, a2, a0;	veor	b0, b2, b0; \
	vorr	a2, a3, a2;	vorr	b2, b3, b2;	veor	a4, a3, a1;	veor	b4, b3, b1; \
	vmvn	a0, a0;		vmvn	b0, b0;		vorr	a1, a1, a5;	vorr	b1, b1, b5; \
	veor	a4, a4, a0;	veor	b4, b4, b0;	vand	a0, a2, a0;	vand	b0, b2, b0; \
	veor	a0, a0, a1;	veor	b0, b0, b1;	vand	a1, a1, a2;	vand	b1, b1, b2; \
	veor	a3, a5, a2;	veor	b3, b5, b2;	veor	a4, a4, a3;	veor	b4, b4, b3; \
	vand	a2, a2, a3;	vand	b2, b2, b3;	vorr	a3, a3, a0;	vorr	b3, b3, b0; \
	veor	a1, a1, a4;	veor	b1, b1, b4;	veor	a3, a3, a4;	veor	b3, b3, b4; \
	vand	a4, a4, a0;	vand	b4, b4, b0;	veor	a4, a4, a2;	veor	b4, b4, b2;

/* Apply SBOX number WHICH to to the block.  */
#define SBOX(which, a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	SBOX##which (a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5)

/* Apply inverse SBOX number WHICH to to the block.  */
#define SBOX_INVERSE(which, a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5) \
	SBOX##which##_INVERSE (a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5)

/* XOR round key into block state in a0,a1,a2,a3. a4 used as temporary.  */
#define BLOCK_XOR_KEY(a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	vdup.32 RT3, RT0d0[0]; \
	vdup.32 RT1, RT0d0[1]; \
	vdup.32 RT2, RT0d1[0]; \
	vdup.32 RT0, RT0d1[1]; \
	veor a0, a0, RT3;	veor b0, b0, RT3; \
	veor a1, a1, RT1;	veor b1, b1, RT1; \
	veor a2, a2, RT2;	veor b2, b2, RT2; \
	veor a3, a3, RT0;	veor b3, b3, RT0;

#define BLOCK_LOAD_KEY_ENC() \
	vld1.8 {RT0d0, RT0d1}, [RROUND]!;

#define BLOCK_LOAD_KEY_DEC() \
	vld1.8 {RT0d0, RT0d1}, [RROUND]; \
	sub RROUND, RROUND, #16

/* Apply the linear transformation to BLOCK.  */
#define LINEAR_TRANSFORMATION(a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	vshl.u32	a4, a0, #13;		vshl.u32	b4, b0, #13;		\
	vshr.u32	a0, a0, #(32-13);	vshr.u32	b0, b0, #(32-13);	\
	veor		a0, a0, a4;		veor		b0, b0, b4;		\
	vshl.u32	a4, a2, #3;		vshl.u32	b4, b2, #3;		\
	vshr.u32	a2, a2, #(32-3);	vshr.u32	b2, b2, #(32-3);	\
	veor		a2, a2, a4;		veor		b2, b2, b4;		\
	veor		a1, a0, a1;		veor		b1, b0, b1;		\
	veor		a1, a2, a1;		veor		b1, b2, b1;		\
	vshl.u32	a4, a0, #3;		vshl.u32	b4, b0, #3;		\
	veor		a3, a2, a3;		veor		b3, b2, b3;		\
	veor		a3, a4, a3;		veor		b3, b4, b3;		\
	vshl.u32	a4, a1, #1;		vshl.u32	b4, b1, #1;		\
	vshr.u32	a1, a1, #(32-1);	vshr.u32	b1, b1, #(32-1);	\
	veor		a1, a1, a4;		veor		b1, b1, b4;		\
	vshl.u32	a4, a3, #7;		vshl.u32	b4, b3, #7;		\
	vshr.u32	a3, a3, #(32-7);	vshr.u32	b3, b3, #(32-7);	\
	veor		a3, a3, a4;		veor		b3, b3, b4;		\
	veor		a0, a1, a0;		veor		b0, b1, b0;		\
	veor		a0, a3, a0;		veor		b0, b3, b0;		\
	vshl.u32	a4, a1, #7;		vshl.u32	b4, b1, #7;		\
	veor		a2, a3, a2;		veor		b2, b3, b2;		\
	veor		a2, a4, a2;		veor		b2, b4, b2;		\
	vshl.u32	a4, a0, #5;		vshl.u32	b4, b0, #5;		\
	vshr.u32	a0, a0, #(32-5);	vshr.u32	b0, b0, #(32-5);	\
	veor		a0, a0, a4;		veor		b0, b0, b4;		\
	vshl.u32	a4, a2, #22;		vshl.u32	b4, b2, #22;		\
	vshr.u32	a2, a2, #(32-22);	vshr.u32	b2, b2, #(32-22);	\
	veor		a2, a2, a4;		veor		b2, b2, b4;

/* Apply the inverse linear transformation to BLOCK.  */
#define LINEAR_TRANSFORMATION_INVERSE(a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	vshr.u32	a4, a2, #22;		vshr.u32	b4, b2, #22;		\
	vshl.u32	a2, a2, #(32-22);	vshl.u32	b2, b2, #(32-22);	\
	veor		a2, a2, a4;		veor		b2, b2, b4;		\
	vshr.u32	a4, a0, #5;		vshr.u32	b4, b0, #5;		\
	vshl.u32	a0, a0, #(32-5);	vshl.u32	b0, b0, #(32-5);	\
	veor		a0, a0, a4;		veor		b0, b0, b4;		\
	vshl.u32	a4, a1, #7;		vshl.u32	b4, b1, #7;		\
	veor		a2, a3, a2;		veor		b2, b3, b2;		\
	veor		a2, a4, a2;		veor		b2, b4, b2;		\
	veor		a0, a1, a0;		veor		b0, b1, b0;		\
	veor		a0, a3, a0;		veor		b0, b3, b0;		\
	vshr.u32	a4, a3, #7;		vshr.u32	b4, b3, #7;		\
	vshl.u32	a3, a3, #(32-7);	vshl.u32	b3, b3, #(32-7);	\
	veor		a3, a3, a4;		veor		b3, b3, b4;		\
	vshr.u32	a4, a1, #1;		vshr.u32	b4, b1, #1;		\
	vshl.u32	a1, a1, #(32-1);	vshl.u32	b1, b1, #(32-1);	\
	veor		a1, a1, a4;		veor		b1, b1, b4;		\
	vshl.u32	a4, a0, #3;		vshl.u32	b4, b0, #3;		\
	veor		a3, a2, a3;		veor		b3, b2, b3;		\
	veor		a3, a4, a3;		veor		b3, b4, b3;		\
	veor		a1, a0, a1;		veor		b1, b0, b1;		\
	veor		a1, a2, a1;		veor		b1, b2, b1;		\
	vshr.u32	a4, a2, #3;		vshr.u32	b4, b2, #3;		\
	vshl.u32	a2, a2, #(32-3);	vshl.u32	b2, b2, #(32-3);	\
	veor		a2, a2, a4;		veor		b2, b2, b4;		\
	vshr.u32	a4, a0, #13;		vshr.u32	b4, b0, #13;		\
	vshl.u32	a0, a0, #(32-13);	vshl.u32	b0, b0, #(32-13);	\
	veor		a0, a0, a4;		veor		b0, b0, b4;

/* Apply a Serpent round to eight parallel blocks.  This macro increments
   `round'.  */
#define ROUND(round, which, a0, a1, a2, a3, a4, na0, na1, na2, na3, na4, \
			    b0, b1, b2, b3, b4, nb0, nb1, nb2, nb3, nb4) \
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, b0, b1, b2, b3, b4);		\
	BLOCK_LOAD_KEY_ENC ();						\
	SBOX (which, a0, a1, a2, a3, a4, RT4, b0, b1, b2, b3, b4, RT5);		\
	LINEAR_TRANSFORMATION (na0, na1, na2, na3, na4, nb0, nb1, nb2, nb3, nb4);

/* Apply the last Serpent round to eight parallel blocks.  This macro increments
   `round'.  */
#define ROUND_LAST(round, which, a0, a1, a2, a3, a4, na0, na1, na2, na3, na4, \
				 b0, b1, b2, b3, b4, nb0, nb1, nb2, nb3, nb4) \
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, b0, b1, b2, b3, b4);		\
	BLOCK_LOAD_KEY_ENC ();						\
	SBOX (which, a0, a1, a2, a3, a4, RT4, b0, b1, b2, b3, b4, RT5);		\
	BLOCK_XOR_KEY (na0, na1, na2, na3, na4, nb0, nb1, nb2, nb3, nb4);

/* Apply an inverse Serpent round to eight parallel blocks.  This macro
   increments `round'.  */
#define ROUND_INVERSE(round, which, a0, a1, a2, a3, a4, \
				    na0, na1, na2, na3, na4, \
				    b0, b1, b2, b3, b4, \
				    nb0, nb1, nb2, nb3, nb4) \
	LINEAR_TRANSFORMATION_INVERSE (a0, a1, a2, a3, a4, b0, b1, b2, b3, b4);	\
	SBOX_INVERSE (which, a0, a1, a2, a3, a4, RT4, b0, b1, b2, b3, b4, RT5);	\
	BLOCK_XOR_KEY (na0, na1, na2, na3, na4, nb0, nb1, nb2, nb3, nb4);	\
	BLOCK_LOAD_KEY_DEC ();

/* Apply the first inverse Serpent round to eight parallel blocks.  This macro
   increments `round'.  */
#define ROUND_FIRST_INVERSE(round, which, a0, a1, a2, a3, a4, \
					  na0, na1, na2, na3, na4, \
					  b0, b1, b2, b3, b4, \
					  nb0, nb1, nb2, nb3, nb4) \
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, b0, b1, b2, b3, b4);			\
	BLOCK_LOAD_KEY_DEC ();							\
	SBOX_INVERSE (which, a0, a1, a2, a3, a4, RT4, b0, b1, b2, b3, b4, RT5);	\
	BLOCK_XOR_KEY (na0, na1, na2, na3, na4, nb0, nb1, nb2, nb3, nb4);	\
	BLOCK_LOAD_KEY_DEC ();

.type __serpent_enc_blk8_neon,%function
.align 4
__serpent_enc_blk8_neon:
	/* input:
	 *	r0: round key pointer
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel plaintext
	 *						blocks
	 * output:
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel
	 * 						ciphertext blocks
	 */

	transpose_4x4(RA0, RA1, RA2, RA3);
	BLOCK_LOAD_KEY_ENC ();
	transpose_4x4(RB0, RB1, RB2, RB3);

	ROUND (0, 0, RA0, RA1, RA2, RA3, RA4, RA2, RA1, RA3, RA0, RA4,
		     RB0, RB1, RB2, RB3, RB4, RB2, RB1, RB3, RB0, RB4);
	ROUND (1, 1, RA2, RA1, RA3, RA0, RA4, RA4, RA3, RA0, RA2, RA1,
		     RB2, RB1, RB3, RB0, RB4, RB4, RB3, RB0, RB2, RB1);
	ROUND (2, 2, RA4, RA3, RA0, RA2, RA1, RA1, RA3, RA4, RA2, RA0,
		     RB4, RB3, RB0, RB2, RB1, RB1, RB3, RB4, RB2, RB0);
	ROUND (3, 3, RA1, RA3, RA4, RA2, RA0, RA2, RA0, RA3, RA1, RA4,
		     RB1, RB3, RB4, RB2, RB0, RB2, RB0, RB3, RB1, RB4);
	ROUND (4, 4, RA2, RA0, RA3, RA1, RA4, RA0, RA3, RA1, RA4, RA2,
		     RB2, RB0, RB3, RB1, RB4, RB0, RB3, RB1, RB4, RB2);
	ROUND (5, 5, RA0, RA3, RA1, RA4, RA2, RA2, RA0, RA3, RA4, RA1,
		     RB0, RB3, RB1, RB4, RB2, RB2, RB0, RB3, RB4, RB1);
	ROUND (6, 6, RA2, RA0, RA3, RA4, RA1, RA3, RA1, RA0, RA4, RA2,
		     RB2, RB0, RB3, RB4, RB1, RB3, RB1, RB0, RB4, RB2);
	ROUND (7, 7, RA3, RA1, RA0, RA4, RA2, RA2, RA0, RA4, RA3, RA1,
		     RB3, RB1, RB0, RB4, RB2, RB2, RB0, RB4, RB3, RB1);
	ROUND (8, 0, RA2, RA0, RA4, RA3, RA1, RA4, RA0, RA3, RA2, RA1,
		     RB2, RB0, RB4, RB3, RB1, RB4, RB0, RB3, RB2, RB1);
	ROUND (9, 1, RA4, RA0, RA3, RA2, RA1, RA1, RA3, RA2, RA4, RA0,
		     RB4, RB0, RB3, RB2, RB1, RB1, RB3, RB2, RB4, RB0);
	ROUND (10, 2, RA1, RA3, RA2, RA4, RA0, RA0, RA3, RA1, RA4, RA2,
		      RB1, RB3, RB2, RB4, RB0, RB0, RB3, RB1, RB4, RB2);
	ROUND (11, 3, RA0, RA3, RA1, RA4, RA2, RA4, RA2, RA3, RA0, RA1,
		      RB0, RB3, RB1, RB4, RB2, RB4, RB2, RB3, RB0, RB1);
	ROUND (12, 4, RA4, RA2, RA3, RA0, RA1, RA2, RA3, RA0, RA1, RA4,
		      RB4, RB2, RB3, RB0, RB1, RB2, RB3, RB0, RB1, RB4);
	ROUND (13, 5, RA2, RA3, RA0, RA1, RA4, RA4, RA2, RA3, RA1, RA0,
		      RB2, RB3, RB0, RB1, RB4, RB4, RB2, RB3, RB1, RB0);
	ROUND (14, 6, RA4, RA2, RA3, RA1, RA0, RA3, RA0, RA2, RA1, RA4,
		      RB4, RB2, RB3, RB1, RB0, RB3, RB0, RB2, RB1, RB4);
	ROUND (15, 7, RA3, RA0, RA2, RA1, RA4, RA4, RA2, RA1, RA3, RA0,
		      RB3, RB0, RB2, RB1, RB4, RB4, RB2, RB1, RB3, RB0);
	ROUND (16, 0, RA4, RA2, RA1, RA3, RA0, RA1, RA2, RA3, RA4, RA0,
		      RB4, RB2, RB1, RB3, RB0, RB1, RB2, RB3, RB4, RB0);
	ROUND (17, 1, RA1, RA2, RA3, RA4, RA0, RA0, RA3, RA4, RA1, RA2,
		      RB1, RB2, RB3, RB4, RB0, RB0, RB3, RB4, RB1, RB2);
	ROUND (18, 2, RA0, RA3, RA4, RA1, RA2, RA2, RA3, RA0, RA1, RA4,
		      RB0, RB3, RB4, RB1, RB2, RB2, RB3, RB0, RB1, RB4);
	ROUND (19, 3, RA2, RA3, RA0, RA1, RA4, RA1, RA4, RA3, RA2, RA0,
		      RB2, RB3, RB0, RB1, RB4, RB1, RB4, RB3, RB2, RB0);
	ROUND (20, 4, RA1, RA4, RA3, RA2, RA0, RA4, RA3, RA2, RA0, RA1,
		      RB1, RB4, RB3, RB2, RB0, RB4, RB3, RB2, RB0, RB1);
	ROUND (21, 5, RA4, RA3, RA2, RA0, RA1, RA1, RA4, RA3, RA0, RA2,
		      RB4, RB3, RB2, RB0, RB1, RB1, RB4, RB3, RB0, RB2);
	ROUND (22, 6, RA1, RA4, RA3, RA0, RA2, RA3, RA2, RA4, RA0, RA1,
		      RB1, RB4, RB3, RB0, RB2, RB3, RB2, RB4, RB0, RB1);
	ROUND (23, 7, RA3, RA2, RA4, RA0, RA1, RA1, RA4, RA0, RA3, RA2,
		      RB3, RB2, RB4, RB0, RB1, RB1, RB4, RB0, RB3, RB2);
	ROUND (24, 0, RA1, RA4, RA0, RA3, RA2, RA0, RA4, RA3, RA1, RA2,
		      RB1, RB4, RB0, RB3, RB2, RB0, RB4, RB3, RB1, RB2);
	ROUND (25, 1, RA0, RA4, RA3, RA1, RA2, RA2, RA3, RA1, RA0, RA4,
		      RB0, RB4, RB3, RB1, RB2, RB2, RB3, RB1, RB0, RB4);
	ROUND (26, 2, RA2, RA3, RA1, RA0, RA4, RA4, RA3, RA2, RA0, RA1,
		      RB2, RB3, RB1, RB0, RB4, RB4, RB3, RB2, RB0, RB1);
	ROUND (27, 3, RA4, RA3, RA2, RA0, RA1, RA0, RA1, RA3, RA4, RA2,
		      RB4, RB3, RB2, RB0, RB1, RB0, RB1, RB3, RB4, RB2);
	ROUND (28, 4, RA0, RA1, RA3, RA4, RA2, RA1, RA3, RA4, RA2, RA0,
		      RB0, RB1, RB3, RB4, RB2, RB1, RB3, RB4, RB2, RB0);
	ROUND (29, 5, RA1, RA3, RA4, RA2, RA0, RA0, RA1, RA3, RA2, RA4,
		      RB1, RB3, RB4, RB2, RB0, RB0, RB1, RB3, RB2, RB4);
	ROUND (30, 6, RA0, RA1, RA3, RA2, RA4, RA3, RA4, RA1, RA2, RA0,
		      RB0, RB1, RB3, RB2, RB4, RB3, RB4, RB1, RB2, RB0);
	ROUND_LAST (31, 7, RA3, RA4, RA1, RA2, RA0, RA0, RA1, RA2, RA3, RA4,
		           RB3, RB4, RB1, RB2, RB0, RB0, RB1, RB2, RB3, RB4);

	transpose_4x4(RA0, RA1, RA2, RA3);
	transpose_4x4(RB0, RB1, RB2, RB3);

	bx lr;
.size __serpent_enc_blk8_neon,.-__serpent_enc_blk8_neon

.type __serpent_dec_blk8_neon,%function
.align 4
__serpent_dec_blk8_neon:
	/* input:
	 *	r0: round key pointer
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel
	 * 						ciphertext blocks
	 * output:
	 *	RA2, RA3, RA1, RA4, RB2, RB3, RB1, RB4: eight parallel plaintext
	 *						blocks
	 */

	add RROUND, RROUND, #(32*16);

	transpose_4x4(RA0, RA1, RA2, RA3);
	BLOCK_LOAD_KEY_DEC ();
	transpose_4x4(RB0, RB1, RB2, RB3);

	ROUND_FIRST_INVERSE (31, 7, RA0, RA1, RA2, RA3, RA4,
				    RA1, RA3, RA0, RA4, RA2,
				    RB0, RB1, RB2, RB3, RB4,
				    RB1, RB3, RB0, RB4, RB2);
	ROUND_INVERSE (30, 6, RA1, RA3, RA0, RA4, RA2, RA0, RA2, RA4, RA1, RA3,
		              RB1, RB3, RB0, RB4, RB2, RB0, RB2, RB4, RB1, RB3);
	ROUND_INVERSE (29, 5, RA0, RA2, RA4, RA1, RA3, RA2, RA3, RA0, RA4, RA1,
		              RB0, RB2, RB4, RB1, RB3, RB2, RB3, RB0, RB4, RB1);
	ROUND_INVERSE (28, 4, RA2, RA3, RA0, RA4, RA1, RA2, RA0, RA1, RA4, RA3,
		              RB2, RB3, RB0, RB4, RB1, RB2, RB0, RB1, RB4, RB3);
	ROUND_INVERSE (27, 3, RA2, RA0, RA1, RA4, RA3, RA1, RA2, RA3, RA4, RA0,
		              RB2, RB0, RB1, RB4, RB3, RB1, RB2, RB3, RB4, RB0);
	ROUND_INVERSE (26, 2, RA1, RA2, RA3, RA4, RA0, RA2, RA0, RA4, RA3, RA1,
		              RB1, RB2, RB3, RB4, RB0, RB2, RB0, RB4, RB3, RB1);
	ROUND_INVERSE (25, 1, RA2, RA0, RA4, RA3, RA1, RA1, RA0, RA4, RA3, RA2,
		              RB2, RB0, RB4, RB3, RB1, RB1, RB0, RB4, RB3, RB2);
	ROUND_INVERSE (24, 0, RA1, RA0, RA4, RA3, RA2, RA4, RA2, RA0, RA1, RA3,
		              RB1, RB0, RB4, RB3, RB2, RB4, RB2, RB0, RB1, RB3);
	ROUND_INVERSE (23, 7, RA4, RA2, RA0, RA1, RA3, RA2, RA1, RA4, RA3, RA0,
		              RB4, RB2, RB0, RB1, RB3, RB2, RB1, RB4, RB3, RB0);
	ROUND_INVERSE (22, 6, RA2, RA1, RA4, RA3, RA0, RA4, RA0, RA3, RA2, RA1,
		              RB2, RB1, RB4, RB3, RB0, RB4, RB0, RB3, RB2, RB1);
	ROUND_INVERSE (21, 5, RA4, RA0, RA3, RA2, RA1, RA0, RA1, RA4, RA3, RA2,
		              RB4, RB0, RB3, RB2, RB1, RB0, RB1, RB4, RB3, RB2);
	ROUND_INVERSE (20, 4, RA0, RA1, RA4, RA3, RA2, RA0, RA4, RA2, RA3, RA1,
		              RB0, RB1, RB4, RB3, RB2, RB0, RB4, RB2, RB3, RB1);
	ROUND_INVERSE (19, 3, RA0, RA4, RA2, RA3, RA1, RA2, RA0, RA1, RA3, RA4,
		              RB0, RB4, RB2, RB3, RB1, RB2, RB0, RB1, RB3, RB4);
	ROUND_INVERSE (18, 2, RA2, RA0, RA1, RA3, RA4, RA0, RA4, RA3, RA1, RA2,
		              RB2, RB0, RB1, RB3, RB4, RB0, RB4, RB3, RB1, RB2);
	ROUND_INVERSE (17, 1, RA0, RA4, RA3, RA1, RA2, RA2, RA4, RA3, RA1, RA0,
		              RB0, RB4, RB3, RB1, RB2, RB2, RB4, RB3, RB1, RB0);
	ROUND_INVERSE (16, 0, RA2, RA4, RA3, RA1, RA0, RA3, RA0, RA4, RA2, RA1,
		              RB2, RB4, RB3, RB1, RB0, RB3, RB0, RB4, RB2, RB1);
	ROUND_INVERSE (15, 7, RA3, RA0, RA4, RA2, RA1, RA0, RA2, RA3, RA1, RA4,
		              RB3, RB0, RB4, RB2, RB1, RB0, RB2, RB3, RB1, RB4);
	ROUND_INVERSE (14, 6, RA0, RA2, RA3, RA1, RA4, RA3, RA4, RA1, RA0, RA2,
		              RB0, RB2, RB3, RB1, RB4, RB3, RB4, RB1, RB0, RB2);
	ROUND_INVERSE (13, 5, RA3, RA4, RA1, RA0, RA2, RA4, RA2, RA3, RA1, RA0,
		              RB3, RB4, RB1, RB0, RB2, RB4, RB2, RB3, RB1, RB0);
	ROUND_INVERSE (12, 4, RA4, RA2, RA3, RA1, RA0, RA4, RA3, RA0, RA1, RA2,
		              RB4, RB2, RB3, RB1, RB0, RB4, RB3, RB0, RB1, RB2);
	ROUND_INVERSE (11, 3, RA4, RA3, RA0, RA1, RA2, RA0, RA4, RA2, RA1, RA3,
		              RB4, RB3, RB0, RB1, RB2, RB0, RB4, RB2, RB1, RB3);
	ROUND_INVERSE (10, 2, RA0, RA4, RA2, RA1, RA3, RA4, RA3, RA1, RA2, RA0,
		              RB0, RB4, RB2, RB1, RB3, RB4, RB3, RB1, RB2, RB0);
	ROUND_INVERSE (9, 1, RA4, RA3, RA1, RA2, RA0, RA0, RA3, RA1, RA2, RA4,
		             RB4, RB3, RB1, RB2, RB0, RB0, RB3, RB1, RB2, RB4);
	ROUND_INVERSE (8, 0, RA0, RA3, RA1, RA2, RA4, RA1, RA4, RA3, RA0, RA2,
		             RB0, RB3, RB1, RB2, RB4, RB1, RB4, RB3, RB0, RB2);
	ROUND_INVERSE (7, 7, RA1, RA4, RA3, RA0, RA2, RA4, RA0, RA1, RA2, RA3,
		             RB1, RB4, RB3, RB0, RB2, RB4, RB0, RB1, RB2, RB3);
	ROUND_INVERSE (6, 6, RA4, RA0, RA1, RA2, RA3, RA1, RA3, RA2, RA4, RA0,
		             RB4, RB0, RB1, RB2, RB3, RB1, RB3, RB2, RB4, RB0);
	ROUND_INVERSE (5, 5, RA1, RA3, RA2, RA4, RA0, RA3, RA0, RA1, RA2, RA4,
		             RB1, RB3, RB2, RB4, RB0, RB3, RB0, RB1, RB2, RB4);
	ROUND_INVERSE (4, 4, RA3, RA0, RA1, RA2, RA4, RA3, RA1, RA4, RA2, RA0,
		             RB3, RB0, RB1, RB2, RB4, RB3, RB1, RB4, RB2, RB0);
	ROUND_INVERSE (3, 3, RA3, RA1, RA4, RA2, RA0, RA4, RA3, RA0, RA2, RA1,
		             RB3, RB1, RB4, RB2, RB0, RB4, RB3, RB0, RB2, RB1);
	ROUND_INVERSE (2, 2, RA4, RA3, RA0, RA2, RA1, RA3, RA1, RA2, RA0, RA4,
		             RB4, RB3, RB0, RB2, RB1, RB3, RB1, RB2, RB0, RB4);
	ROUND_INVERSE (1, 1, RA3, RA1, RA2, RA0, RA4, RA4, RA1, RA2, RA0, RA3,
		             RB3, RB1, RB2, RB0, RB4, RB4, RB1, RB2, RB0, RB3);
	ROUND_INVERSE (0, 0, RA4, RA1, RA2, RA0, RA3, RA2, RA3, RA1, RA4, RA0,
		             RB4, RB1, RB2, RB0, RB3, RB2, RB3, RB1, RB4, RB0);

	transpose_4x4(RA2, RA3, RA1, RA4);
	transpose_4x4(RB2, RB3, RB1, RB4);

	bx lr;
.size __serpent_dec_blk8_neon,.-__serpent_dec_blk8_neon

ENTRY(serpent_ecb_enc_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r4-r11, ip, lr};

	load_8way(%r2, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3);

	bl __serpent_enc_blk8_neon;

	store_8way(%r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3);

	pop {r4-r11, ip, pc};
ENDPROC(serpent_ecb_enc_8way_neon)

ENTRY(serpent_ecb_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r4-r11, ip, lr};

	load_8way(%r2, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3);

	bl __serpent_dec_blk8_neon;

	store_8way(%r1, RA2, RA3, RA1, RA4, RB2, RB3, RB1, RB4);

	pop {r4-r11, ip, pc};
ENDPROC(serpent_ecb_dec_8way_neon)

ENTRY(serpent_cbc_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r4-r11, ip, lr};

	load_8way(%r2, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3);

	bl __serpent_dec_blk8_neon;

	store_cbc_8way(%r2, %r1, RA2, RA3, RA1, RA4, RB2, RB3, RB1, RB4, RT0, RT1, RT2, RT3);

	pop {r4-r11, ip, pc};
ENDPROC(serpent_cbc_dec_8way_neon)

ENTRY(serpent_ctr_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv (little endian, 128bit)
	 */

	stmdb sp!, {r4-r11, ip, lr};

	load_ctr_8way(%r3, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		      RT0, RT1, RT2);

	bl __serpent_enc_blk8_neon;

	store_ctr_8way(%r2, %r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		       RT0, RT1, RT2, RT3);

	pop {r4-r11, ip, pc};
ENDPROC(serpent_ctr_8way_neon)

ENTRY(serpent_xts_enc_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv
	 */

	stmdb sp!, {r4-r11, ip, lr};

	/* regs <= src, dst <= IVs, regs <= regs xor IVs */
	load_xts_8way(%r3, %r4, %r2, %r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		      RA4, RB4,
		      RT0, RT1, RT2, .Lxts_gf128mul_and_shl1_mask);

	bl __serpent_enc_blk8_neon;

	/* dst <= regs xor IVs(in dst) */
	store_xts_8way(%r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		       RT0, RT1, RT2, RT3);

	pop {r4-r11, ip, pc};
ENDPROC(serpent_xts_enc_8way_neon)

ENTRY(serpent_xts_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv
	 */

	stmdb sp!, {r4-r11, ip, lr};

	/* regs <= src, dst <= IVs, regs <= regs xor IVs */
	load_xts_8way(%r3, %r4, %r2, %r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		      RA4, RB4,
		      RT0, RT1, RT2, .Lxts_gf128mul_and_shl1_mask);

	bl __serpent_dec_blk8_neon;

	/* dst <= regs xor IVs(in dst) */
	store_xts_8way(%r1, RA2, RA3, RA1, RA4, RB2, RB3, RB1, RB4,
		       RT0, RT1, RT2, RT3);

	pop {r4-r11, ip, pc};
ENDPROC(serpent_xts_dec_8way_neon)

.align 6

.Lxts_gf128mul_and_shl1_mask:
	.byte 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
