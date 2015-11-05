#define __ARM_ARCH__ __LINUX_ARM_ARCH__
@ ====================================================================
@ Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
@ project. The module is, however, dual licensed under OpenSSL and
@ CRYPTOGAMS licenses depending on where you obtain it. For further
@ details see http://www.openssl.org/~appro/cryptogams/.
@ ====================================================================

@ SHA256 block procedure for ARMv4. May 2007.

@ Performance is ~2x better than gcc 3.4 generated code and in "abso-
@ lute" terms is ~2250 cycles per 64-byte block or ~35 cycles per
@ byte [on single-issue Xscale PXA250 core].

@ July 2010.
@
@ Rescheduling for dual-issue pipeline resulted in 22% improvement on
@ Cortex A8 core and ~20 cycles per processed byte.

@ February 2011.
@
@ Profiler-assisted and platform-specific optimization resulted in 16%
@ improvement on Cortex A8 core and ~15.4 cycles per processed byte.

#include <linux/linkage.h>
#include <asm/assembler.h>

.text

.type	K256,%object
.align	5
K256:
.word	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
.word	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
.word	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
.word	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
.word	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
.word	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
.word	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
.word	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
.word	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
.word	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
.word	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
.word	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
.word	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
.word	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
.word	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
.word	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
.size	K256,.-K256

.align	5

ENTRY(sha256_block_data_order)
	adr	r3,sha256_block_data_order		@ sha256_block_data_order
	add	r2,r1,r2,lsl#6				@ len to point at the end of inp
	stmdb	sp!,{r0,r1,r2,r4-r12,lr}
	ldmia	r0,{r4,r5,r6,r7,r8,r9,r10,r11}
	sub	r14,r3,#sha256_block_data_order-K256		@ K256
	sub	sp,sp,#16*4				@ alloca(X[16])
.Loop:
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r5,r6				@ magic
	eor	r12,r12,r12
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 0
# if 0==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r8,r8,ror#5
	add	r4,r4,r12				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r8,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 0
	add	r4,r4,r12				@ h+=Maj(a,b,c) from the past
	ldrb	r12,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r12,lsl#8
	ldrb	r12,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 0==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r8,r8,ror#5
	orr	r2,r2,r12,lsl#24
	eor	r0,r0,r8,ror#19				@ Sigma1(e)
#endif
	ldr	r12,[r14],#4				@ *K256++
	add	r11,r11,r2				@ h+=X[i]
	str	r2,[sp,#0*4]
	eor	r2,r9,r10
	add	r11,r11,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r8
	add	r11,r11,r12				@ h+=K256[i]
	eor	r2,r2,r10				@ Ch(e,f,g)
	eor	r0,r4,r4,ror#11
	add	r11,r11,r2				@ h+=Ch(e,f,g)
#if 0==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 0<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r4,r5				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#2*4]				@ from future BODY_16_xx
	eor	r12,r4,r5				@ a^b, b^c in next round
	ldr	r1,[sp,#15*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r4,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r7,r7,r11				@ d+=h
	eor	r3,r3,r5				@ Maj(a,b,c)
	add	r11,r11,r0,ror#2			@ h+=Sigma0(a)
	@ add	r11,r11,r3				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 1
# if 1==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r7,r7,ror#5
	add	r11,r11,r3				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r7,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 1
	add	r11,r11,r3				@ h+=Maj(a,b,c) from the past
	ldrb	r3,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r3,lsl#8
	ldrb	r3,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 1==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r7,r7,ror#5
	orr	r2,r2,r3,lsl#24
	eor	r0,r0,r7,ror#19				@ Sigma1(e)
#endif
	ldr	r3,[r14],#4				@ *K256++
	add	r10,r10,r2				@ h+=X[i]
	str	r2,[sp,#1*4]
	eor	r2,r8,r9
	add	r10,r10,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r7
	add	r10,r10,r3				@ h+=K256[i]
	eor	r2,r2,r9				@ Ch(e,f,g)
	eor	r0,r11,r11,ror#11
	add	r10,r10,r2				@ h+=Ch(e,f,g)
#if 1==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 1<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r11,r4				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#3*4]				@ from future BODY_16_xx
	eor	r3,r11,r4				@ a^b, b^c in next round
	ldr	r1,[sp,#0*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r11,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r6,r6,r10				@ d+=h
	eor	r12,r12,r4				@ Maj(a,b,c)
	add	r10,r10,r0,ror#2			@ h+=Sigma0(a)
	@ add	r10,r10,r12				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 2
# if 2==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r6,r6,ror#5
	add	r10,r10,r12				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r6,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 2
	add	r10,r10,r12				@ h+=Maj(a,b,c) from the past
	ldrb	r12,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r12,lsl#8
	ldrb	r12,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 2==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r6,r6,ror#5
	orr	r2,r2,r12,lsl#24
	eor	r0,r0,r6,ror#19				@ Sigma1(e)
#endif
	ldr	r12,[r14],#4				@ *K256++
	add	r9,r9,r2				@ h+=X[i]
	str	r2,[sp,#2*4]
	eor	r2,r7,r8
	add	r9,r9,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r6
	add	r9,r9,r12				@ h+=K256[i]
	eor	r2,r2,r8				@ Ch(e,f,g)
	eor	r0,r10,r10,ror#11
	add	r9,r9,r2				@ h+=Ch(e,f,g)
#if 2==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 2<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r10,r11				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#4*4]				@ from future BODY_16_xx
	eor	r12,r10,r11				@ a^b, b^c in next round
	ldr	r1,[sp,#1*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r10,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r5,r5,r9				@ d+=h
	eor	r3,r3,r11				@ Maj(a,b,c)
	add	r9,r9,r0,ror#2			@ h+=Sigma0(a)
	@ add	r9,r9,r3				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 3
# if 3==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r5,r5,ror#5
	add	r9,r9,r3				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r5,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 3
	add	r9,r9,r3				@ h+=Maj(a,b,c) from the past
	ldrb	r3,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r3,lsl#8
	ldrb	r3,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 3==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r5,r5,ror#5
	orr	r2,r2,r3,lsl#24
	eor	r0,r0,r5,ror#19				@ Sigma1(e)
#endif
	ldr	r3,[r14],#4				@ *K256++
	add	r8,r8,r2				@ h+=X[i]
	str	r2,[sp,#3*4]
	eor	r2,r6,r7
	add	r8,r8,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r5
	add	r8,r8,r3				@ h+=K256[i]
	eor	r2,r2,r7				@ Ch(e,f,g)
	eor	r0,r9,r9,ror#11
	add	r8,r8,r2				@ h+=Ch(e,f,g)
#if 3==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 3<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r9,r10				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#5*4]				@ from future BODY_16_xx
	eor	r3,r9,r10				@ a^b, b^c in next round
	ldr	r1,[sp,#2*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r9,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r4,r4,r8				@ d+=h
	eor	r12,r12,r10				@ Maj(a,b,c)
	add	r8,r8,r0,ror#2			@ h+=Sigma0(a)
	@ add	r8,r8,r12				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 4
# if 4==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r4,r4,ror#5
	add	r8,r8,r12				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r4,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 4
	add	r8,r8,r12				@ h+=Maj(a,b,c) from the past
	ldrb	r12,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r12,lsl#8
	ldrb	r12,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 4==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r4,r4,ror#5
	orr	r2,r2,r12,lsl#24
	eor	r0,r0,r4,ror#19				@ Sigma1(e)
#endif
	ldr	r12,[r14],#4				@ *K256++
	add	r7,r7,r2				@ h+=X[i]
	str	r2,[sp,#4*4]
	eor	r2,r5,r6
	add	r7,r7,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r4
	add	r7,r7,r12				@ h+=K256[i]
	eor	r2,r2,r6				@ Ch(e,f,g)
	eor	r0,r8,r8,ror#11
	add	r7,r7,r2				@ h+=Ch(e,f,g)
#if 4==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 4<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r8,r9				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#6*4]				@ from future BODY_16_xx
	eor	r12,r8,r9				@ a^b, b^c in next round
	ldr	r1,[sp,#3*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r8,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r11,r11,r7				@ d+=h
	eor	r3,r3,r9				@ Maj(a,b,c)
	add	r7,r7,r0,ror#2			@ h+=Sigma0(a)
	@ add	r7,r7,r3				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 5
# if 5==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r11,r11,ror#5
	add	r7,r7,r3				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r11,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 5
	add	r7,r7,r3				@ h+=Maj(a,b,c) from the past
	ldrb	r3,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r3,lsl#8
	ldrb	r3,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 5==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r11,r11,ror#5
	orr	r2,r2,r3,lsl#24
	eor	r0,r0,r11,ror#19				@ Sigma1(e)
#endif
	ldr	r3,[r14],#4				@ *K256++
	add	r6,r6,r2				@ h+=X[i]
	str	r2,[sp,#5*4]
	eor	r2,r4,r5
	add	r6,r6,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r11
	add	r6,r6,r3				@ h+=K256[i]
	eor	r2,r2,r5				@ Ch(e,f,g)
	eor	r0,r7,r7,ror#11
	add	r6,r6,r2				@ h+=Ch(e,f,g)
#if 5==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 5<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r7,r8				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#7*4]				@ from future BODY_16_xx
	eor	r3,r7,r8				@ a^b, b^c in next round
	ldr	r1,[sp,#4*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r7,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r10,r10,r6				@ d+=h
	eor	r12,r12,r8				@ Maj(a,b,c)
	add	r6,r6,r0,ror#2			@ h+=Sigma0(a)
	@ add	r6,r6,r12				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 6
# if 6==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r10,r10,ror#5
	add	r6,r6,r12				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r10,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 6
	add	r6,r6,r12				@ h+=Maj(a,b,c) from the past
	ldrb	r12,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r12,lsl#8
	ldrb	r12,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 6==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r10,r10,ror#5
	orr	r2,r2,r12,lsl#24
	eor	r0,r0,r10,ror#19				@ Sigma1(e)
#endif
	ldr	r12,[r14],#4				@ *K256++
	add	r5,r5,r2				@ h+=X[i]
	str	r2,[sp,#6*4]
	eor	r2,r11,r4
	add	r5,r5,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r10
	add	r5,r5,r12				@ h+=K256[i]
	eor	r2,r2,r4				@ Ch(e,f,g)
	eor	r0,r6,r6,ror#11
	add	r5,r5,r2				@ h+=Ch(e,f,g)
#if 6==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 6<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r6,r7				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#8*4]				@ from future BODY_16_xx
	eor	r12,r6,r7				@ a^b, b^c in next round
	ldr	r1,[sp,#5*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r6,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r9,r9,r5				@ d+=h
	eor	r3,r3,r7				@ Maj(a,b,c)
	add	r5,r5,r0,ror#2			@ h+=Sigma0(a)
	@ add	r5,r5,r3				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 7
# if 7==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r9,r9,ror#5
	add	r5,r5,r3				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r9,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 7
	add	r5,r5,r3				@ h+=Maj(a,b,c) from the past
	ldrb	r3,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r3,lsl#8
	ldrb	r3,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 7==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r9,r9,ror#5
	orr	r2,r2,r3,lsl#24
	eor	r0,r0,r9,ror#19				@ Sigma1(e)
#endif
	ldr	r3,[r14],#4				@ *K256++
	add	r4,r4,r2				@ h+=X[i]
	str	r2,[sp,#7*4]
	eor	r2,r10,r11
	add	r4,r4,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r9
	add	r4,r4,r3				@ h+=K256[i]
	eor	r2,r2,r11				@ Ch(e,f,g)
	eor	r0,r5,r5,ror#11
	add	r4,r4,r2				@ h+=Ch(e,f,g)
#if 7==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 7<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r5,r6				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#9*4]				@ from future BODY_16_xx
	eor	r3,r5,r6				@ a^b, b^c in next round
	ldr	r1,[sp,#6*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r5,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r8,r8,r4				@ d+=h
	eor	r12,r12,r6				@ Maj(a,b,c)
	add	r4,r4,r0,ror#2			@ h+=Sigma0(a)
	@ add	r4,r4,r12				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 8
# if 8==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r8,r8,ror#5
	add	r4,r4,r12				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r8,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 8
	add	r4,r4,r12				@ h+=Maj(a,b,c) from the past
	ldrb	r12,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r12,lsl#8
	ldrb	r12,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 8==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r8,r8,ror#5
	orr	r2,r2,r12,lsl#24
	eor	r0,r0,r8,ror#19				@ Sigma1(e)
#endif
	ldr	r12,[r14],#4				@ *K256++
	add	r11,r11,r2				@ h+=X[i]
	str	r2,[sp,#8*4]
	eor	r2,r9,r10
	add	r11,r11,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r8
	add	r11,r11,r12				@ h+=K256[i]
	eor	r2,r2,r10				@ Ch(e,f,g)
	eor	r0,r4,r4,ror#11
	add	r11,r11,r2				@ h+=Ch(e,f,g)
#if 8==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 8<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r4,r5				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#10*4]				@ from future BODY_16_xx
	eor	r12,r4,r5				@ a^b, b^c in next round
	ldr	r1,[sp,#7*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r4,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r7,r7,r11				@ d+=h
	eor	r3,r3,r5				@ Maj(a,b,c)
	add	r11,r11,r0,ror#2			@ h+=Sigma0(a)
	@ add	r11,r11,r3				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 9
# if 9==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r7,r7,ror#5
	add	r11,r11,r3				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r7,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 9
	add	r11,r11,r3				@ h+=Maj(a,b,c) from the past
	ldrb	r3,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r3,lsl#8
	ldrb	r3,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 9==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r7,r7,ror#5
	orr	r2,r2,r3,lsl#24
	eor	r0,r0,r7,ror#19				@ Sigma1(e)
#endif
	ldr	r3,[r14],#4				@ *K256++
	add	r10,r10,r2				@ h+=X[i]
	str	r2,[sp,#9*4]
	eor	r2,r8,r9
	add	r10,r10,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r7
	add	r10,r10,r3				@ h+=K256[i]
	eor	r2,r2,r9				@ Ch(e,f,g)
	eor	r0,r11,r11,ror#11
	add	r10,r10,r2				@ h+=Ch(e,f,g)
#if 9==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 9<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r11,r4				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#11*4]				@ from future BODY_16_xx
	eor	r3,r11,r4				@ a^b, b^c in next round
	ldr	r1,[sp,#8*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r11,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r6,r6,r10				@ d+=h
	eor	r12,r12,r4				@ Maj(a,b,c)
	add	r10,r10,r0,ror#2			@ h+=Sigma0(a)
	@ add	r10,r10,r12				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 10
# if 10==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r6,r6,ror#5
	add	r10,r10,r12				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r6,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 10
	add	r10,r10,r12				@ h+=Maj(a,b,c) from the past
	ldrb	r12,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r12,lsl#8
	ldrb	r12,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 10==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r6,r6,ror#5
	orr	r2,r2,r12,lsl#24
	eor	r0,r0,r6,ror#19				@ Sigma1(e)
#endif
	ldr	r12,[r14],#4				@ *K256++
	add	r9,r9,r2				@ h+=X[i]
	str	r2,[sp,#10*4]
	eor	r2,r7,r8
	add	r9,r9,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r6
	add	r9,r9,r12				@ h+=K256[i]
	eor	r2,r2,r8				@ Ch(e,f,g)
	eor	r0,r10,r10,ror#11
	add	r9,r9,r2				@ h+=Ch(e,f,g)
#if 10==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 10<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r10,r11				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#12*4]				@ from future BODY_16_xx
	eor	r12,r10,r11				@ a^b, b^c in next round
	ldr	r1,[sp,#9*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r10,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r5,r5,r9				@ d+=h
	eor	r3,r3,r11				@ Maj(a,b,c)
	add	r9,r9,r0,ror#2			@ h+=Sigma0(a)
	@ add	r9,r9,r3				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 11
# if 11==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r5,r5,ror#5
	add	r9,r9,r3				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r5,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 11
	add	r9,r9,r3				@ h+=Maj(a,b,c) from the past
	ldrb	r3,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r3,lsl#8
	ldrb	r3,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 11==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r5,r5,ror#5
	orr	r2,r2,r3,lsl#24
	eor	r0,r0,r5,ror#19				@ Sigma1(e)
#endif
	ldr	r3,[r14],#4				@ *K256++
	add	r8,r8,r2				@ h+=X[i]
	str	r2,[sp,#11*4]
	eor	r2,r6,r7
	add	r8,r8,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r5
	add	r8,r8,r3				@ h+=K256[i]
	eor	r2,r2,r7				@ Ch(e,f,g)
	eor	r0,r9,r9,ror#11
	add	r8,r8,r2				@ h+=Ch(e,f,g)
#if 11==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 11<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r9,r10				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#13*4]				@ from future BODY_16_xx
	eor	r3,r9,r10				@ a^b, b^c in next round
	ldr	r1,[sp,#10*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r9,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r4,r4,r8				@ d+=h
	eor	r12,r12,r10				@ Maj(a,b,c)
	add	r8,r8,r0,ror#2			@ h+=Sigma0(a)
	@ add	r8,r8,r12				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 12
# if 12==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r4,r4,ror#5
	add	r8,r8,r12				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r4,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 12
	add	r8,r8,r12				@ h+=Maj(a,b,c) from the past
	ldrb	r12,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r12,lsl#8
	ldrb	r12,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 12==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r4,r4,ror#5
	orr	r2,r2,r12,lsl#24
	eor	r0,r0,r4,ror#19				@ Sigma1(e)
#endif
	ldr	r12,[r14],#4				@ *K256++
	add	r7,r7,r2				@ h+=X[i]
	str	r2,[sp,#12*4]
	eor	r2,r5,r6
	add	r7,r7,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r4
	add	r7,r7,r12				@ h+=K256[i]
	eor	r2,r2,r6				@ Ch(e,f,g)
	eor	r0,r8,r8,ror#11
	add	r7,r7,r2				@ h+=Ch(e,f,g)
#if 12==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 12<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r8,r9				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#14*4]				@ from future BODY_16_xx
	eor	r12,r8,r9				@ a^b, b^c in next round
	ldr	r1,[sp,#11*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r8,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r11,r11,r7				@ d+=h
	eor	r3,r3,r9				@ Maj(a,b,c)
	add	r7,r7,r0,ror#2			@ h+=Sigma0(a)
	@ add	r7,r7,r3				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 13
# if 13==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r11,r11,ror#5
	add	r7,r7,r3				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r11,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 13
	add	r7,r7,r3				@ h+=Maj(a,b,c) from the past
	ldrb	r3,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r3,lsl#8
	ldrb	r3,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 13==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r11,r11,ror#5
	orr	r2,r2,r3,lsl#24
	eor	r0,r0,r11,ror#19				@ Sigma1(e)
#endif
	ldr	r3,[r14],#4				@ *K256++
	add	r6,r6,r2				@ h+=X[i]
	str	r2,[sp,#13*4]
	eor	r2,r4,r5
	add	r6,r6,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r11
	add	r6,r6,r3				@ h+=K256[i]
	eor	r2,r2,r5				@ Ch(e,f,g)
	eor	r0,r7,r7,ror#11
	add	r6,r6,r2				@ h+=Ch(e,f,g)
#if 13==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 13<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r7,r8				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#15*4]				@ from future BODY_16_xx
	eor	r3,r7,r8				@ a^b, b^c in next round
	ldr	r1,[sp,#12*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r7,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r10,r10,r6				@ d+=h
	eor	r12,r12,r8				@ Maj(a,b,c)
	add	r6,r6,r0,ror#2			@ h+=Sigma0(a)
	@ add	r6,r6,r12				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 14
# if 14==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r10,r10,ror#5
	add	r6,r6,r12				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r10,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 14
	add	r6,r6,r12				@ h+=Maj(a,b,c) from the past
	ldrb	r12,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r12,lsl#8
	ldrb	r12,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 14==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r10,r10,ror#5
	orr	r2,r2,r12,lsl#24
	eor	r0,r0,r10,ror#19				@ Sigma1(e)
#endif
	ldr	r12,[r14],#4				@ *K256++
	add	r5,r5,r2				@ h+=X[i]
	str	r2,[sp,#14*4]
	eor	r2,r11,r4
	add	r5,r5,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r10
	add	r5,r5,r12				@ h+=K256[i]
	eor	r2,r2,r4				@ Ch(e,f,g)
	eor	r0,r6,r6,ror#11
	add	r5,r5,r2				@ h+=Ch(e,f,g)
#if 14==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 14<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r6,r7				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#0*4]				@ from future BODY_16_xx
	eor	r12,r6,r7				@ a^b, b^c in next round
	ldr	r1,[sp,#13*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r6,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r9,r9,r5				@ d+=h
	eor	r3,r3,r7				@ Maj(a,b,c)
	add	r5,r5,r0,ror#2			@ h+=Sigma0(a)
	@ add	r5,r5,r3				@ h+=Maj(a,b,c)
#ifdef CONFIG_DCACHE_WORD_ACCESS
	@ ldr	r2,[r1],#4				@ 15
# if 15==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r9,r9,ror#5
	add	r5,r5,r3				@ h+=Maj(a,b,c) from the past
	eor	r0,r0,r9,ror#19				@ Sigma1(e)
	rev	r2,r2
#else
	@ ldrb	r2,[r1,#3]				@ 15
	add	r5,r5,r3				@ h+=Maj(a,b,c) from the past
	ldrb	r3,[r1,#2]
	ldrb	r0,[r1,#1]
	orr	r2,r2,r3,lsl#8
	ldrb	r3,[r1],#4
	orr	r2,r2,r0,lsl#16
# if 15==15
	str	r1,[sp,#17*4]				@ make room for r1
# endif
	eor	r0,r9,r9,ror#5
	orr	r2,r2,r3,lsl#24
	eor	r0,r0,r9,ror#19				@ Sigma1(e)
#endif
	ldr	r3,[r14],#4				@ *K256++
	add	r4,r4,r2				@ h+=X[i]
	str	r2,[sp,#15*4]
	eor	r2,r10,r11
	add	r4,r4,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r9
	add	r4,r4,r3				@ h+=K256[i]
	eor	r2,r2,r11				@ Ch(e,f,g)
	eor	r0,r5,r5,ror#11
	add	r4,r4,r2				@ h+=Ch(e,f,g)
#if 15==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 15<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r5,r6				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#1*4]				@ from future BODY_16_xx
	eor	r3,r5,r6				@ a^b, b^c in next round
	ldr	r1,[sp,#14*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r5,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r8,r8,r4				@ d+=h
	eor	r12,r12,r6				@ Maj(a,b,c)
	add	r4,r4,r0,ror#2			@ h+=Sigma0(a)
	@ add	r4,r4,r12				@ h+=Maj(a,b,c)
.Lrounds_16_xx:
	@ ldr	r2,[sp,#1*4]			@ 16
	@ ldr	r1,[sp,#14*4]
	mov	r0,r2,ror#7
	add	r4,r4,r12				@ h+=Maj(a,b,c) from the past
	mov	r12,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r12,r12,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#0*4]
	eor	r12,r12,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#9*4]

	add	r12,r12,r0
	eor	r0,r8,r8,ror#5			@ from BODY_00_15
	add	r2,r2,r12
	eor	r0,r0,r8,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r12,[r14],#4				@ *K256++
	add	r11,r11,r2				@ h+=X[i]
	str	r2,[sp,#0*4]
	eor	r2,r9,r10
	add	r11,r11,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r8
	add	r11,r11,r12				@ h+=K256[i]
	eor	r2,r2,r10				@ Ch(e,f,g)
	eor	r0,r4,r4,ror#11
	add	r11,r11,r2				@ h+=Ch(e,f,g)
#if 16==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 16<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r4,r5				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#2*4]				@ from future BODY_16_xx
	eor	r12,r4,r5				@ a^b, b^c in next round
	ldr	r1,[sp,#15*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r4,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r7,r7,r11				@ d+=h
	eor	r3,r3,r5				@ Maj(a,b,c)
	add	r11,r11,r0,ror#2			@ h+=Sigma0(a)
	@ add	r11,r11,r3				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#2*4]			@ 17
	@ ldr	r1,[sp,#15*4]
	mov	r0,r2,ror#7
	add	r11,r11,r3				@ h+=Maj(a,b,c) from the past
	mov	r3,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r3,r3,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#1*4]
	eor	r3,r3,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#10*4]

	add	r3,r3,r0
	eor	r0,r7,r7,ror#5			@ from BODY_00_15
	add	r2,r2,r3
	eor	r0,r0,r7,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r3,[r14],#4				@ *K256++
	add	r10,r10,r2				@ h+=X[i]
	str	r2,[sp,#1*4]
	eor	r2,r8,r9
	add	r10,r10,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r7
	add	r10,r10,r3				@ h+=K256[i]
	eor	r2,r2,r9				@ Ch(e,f,g)
	eor	r0,r11,r11,ror#11
	add	r10,r10,r2				@ h+=Ch(e,f,g)
#if 17==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 17<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r11,r4				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#3*4]				@ from future BODY_16_xx
	eor	r3,r11,r4				@ a^b, b^c in next round
	ldr	r1,[sp,#0*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r11,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r6,r6,r10				@ d+=h
	eor	r12,r12,r4				@ Maj(a,b,c)
	add	r10,r10,r0,ror#2			@ h+=Sigma0(a)
	@ add	r10,r10,r12				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#3*4]			@ 18
	@ ldr	r1,[sp,#0*4]
	mov	r0,r2,ror#7
	add	r10,r10,r12				@ h+=Maj(a,b,c) from the past
	mov	r12,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r12,r12,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#2*4]
	eor	r12,r12,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#11*4]

	add	r12,r12,r0
	eor	r0,r6,r6,ror#5			@ from BODY_00_15
	add	r2,r2,r12
	eor	r0,r0,r6,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r12,[r14],#4				@ *K256++
	add	r9,r9,r2				@ h+=X[i]
	str	r2,[sp,#2*4]
	eor	r2,r7,r8
	add	r9,r9,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r6
	add	r9,r9,r12				@ h+=K256[i]
	eor	r2,r2,r8				@ Ch(e,f,g)
	eor	r0,r10,r10,ror#11
	add	r9,r9,r2				@ h+=Ch(e,f,g)
#if 18==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 18<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r10,r11				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#4*4]				@ from future BODY_16_xx
	eor	r12,r10,r11				@ a^b, b^c in next round
	ldr	r1,[sp,#1*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r10,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r5,r5,r9				@ d+=h
	eor	r3,r3,r11				@ Maj(a,b,c)
	add	r9,r9,r0,ror#2			@ h+=Sigma0(a)
	@ add	r9,r9,r3				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#4*4]			@ 19
	@ ldr	r1,[sp,#1*4]
	mov	r0,r2,ror#7
	add	r9,r9,r3				@ h+=Maj(a,b,c) from the past
	mov	r3,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r3,r3,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#3*4]
	eor	r3,r3,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#12*4]

	add	r3,r3,r0
	eor	r0,r5,r5,ror#5			@ from BODY_00_15
	add	r2,r2,r3
	eor	r0,r0,r5,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r3,[r14],#4				@ *K256++
	add	r8,r8,r2				@ h+=X[i]
	str	r2,[sp,#3*4]
	eor	r2,r6,r7
	add	r8,r8,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r5
	add	r8,r8,r3				@ h+=K256[i]
	eor	r2,r2,r7				@ Ch(e,f,g)
	eor	r0,r9,r9,ror#11
	add	r8,r8,r2				@ h+=Ch(e,f,g)
#if 19==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 19<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r9,r10				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#5*4]				@ from future BODY_16_xx
	eor	r3,r9,r10				@ a^b, b^c in next round
	ldr	r1,[sp,#2*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r9,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r4,r4,r8				@ d+=h
	eor	r12,r12,r10				@ Maj(a,b,c)
	add	r8,r8,r0,ror#2			@ h+=Sigma0(a)
	@ add	r8,r8,r12				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#5*4]			@ 20
	@ ldr	r1,[sp,#2*4]
	mov	r0,r2,ror#7
	add	r8,r8,r12				@ h+=Maj(a,b,c) from the past
	mov	r12,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r12,r12,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#4*4]
	eor	r12,r12,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#13*4]

	add	r12,r12,r0
	eor	r0,r4,r4,ror#5			@ from BODY_00_15
	add	r2,r2,r12
	eor	r0,r0,r4,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r12,[r14],#4				@ *K256++
	add	r7,r7,r2				@ h+=X[i]
	str	r2,[sp,#4*4]
	eor	r2,r5,r6
	add	r7,r7,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r4
	add	r7,r7,r12				@ h+=K256[i]
	eor	r2,r2,r6				@ Ch(e,f,g)
	eor	r0,r8,r8,ror#11
	add	r7,r7,r2				@ h+=Ch(e,f,g)
#if 20==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 20<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r8,r9				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#6*4]				@ from future BODY_16_xx
	eor	r12,r8,r9				@ a^b, b^c in next round
	ldr	r1,[sp,#3*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r8,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r11,r11,r7				@ d+=h
	eor	r3,r3,r9				@ Maj(a,b,c)
	add	r7,r7,r0,ror#2			@ h+=Sigma0(a)
	@ add	r7,r7,r3				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#6*4]			@ 21
	@ ldr	r1,[sp,#3*4]
	mov	r0,r2,ror#7
	add	r7,r7,r3				@ h+=Maj(a,b,c) from the past
	mov	r3,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r3,r3,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#5*4]
	eor	r3,r3,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#14*4]

	add	r3,r3,r0
	eor	r0,r11,r11,ror#5			@ from BODY_00_15
	add	r2,r2,r3
	eor	r0,r0,r11,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r3,[r14],#4				@ *K256++
	add	r6,r6,r2				@ h+=X[i]
	str	r2,[sp,#5*4]
	eor	r2,r4,r5
	add	r6,r6,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r11
	add	r6,r6,r3				@ h+=K256[i]
	eor	r2,r2,r5				@ Ch(e,f,g)
	eor	r0,r7,r7,ror#11
	add	r6,r6,r2				@ h+=Ch(e,f,g)
#if 21==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 21<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r7,r8				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#7*4]				@ from future BODY_16_xx
	eor	r3,r7,r8				@ a^b, b^c in next round
	ldr	r1,[sp,#4*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r7,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r10,r10,r6				@ d+=h
	eor	r12,r12,r8				@ Maj(a,b,c)
	add	r6,r6,r0,ror#2			@ h+=Sigma0(a)
	@ add	r6,r6,r12				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#7*4]			@ 22
	@ ldr	r1,[sp,#4*4]
	mov	r0,r2,ror#7
	add	r6,r6,r12				@ h+=Maj(a,b,c) from the past
	mov	r12,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r12,r12,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#6*4]
	eor	r12,r12,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#15*4]

	add	r12,r12,r0
	eor	r0,r10,r10,ror#5			@ from BODY_00_15
	add	r2,r2,r12
	eor	r0,r0,r10,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r12,[r14],#4				@ *K256++
	add	r5,r5,r2				@ h+=X[i]
	str	r2,[sp,#6*4]
	eor	r2,r11,r4
	add	r5,r5,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r10
	add	r5,r5,r12				@ h+=K256[i]
	eor	r2,r2,r4				@ Ch(e,f,g)
	eor	r0,r6,r6,ror#11
	add	r5,r5,r2				@ h+=Ch(e,f,g)
#if 22==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 22<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r6,r7				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#8*4]				@ from future BODY_16_xx
	eor	r12,r6,r7				@ a^b, b^c in next round
	ldr	r1,[sp,#5*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r6,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r9,r9,r5				@ d+=h
	eor	r3,r3,r7				@ Maj(a,b,c)
	add	r5,r5,r0,ror#2			@ h+=Sigma0(a)
	@ add	r5,r5,r3				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#8*4]			@ 23
	@ ldr	r1,[sp,#5*4]
	mov	r0,r2,ror#7
	add	r5,r5,r3				@ h+=Maj(a,b,c) from the past
	mov	r3,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r3,r3,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#7*4]
	eor	r3,r3,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#0*4]

	add	r3,r3,r0
	eor	r0,r9,r9,ror#5			@ from BODY_00_15
	add	r2,r2,r3
	eor	r0,r0,r9,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r3,[r14],#4				@ *K256++
	add	r4,r4,r2				@ h+=X[i]
	str	r2,[sp,#7*4]
	eor	r2,r10,r11
	add	r4,r4,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r9
	add	r4,r4,r3				@ h+=K256[i]
	eor	r2,r2,r11				@ Ch(e,f,g)
	eor	r0,r5,r5,ror#11
	add	r4,r4,r2				@ h+=Ch(e,f,g)
#if 23==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 23<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r5,r6				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#9*4]				@ from future BODY_16_xx
	eor	r3,r5,r6				@ a^b, b^c in next round
	ldr	r1,[sp,#6*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r5,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r8,r8,r4				@ d+=h
	eor	r12,r12,r6				@ Maj(a,b,c)
	add	r4,r4,r0,ror#2			@ h+=Sigma0(a)
	@ add	r4,r4,r12				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#9*4]			@ 24
	@ ldr	r1,[sp,#6*4]
	mov	r0,r2,ror#7
	add	r4,r4,r12				@ h+=Maj(a,b,c) from the past
	mov	r12,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r12,r12,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#8*4]
	eor	r12,r12,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#1*4]

	add	r12,r12,r0
	eor	r0,r8,r8,ror#5			@ from BODY_00_15
	add	r2,r2,r12
	eor	r0,r0,r8,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r12,[r14],#4				@ *K256++
	add	r11,r11,r2				@ h+=X[i]
	str	r2,[sp,#8*4]
	eor	r2,r9,r10
	add	r11,r11,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r8
	add	r11,r11,r12				@ h+=K256[i]
	eor	r2,r2,r10				@ Ch(e,f,g)
	eor	r0,r4,r4,ror#11
	add	r11,r11,r2				@ h+=Ch(e,f,g)
#if 24==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 24<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r4,r5				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#10*4]				@ from future BODY_16_xx
	eor	r12,r4,r5				@ a^b, b^c in next round
	ldr	r1,[sp,#7*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r4,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r7,r7,r11				@ d+=h
	eor	r3,r3,r5				@ Maj(a,b,c)
	add	r11,r11,r0,ror#2			@ h+=Sigma0(a)
	@ add	r11,r11,r3				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#10*4]			@ 25
	@ ldr	r1,[sp,#7*4]
	mov	r0,r2,ror#7
	add	r11,r11,r3				@ h+=Maj(a,b,c) from the past
	mov	r3,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r3,r3,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#9*4]
	eor	r3,r3,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#2*4]

	add	r3,r3,r0
	eor	r0,r7,r7,ror#5			@ from BODY_00_15
	add	r2,r2,r3
	eor	r0,r0,r7,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r3,[r14],#4				@ *K256++
	add	r10,r10,r2				@ h+=X[i]
	str	r2,[sp,#9*4]
	eor	r2,r8,r9
	add	r10,r10,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r7
	add	r10,r10,r3				@ h+=K256[i]
	eor	r2,r2,r9				@ Ch(e,f,g)
	eor	r0,r11,r11,ror#11
	add	r10,r10,r2				@ h+=Ch(e,f,g)
#if 25==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 25<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r11,r4				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#11*4]				@ from future BODY_16_xx
	eor	r3,r11,r4				@ a^b, b^c in next round
	ldr	r1,[sp,#8*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r11,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r6,r6,r10				@ d+=h
	eor	r12,r12,r4				@ Maj(a,b,c)
	add	r10,r10,r0,ror#2			@ h+=Sigma0(a)
	@ add	r10,r10,r12				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#11*4]			@ 26
	@ ldr	r1,[sp,#8*4]
	mov	r0,r2,ror#7
	add	r10,r10,r12				@ h+=Maj(a,b,c) from the past
	mov	r12,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r12,r12,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#10*4]
	eor	r12,r12,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#3*4]

	add	r12,r12,r0
	eor	r0,r6,r6,ror#5			@ from BODY_00_15
	add	r2,r2,r12
	eor	r0,r0,r6,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r12,[r14],#4				@ *K256++
	add	r9,r9,r2				@ h+=X[i]
	str	r2,[sp,#10*4]
	eor	r2,r7,r8
	add	r9,r9,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r6
	add	r9,r9,r12				@ h+=K256[i]
	eor	r2,r2,r8				@ Ch(e,f,g)
	eor	r0,r10,r10,ror#11
	add	r9,r9,r2				@ h+=Ch(e,f,g)
#if 26==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 26<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r10,r11				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#12*4]				@ from future BODY_16_xx
	eor	r12,r10,r11				@ a^b, b^c in next round
	ldr	r1,[sp,#9*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r10,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r5,r5,r9				@ d+=h
	eor	r3,r3,r11				@ Maj(a,b,c)
	add	r9,r9,r0,ror#2			@ h+=Sigma0(a)
	@ add	r9,r9,r3				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#12*4]			@ 27
	@ ldr	r1,[sp,#9*4]
	mov	r0,r2,ror#7
	add	r9,r9,r3				@ h+=Maj(a,b,c) from the past
	mov	r3,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r3,r3,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#11*4]
	eor	r3,r3,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#4*4]

	add	r3,r3,r0
	eor	r0,r5,r5,ror#5			@ from BODY_00_15
	add	r2,r2,r3
	eor	r0,r0,r5,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r3,[r14],#4				@ *K256++
	add	r8,r8,r2				@ h+=X[i]
	str	r2,[sp,#11*4]
	eor	r2,r6,r7
	add	r8,r8,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r5
	add	r8,r8,r3				@ h+=K256[i]
	eor	r2,r2,r7				@ Ch(e,f,g)
	eor	r0,r9,r9,ror#11
	add	r8,r8,r2				@ h+=Ch(e,f,g)
#if 27==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 27<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r9,r10				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#13*4]				@ from future BODY_16_xx
	eor	r3,r9,r10				@ a^b, b^c in next round
	ldr	r1,[sp,#10*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r9,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r4,r4,r8				@ d+=h
	eor	r12,r12,r10				@ Maj(a,b,c)
	add	r8,r8,r0,ror#2			@ h+=Sigma0(a)
	@ add	r8,r8,r12				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#13*4]			@ 28
	@ ldr	r1,[sp,#10*4]
	mov	r0,r2,ror#7
	add	r8,r8,r12				@ h+=Maj(a,b,c) from the past
	mov	r12,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r12,r12,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#12*4]
	eor	r12,r12,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#5*4]

	add	r12,r12,r0
	eor	r0,r4,r4,ror#5			@ from BODY_00_15
	add	r2,r2,r12
	eor	r0,r0,r4,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r12,[r14],#4				@ *K256++
	add	r7,r7,r2				@ h+=X[i]
	str	r2,[sp,#12*4]
	eor	r2,r5,r6
	add	r7,r7,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r4
	add	r7,r7,r12				@ h+=K256[i]
	eor	r2,r2,r6				@ Ch(e,f,g)
	eor	r0,r8,r8,ror#11
	add	r7,r7,r2				@ h+=Ch(e,f,g)
#if 28==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 28<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r8,r9				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#14*4]				@ from future BODY_16_xx
	eor	r12,r8,r9				@ a^b, b^c in next round
	ldr	r1,[sp,#11*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r8,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r11,r11,r7				@ d+=h
	eor	r3,r3,r9				@ Maj(a,b,c)
	add	r7,r7,r0,ror#2			@ h+=Sigma0(a)
	@ add	r7,r7,r3				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#14*4]			@ 29
	@ ldr	r1,[sp,#11*4]
	mov	r0,r2,ror#7
	add	r7,r7,r3				@ h+=Maj(a,b,c) from the past
	mov	r3,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r3,r3,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#13*4]
	eor	r3,r3,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#6*4]

	add	r3,r3,r0
	eor	r0,r11,r11,ror#5			@ from BODY_00_15
	add	r2,r2,r3
	eor	r0,r0,r11,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r3,[r14],#4				@ *K256++
	add	r6,r6,r2				@ h+=X[i]
	str	r2,[sp,#13*4]
	eor	r2,r4,r5
	add	r6,r6,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r11
	add	r6,r6,r3				@ h+=K256[i]
	eor	r2,r2,r5				@ Ch(e,f,g)
	eor	r0,r7,r7,ror#11
	add	r6,r6,r2				@ h+=Ch(e,f,g)
#if 29==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 29<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r7,r8				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#15*4]				@ from future BODY_16_xx
	eor	r3,r7,r8				@ a^b, b^c in next round
	ldr	r1,[sp,#12*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r7,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r10,r10,r6				@ d+=h
	eor	r12,r12,r8				@ Maj(a,b,c)
	add	r6,r6,r0,ror#2			@ h+=Sigma0(a)
	@ add	r6,r6,r12				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#15*4]			@ 30
	@ ldr	r1,[sp,#12*4]
	mov	r0,r2,ror#7
	add	r6,r6,r12				@ h+=Maj(a,b,c) from the past
	mov	r12,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r12,r12,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#14*4]
	eor	r12,r12,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#7*4]

	add	r12,r12,r0
	eor	r0,r10,r10,ror#5			@ from BODY_00_15
	add	r2,r2,r12
	eor	r0,r0,r10,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r12,[r14],#4				@ *K256++
	add	r5,r5,r2				@ h+=X[i]
	str	r2,[sp,#14*4]
	eor	r2,r11,r4
	add	r5,r5,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r10
	add	r5,r5,r12				@ h+=K256[i]
	eor	r2,r2,r4				@ Ch(e,f,g)
	eor	r0,r6,r6,ror#11
	add	r5,r5,r2				@ h+=Ch(e,f,g)
#if 30==31
	and	r12,r12,#0xff
	cmp	r12,#0xf2				@ done?
#endif
#if 30<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r12,r6,r7				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#0*4]				@ from future BODY_16_xx
	eor	r12,r6,r7				@ a^b, b^c in next round
	ldr	r1,[sp,#13*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r6,ror#20			@ Sigma0(a)
	and	r3,r3,r12				@ (b^c)&=(a^b)
	add	r9,r9,r5				@ d+=h
	eor	r3,r3,r7				@ Maj(a,b,c)
	add	r5,r5,r0,ror#2			@ h+=Sigma0(a)
	@ add	r5,r5,r3				@ h+=Maj(a,b,c)
	@ ldr	r2,[sp,#0*4]			@ 31
	@ ldr	r1,[sp,#13*4]
	mov	r0,r2,ror#7
	add	r5,r5,r3				@ h+=Maj(a,b,c) from the past
	mov	r3,r1,ror#17
	eor	r0,r0,r2,ror#18
	eor	r3,r3,r1,ror#19
	eor	r0,r0,r2,lsr#3			@ sigma0(X[i+1])
	ldr	r2,[sp,#15*4]
	eor	r3,r3,r1,lsr#10			@ sigma1(X[i+14])
	ldr	r1,[sp,#8*4]

	add	r3,r3,r0
	eor	r0,r9,r9,ror#5			@ from BODY_00_15
	add	r2,r2,r3
	eor	r0,r0,r9,ror#19			@ Sigma1(e)
	add	r2,r2,r1				@ X[i]
	ldr	r3,[r14],#4				@ *K256++
	add	r4,r4,r2				@ h+=X[i]
	str	r2,[sp,#15*4]
	eor	r2,r10,r11
	add	r4,r4,r0,ror#6			@ h+=Sigma1(e)
	and	r2,r2,r9
	add	r4,r4,r3				@ h+=K256[i]
	eor	r2,r2,r11				@ Ch(e,f,g)
	eor	r0,r5,r5,ror#11
	add	r4,r4,r2				@ h+=Ch(e,f,g)
#if 31==31
	and	r3,r3,#0xff
	cmp	r3,#0xf2				@ done?
#endif
#if 31<15
# ifdef CONFIG_DCACHE_WORD_ACCESS
	ldr	r2,[r1],#4				@ prefetch
# else
	ldrb	r2,[r1,#3]
# endif
	eor	r3,r5,r6				@ a^b, b^c in next round
#else
	ldr	r2,[sp,#1*4]				@ from future BODY_16_xx
	eor	r3,r5,r6				@ a^b, b^c in next round
	ldr	r1,[sp,#14*4]				@ from future BODY_16_xx
#endif
	eor	r0,r0,r5,ror#20			@ Sigma0(a)
	and	r12,r12,r3				@ (b^c)&=(a^b)
	add	r8,r8,r4				@ d+=h
	eor	r12,r12,r6				@ Maj(a,b,c)
	add	r4,r4,r0,ror#2			@ h+=Sigma0(a)
	@ add	r4,r4,r12				@ h+=Maj(a,b,c)
	ldreq	r3,[sp,#16*4]		@ pull ctx
	bne	.Lrounds_16_xx

	add	r4,r4,r12				@ h+=Maj(a,b,c) from the past
	ldr	r0,[r3,#0]
	ldr	r2,[r3,#4]
	ldr	r12,[r3,#8]
	add	r4,r4,r0
	ldr	r0,[r3,#12]
	add	r5,r5,r2
	ldr	r2,[r3,#16]
	add	r6,r6,r12
	ldr	r12,[r3,#20]
	add	r7,r7,r0
	ldr	r0,[r3,#24]
	add	r8,r8,r2
	ldr	r2,[r3,#28]
	add	r9,r9,r12
	ldr	r1,[sp,#17*4]				@ pull inp
	ldr	r12,[sp,#18*4]				@ pull inp+len
	add	r10,r10,r0
	add	r11,r11,r2
	stmia	r3,{r4,r5,r6,r7,r8,r9,r10,r11}
	cmp	r1,r12
	sub	r14,r14,#256			@ rewind Ktbl
	bne	.Loop

	add	sp,sp,#19*4				@ destroy frame
	ldmia	sp!,{r4-r12,pc}
ENDPROC(sha256_block_data_order)
.asciz  "SHA256 block transform for ARMv4, CRYPTOGAMS by <appro@openssl.org>"
