#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# SHA256 block procedure for ARMv4. May 2007.

# Performance is ~2x better than gcc 3.4 generated code and in "abso-
# lute" terms is ~2250 cycles per 64-byte block or ~35 cycles per
# byte [on single-issue Xscale PXA250 core].

# July 2010.
#
# Rescheduling for dual-issue pipeline resulted in 22% improvement on
# Cortex A8 core and ~20 cycles per processed byte.

# February 2011.
#
# Profiler-assisted and platform-specific optimization resulted in 16%
# improvement on Cortex A8 core and ~15.4 cycles per processed byte.

while (($output=shift) && ($output!~/^\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$ctx="r0";	$t0="r0";
$inp="r1";	$t4="r1";
$len="r2";	$t1="r2";
$T1="r3";	$t3="r3";
$A="r4";
$B="r5";
$C="r6";
$D="r7";
$E="r8";
$F="r9";
$G="r10";
$H="r11";
@V=($A,$B,$C,$D,$E,$F,$G,$H);
$t2="r12";
$Ktbl="r14";

@Sigma0=( 2,13,22);
@Sigma1=( 6,11,25);
@sigma0=( 7,18, 3);
@sigma1=(17,19,10);

sub BODY_00_15 {
my ($i,$a,$b,$c,$d,$e,$f,$g,$h) = @_;

$code.=<<___ if ($i<16);
#if __ARM_ARCH__>=7
	@ ldr	$t1,[$inp],#4				@ $i
# if $i==15
	str	$inp,[sp,#17*4]				@ make room for $t4
# endif
	eor	$t0,$e,$e,ror#`$Sigma1[1]-$Sigma1[0]`
	add	$a,$a,$t2				@ h+=Maj(a,b,c) from the past
	eor	$t0,$t0,$e,ror#`$Sigma1[2]-$Sigma1[0]`				@ Sigma1(e)
	rev	$t1,$t1
#else
	@ ldrb	$t1,[$inp,#3]				@ $i
	add	$a,$a,$t2				@ h+=Maj(a,b,c) from the past
	ldrb	$t2,[$inp,#2]
	ldrb	$t0,[$inp,#1]
	orr	$t1,$t1,$t2,lsl#8
	ldrb	$t2,[$inp],#4
	orr	$t1,$t1,$t0,lsl#16
# if $i==15
	str	$inp,[sp,#17*4]				@ make room for $t4
# endif
	eor	$t0,$e,$e,ror#`$Sigma1[1]-$Sigma1[0]`
	orr	$t1,$t1,$t2,lsl#24
	eor	$t0,$t0,$e,ror#`$Sigma1[2]-$Sigma1[0]`				@ Sigma1(e)
#endif
___
$code.=<<___;
	ldr	$t2,[$Ktbl],#4				@ *K256++
	add	$h,$h,$t1				@ h+=X[i]
	str	$t1,[sp,#`$i%16`*4]
	eor	$t1,$f,$g
	add	$h,$h,$t0,ror#$Sigma1[0]			@ h+=Sigma1(e)
	and	$t1,$t1,$e
	add	$h,$h,$t2				@ h+=K256[i]
	eor	$t1,$t1,$g				@ Ch(e,f,g)
	eor	$t0,$a,$a,ror#`$Sigma0[1]-$Sigma0[0]`
	add	$h,$h,$t1				@ h+=Ch(e,f,g)
#if $i==31
	and	$t2,$t2,#0xff
	cmp	$t2,#0xf2				@ done?
#endif
#if $i<15
# if __ARM_ARCH__>=7
	ldr	$t1,[$inp],#4				@ prefetch
# else
	ldrb	$t1,[$inp,#3]
# endif
	eor	$t2,$a,$b				@ a^b, b^c in next round
#else
	ldr	$t1,[sp,#`($i+2)%16`*4]				@ from future BODY_16_xx
	eor	$t2,$a,$b				@ a^b, b^c in next round
	ldr	$t4,[sp,#`($i+15)%16`*4]				@ from future BODY_16_xx
#endif
	eor	$t0,$t0,$a,ror#`$Sigma0[2]-$Sigma0[0]`			@ Sigma0(a)
	and	$t3,$t3,$t2				@ (b^c)&=(a^b)
	add	$d,$d,$h				@ d+=h
	eor	$t3,$t3,$b				@ Maj(a,b,c)
	add	$h,$h,$t0,ror#$Sigma0[0]			@ h+=Sigma0(a)
	@ add	$h,$h,$t3				@ h+=Maj(a,b,c)
___
	($t2,$t3)=($t3,$t2);
}

sub BODY_16_XX {
my ($i,$a,$b,$c,$d,$e,$f,$g,$h) = @_;

$code.=<<___;
	@ ldr	$t1,[sp,#`($i+1)%16`*4]			@ $i
	@ ldr	$t4,[sp,#`($i+14)%16`*4]
	mov	$t0,$t1,ror#$sigma0[0]
	add	$a,$a,$t2				@ h+=Maj(a,b,c) from the past
	mov	$t2,$t4,ror#$sigma1[0]
	eor	$t0,$t0,$t1,ror#$sigma0[1]
	eor	$t2,$t2,$t4,ror#$sigma1[1]
	eor	$t0,$t0,$t1,lsr#$sigma0[2]			@ sigma0(X[i+1])
	ldr	$t1,[sp,#`($i+0)%16`*4]
	eor	$t2,$t2,$t4,lsr#$sigma1[2]			@ sigma1(X[i+14])
	ldr	$t4,[sp,#`($i+9)%16`*4]

	add	$t2,$t2,$t0
	eor	$t0,$e,$e,ror#`$Sigma1[1]-$Sigma1[0]`			@ from BODY_00_15
	add	$t1,$t1,$t2
	eor	$t0,$t0,$e,ror#`$Sigma1[2]-$Sigma1[0]`			@ Sigma1(e)
	add	$t1,$t1,$t4				@ X[i]
___
	&BODY_00_15(@_);
}

$code=<<___;
#define __ARM_ARCH__ __LINUX_ARM_ARCH__

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
	add	$len,$inp,$len,lsl#6				@ len to point at the end of inp
	stmdb	sp!,{$ctx,$inp,$len,r4-r12,lr}
	ldmia	$ctx,{$A,$B,$C,$D,$E,$F,$G,$H}
	sub	$Ktbl,r3,#sha256_block_data_order-K256		@ K256
	sub	sp,sp,#16*4				@ alloca(X[16])
.Loop:
# if __ARM_ARCH__>=7
	ldr	$t1,[$inp],#4
# else
	ldrb	$t1,[$inp,#3]
# endif
	eor	$t3,$B,$C				@ magic
	eor	$t2,$t2,$t2
___
for($i=0;$i<16;$i++)	{ &BODY_00_15($i,@V); unshift(@V,pop(@V)); }
$code.=".Lrounds_16_xx:\n";
for (;$i<32;$i++)	{ &BODY_16_XX($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	ldreq	$t3,[sp,#16*4]		@ pull ctx
	bne	.Lrounds_16_xx

	add	$A,$A,$t2				@ h+=Maj(a,b,c) from the past
	ldr	$t0,[$t3,#0]
	ldr	$t1,[$t3,#4]
	ldr	$t2,[$t3,#8]
	add	$A,$A,$t0
	ldr	$t0,[$t3,#12]
	add	$B,$B,$t1
	ldr	$t1,[$t3,#16]
	add	$C,$C,$t2
	ldr	$t2,[$t3,#20]
	add	$D,$D,$t0
	ldr	$t0,[$t3,#24]
	add	$E,$E,$t1
	ldr	$t1,[$t3,#28]
	add	$F,$F,$t2
	ldr	$inp,[sp,#17*4]				@ pull inp
	ldr	$t2,[sp,#18*4]				@ pull inp+len
	add	$G,$G,$t0
	add	$H,$H,$t1
	stmia	$t3,{$A,$B,$C,$D,$E,$F,$G,$H}
	cmp	$inp,$t2
	sub	$Ktbl,$Ktbl,#256			@ rewind Ktbl
	bne	.Loop

	add	sp,sp,#`16+3`*4				@ destroy frame
	ldmia	sp!,{r4-r12,pc}
ENDPROC(sha256_block_data_order)
___
$code.=<<___;
.asciz  "SHA256 block transform for ARMv4, CRYPTOGAMS by <appro\@openssl.org>"
___

{   my  %opcode = (
	"sha256h"	=> 0xf3000c40,	"sha256h2"	=> 0xf3100c40,
	"sha256su0"	=> 0xf3ba03c0,	"sha256su1"	=> 0xf3200c40	);

    sub unsha256 {
	my ($mnemonic,$arg)=@_;

	if ($arg =~ m/q([0-9]+)(?:,\s*q([0-9]+))?,\s*q([0-9]+)/o) {
	    my $word = $opcode{$mnemonic}|(($1&7)<<13)|(($1&8)<<19)
					 |(($2&7)<<17)|(($2&8)<<4)
					 |(($3&7)<<1) |(($3&8)<<2);
	    # since ARMv7 instructions are always encoded little-endian.
	    # correct solution is to use .inst directive, but older
	    # assemblers don't implement it:-(
	    sprintf ".byte\t0x%02x,0x%02x,0x%02x,0x%02x\t@ %s %s",
			$word&0xff,($word>>8)&0xff,
			($word>>16)&0xff,($word>>24)&0xff,
			$mnemonic,$arg;
	}
    }
}

foreach (split($/,$code)) {

	s/\`([^\`]*)\`/eval $1/geo;

	s/\b(sha256\w+)\s+(q.*)/unsha256($1,$2)/geo;

	s/\bret\b/bx	lr/go		or
	s/\bbx\s+lr\b/.word\t0xe12fff1e/go;	# make it possible to compile with -march=armv4

	print $_,"\n";
}

close STDOUT; # enforce flush
