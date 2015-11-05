#ifndef ASM_ARM_TWOFISH_NEON_H
#define ASM_ARM_TWOFISH_NEON_H

#include <linux/crypto.h>
#include <crypto/twofish.h>

asmlinkage void twofish_ecb_enc_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src);
asmlinkage void twofish_ecb_dec_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src);

asmlinkage void twofish_cbc_dec_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src);
asmlinkage void twofish_ctr_8way_neon(struct twofish_ctx *ctx, u8 *dst,
				     const u8 *src, le128 *iv);

asmlinkage void twofish_xts_enc_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src, le128 *iv);
asmlinkage void twofish_xts_dec_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src, le128 *iv);

extern void __twofish_crypt_ctr(void *ctx, u128 *dst, const u128 *src,
				le128 *iv);

extern void twofish_enc_blk(void *ctx, u8 *dst, const u8 *src);
extern void twofish_dec_blk(void *ctx, u8 *dst, const u8 *src);

extern void twofish_xts_enc(void *ctx, u128 *dst, const u128 *src, le128 *iv);
extern void twofish_xts_dec(void *ctx, u128 *dst, const u128 *src, le128 *iv);

extern int lrw_twofish_setkey(struct crypto_tfm *tfm, const u8 *key,
			      unsigned int keylen);

extern void lrw_twofish_exit_tfm(struct crypto_tfm *tfm);

extern int xts_twofish_setkey(struct crypto_tfm *tfm, const u8 *key,
			      unsigned int keylen);

#endif
