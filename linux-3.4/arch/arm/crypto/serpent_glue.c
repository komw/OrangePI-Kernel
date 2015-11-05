/*
 * Glue Code for the asm optimized version of SERPENT cipher algorithm
 */

#include <crypto/serpent.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

asmlinkage void serpent_enc_blk(struct serpent_ctx *ctx, u8 *dst,
				const u8 *src);
EXPORT_SYMBOL_GPL(serpent_enc_blk);
asmlinkage void serpent_dec_blk(struct serpent_ctx *ctx, u8 *dst,
				const u8 *src);
EXPORT_SYMBOL_GPL(serpent_dec_blk);

static void serpent_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	serpent_enc_blk(crypto_tfm_ctx(tfm), dst, src);
}

static void serpent_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	serpent_dec_blk(crypto_tfm_ctx(tfm), dst, src);
}

static struct crypto_alg alg = {
	.cra_name		=	"serpent",
	.cra_driver_name	=	"serpent-asm",
	.cra_priority		=	200,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	SERPENT_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct serpent_ctx),
	.cra_alignmask		=	3,
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	=	SERPENT_MIN_KEY_SIZE,
			.cia_max_keysize	=	SERPENT_MAX_KEY_SIZE,
			.cia_setkey		=	serpent_setkey,
			.cia_encrypt		=	serpent_encrypt,
			.cia_decrypt		=	serpent_decrypt
		}
	}
};

static int __init init(void)
{
	return crypto_register_alg(&alg);
}

static void __exit fini(void)
{
	crypto_unregister_alg(&alg);
}

module_init(init);
module_exit(fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION ("Serpent Cipher Algorithm, asm optimized");
MODULE_ALIAS("serpent");
MODULE_ALIAS("serpent-asm");
