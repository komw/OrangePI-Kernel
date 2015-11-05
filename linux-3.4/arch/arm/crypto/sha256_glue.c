/*
 * Cryptographic API.
 *
 * Glue code for the SHA256 Secure Hash Algorithm assembler
 * implementation using supplemental SSE3 / AVX / AVX2 instructions.
 *
 * This file is based on sha256_generic.c and sha256_ssse3_glue.c
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cryptohash.h>
#include <linux/types.h>
#include <crypto/sha.h>
#include <asm/byteorder.h>

asmlinkage void sha256_block_data_order(unsigned int *digest,
		const unsigned char *data, unsigned int rounds);
EXPORT_SYMBOL_GPL(sha256_block_data_order);

static int sha256_init(struct shash_desc *desc)
{
	struct sha256_state *sctx = shash_desc_ctx(desc);
	memset(sctx,0,sizeof(*sctx));
	sctx->state[0] = SHA256_H0;
	sctx->state[1] = SHA256_H1;
	sctx->state[2] = SHA256_H2;
	sctx->state[3] = SHA256_H3;
	sctx->state[4] = SHA256_H4;
	sctx->state[5] = SHA256_H5;
	sctx->state[6] = SHA256_H6;
	sctx->state[7] = SHA256_H7;
	sctx->count = 0;

	return 0;
}

static int __sha256_update(struct sha256_state *sctx, const u8 *data,
				 unsigned int len, unsigned int partial)
{
	unsigned int done = 0;

	sctx->count += len;

	if (partial) {
		done = SHA256_BLOCK_SIZE - partial;
		memcpy(sctx->buf + partial, data, done);
		sha256_block_data_order(sctx->state, sctx->buf, 1);
	}

	if (len - done >= SHA256_BLOCK_SIZE) {
		const unsigned int rounds = (len - done) / SHA256_BLOCK_SIZE;

		sha256_block_data_order(sctx->state, data + done, (u32) rounds);

		done += rounds * SHA256_BLOCK_SIZE;
	}

	memcpy(sctx->buf, data + done, len - done);
	return 0;
}

static int sha256_update(struct shash_desc *desc, const u8 *data,
			       unsigned int len)
{
	struct sha256_state *sctx = shash_desc_ctx(desc);
	unsigned int partial = sctx->count % SHA256_BLOCK_SIZE;
	int res;

	/* Handle the fast case right here */
	if (partial + len < SHA256_BLOCK_SIZE) {
		sctx->count += len;
		memcpy(sctx->buf + partial, data, len);
		return 0;
	}

	res = __sha256_update(sctx, data, len, partial);
	return res;
}


/* Add padding and return the message digest. */
static int sha256_final(struct shash_desc *desc, u8 *out)
{
	struct sha256_state *sctx = shash_desc_ctx(desc);
	unsigned int i, index, padlen;
	__be32 *dst = (__be32 *)out;
	__be64 bits;
	static const u8 padding[SHA256_BLOCK_SIZE] = { 0x80, };

	bits = cpu_to_be64(sctx->count << 3);

	/* Pad out to 56 mod 64 and append length */
	index = sctx->count % SHA256_BLOCK_SIZE;
	padlen = (index < 56) ? (56 - index) : ((SHA256_BLOCK_SIZE+56)-index);
	/* We need to fill a whole block for __sha256_update() */
	if (padlen <= 56) {
		sctx->count += padlen;
		memcpy(sctx->buf + index, padding, padlen);
	} else {
		__sha256_update(sctx, padding, padlen, index);
	}
	__sha256_update(sctx, (const u8 *)&bits, sizeof(bits), 56);

	/* Store state in digest */
	for (i = 0; i < 8; i++)
		dst[i] = cpu_to_be32(sctx->state[i]);

	/* Wipe context */
	memset(sctx, 0, sizeof(*sctx));
	return 0;
}

static int sha256_export(struct shash_desc *desc, void *out)
{
	struct sha256_state *sctx = shash_desc_ctx(desc);
	memcpy(out, sctx, sizeof(*sctx));
	return 0;
}

static int sha256_import(struct shash_desc *desc, const void *in)
{
	struct sha256_state *sctx = shash_desc_ctx(desc);
	memcpy(sctx, in, sizeof(*sctx));
	return 0;
}

static int sha224_init(struct shash_desc *desc)
{
	struct sha256_state *sctx = shash_desc_ctx(desc);

	sctx->state[0] = SHA224_H0;
	sctx->state[1] = SHA224_H1;
	sctx->state[2] = SHA224_H2;
	sctx->state[3] = SHA224_H3;
	sctx->state[4] = SHA224_H4;
	sctx->state[5] = SHA224_H5;
	sctx->state[6] = SHA224_H6;
	sctx->state[7] = SHA224_H7;
	sctx->count = 0;

	return 0;
}

static int sha224_final(struct shash_desc *desc, u8 *hash)
{
	u8 D[SHA256_DIGEST_SIZE];

	sha256_final(desc, D);

	memcpy(hash, D, SHA224_DIGEST_SIZE);
	memset(D, 0, SHA256_DIGEST_SIZE);

	return 0;
}

static struct shash_alg sha256 = {
	.digestsize	=	SHA256_DIGEST_SIZE,
	.init		=	sha256_init,
	.update		=	sha256_update,
	.final		=	sha256_final,
	.export		=	sha256_export,
	.import		=	sha256_import,
	.descsize	=	sizeof(struct sha256_state),
	.statesize	=	sizeof(struct sha256_state),
	.base		=	{
		.cra_name	=	"sha256",
		.cra_driver_name =	"sha256-asm",
		.cra_priority	=	150,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	SHA256_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

static struct shash_alg sha224 = {
	.digestsize	=	SHA224_DIGEST_SIZE,
	.init		=	sha224_init,
	.update		=	sha256_update,
	.final		=	sha224_final,
	.export		=	sha256_export,
	.import		=	sha256_import,
	.descsize	=	sizeof(struct sha256_state),
	.statesize	=	sizeof(struct sha256_state),
	.base		=	{
		.cra_name	=	"sha224",
		.cra_driver_name =	"sha224-asm",
		.cra_priority	=	150,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	SHA224_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

static int __init sha256_mod_init(void)
{
	int ret = 0;

	ret = crypto_register_shash(&sha224);

	if (ret < 0)
		return ret;

	ret = crypto_register_shash(&sha256);

	if (ret < 0)
		crypto_unregister_shash(&sha224);

	return ret;
}

static void __exit sha256_mod_fini(void)
{
	crypto_unregister_shash(&sha224);
	crypto_unregister_shash(&sha256);
}

module_init(sha256_mod_init);
module_exit(sha256_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA256 Secure Hash Algorithm (ARM)");

MODULE_ALIAS("sha256");
MODULE_ALIAS("sha224");
MODULE_ALIAS("sha256-asm");
MODULE_ALIAS("sha224-asm");
