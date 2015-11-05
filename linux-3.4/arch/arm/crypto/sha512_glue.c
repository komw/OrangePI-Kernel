/*
 * Cryptographic API.
 *
 * Glue code for the SHA512 Secure Hash Algorithm assembler
 * implementation using supplemental SSE3 / AVX / AVX2 instructions.
 *
 * This file is based on sha512_generic.c and sha512_ssse3_glue.c
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
 *
 */

#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cryptohash.h>
#include <linux/types.h>
#include <crypto/sha.h>
#include <asm/byteorder.h>


asmlinkage void sha512_block_data_order(u64 *digest,
				const unsigned char *data, unsigned int rounds);
EXPORT_SYMBOL_GPL(sha512_block_data_order);

static int sha512_init(struct shash_desc *desc)
{
	struct sha512_state *sctx = shash_desc_ctx(desc);

	sctx->state[0] = SHA512_H0;
	sctx->state[1] = SHA512_H1;
	sctx->state[2] = SHA512_H2;
	sctx->state[3] = SHA512_H3;
	sctx->state[4] = SHA512_H4;
	sctx->state[5] = SHA512_H5;
	sctx->state[6] = SHA512_H6;
	sctx->state[7] = SHA512_H7;
	sctx->count[0] = sctx->count[1] = 0;

	return 0;
}

static int __sha512_update(struct sha512_state *sctx, const u8 *data,
			       unsigned int len, unsigned int partial)
{
	unsigned int done = 0;

	sctx->count[0] += len;
	if (sctx->count[0] < len)
		sctx->count[1]++;

	if (partial) {
		done = SHA512_BLOCK_SIZE - partial;
		memcpy(sctx->buf + partial, data, done);
		sha512_block_data_order(sctx->state, sctx->buf, 1);
	}

	if (len - done >= SHA512_BLOCK_SIZE) {
		const unsigned int rounds = (len - done) / SHA512_BLOCK_SIZE;

		sha512_block_data_order(sctx->state, sctx->buf, (u32) rounds);

		done += rounds * SHA512_BLOCK_SIZE;
	}

	memcpy(sctx->buf, data + done, len - done);
	return 0;
}

static int sha512_update(struct shash_desc *desc, const u8 *data,
			     unsigned int len)
{
	struct sha512_state *sctx = shash_desc_ctx(desc);
	unsigned int partial = sctx->count[0] % SHA512_BLOCK_SIZE;
	int res;

	/* Handle the fast case right here */
	if (partial + len < SHA512_BLOCK_SIZE) {
		sctx->count[0] += len;
		if (sctx->count[0] < len)
			sctx->count[1]++;
		memcpy(sctx->buf + partial, data, len);
		return 0;
	}

	res = __sha512_update(sctx, data, len, partial);
	return res;
}


/* Add padding and return the message digest. */
static int sha512_final(struct shash_desc *desc, u8 *out)
{
	struct sha512_state *sctx = shash_desc_ctx(desc);
	unsigned int i, index, padlen;
	__be64 *dst = (__be64 *)out;
	__be64 bits[2];
	static const u8 padding[SHA512_BLOCK_SIZE] = { 0x80, };

	/* save number of bits */
	bits[1] = cpu_to_be64(sctx->count[0] << 3);
	bits[0] = cpu_to_be64(sctx->count[1] << 3 | sctx->count[0] >> 61);

	/* Pad out to 112 mod 128 and append length */
	index = sctx->count[0] & 0x7f;
	padlen = (index < 112) ? (112 - index) : ((128+112) - index);

	/* We need to fill a whole block for __sha512_update() */
	if (padlen <= 112) {
		sctx->count[0] += padlen;
		if (sctx->count[0] < padlen)
			sctx->count[1]++;
		memcpy(sctx->buf + index, padding, padlen);
	} else {
		__sha512_update(sctx, padding, padlen, index);
	}
	__sha512_update(sctx, (const u8 *)&bits, sizeof(bits), 112);

	/* Store state in digest */
	for (i = 0; i < 8; i++)
		dst[i] = cpu_to_be64(sctx->state[i]);

	/* Wipe context */
	memset(sctx, 0, sizeof(*sctx));
	return 0;
}

static int sha512_export(struct shash_desc *desc, void *out)
{
	struct sha512_state *sctx = shash_desc_ctx(desc);
	memcpy(out, sctx, sizeof(*sctx));
	return 0;
}

static int sha512_import(struct shash_desc *desc, const void *in)
{
	struct sha512_state *sctx = shash_desc_ctx(desc);
	memcpy(sctx, in, sizeof(*sctx));
	return 0;
}

static int sha384_init(struct shash_desc *desc)
{
	struct sha512_state *sctx = shash_desc_ctx(desc);

	sctx->state[0] = SHA384_H0;
	sctx->state[1] = SHA384_H1;
	sctx->state[2] = SHA384_H2;
	sctx->state[3] = SHA384_H3;
	sctx->state[4] = SHA384_H4;
	sctx->state[5] = SHA384_H5;
	sctx->state[6] = SHA384_H6;
	sctx->state[7] = SHA384_H7;

	sctx->count[0] = sctx->count[1] = 0;

	return 0;
}

static int sha384_final(struct shash_desc *desc, u8 *hash)
{
	u8 D[SHA512_DIGEST_SIZE];

	sha512_final(desc, D);

	memcpy(hash, D, SHA384_DIGEST_SIZE);
	memset(D, 0, SHA512_DIGEST_SIZE);

	return 0;
}

static struct shash_alg sha512 = {
	.digestsize	=	SHA512_DIGEST_SIZE,
	.init		=	sha512_init,
	.update		=	sha512_update,
	.final		=	sha512_final,
	.export		=	sha512_export,
	.import		=	sha512_import,
	.descsize	=	sizeof(struct sha512_state),
	.statesize	=	sizeof(struct sha512_state),
	.base		=	{
		.cra_name	=	"sha512",
		.cra_driver_name =	"sha512-asm",
		.cra_priority	=	150,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	SHA512_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

static struct shash_alg sha384 = {
	.digestsize	=	SHA384_DIGEST_SIZE,
	.init		=	sha384_init,
	.update		=	sha512_update,
	.final		=	sha384_final,
	.export		=	sha512_export,
	.import		=	sha512_import,
	.descsize	=	sizeof(struct sha512_state),
	.statesize	=	sizeof(struct sha512_state),
	.base		=	{
		.cra_name	=	"sha384",
		.cra_driver_name =	"sha384-asm",
		.cra_priority	=	150,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	SHA384_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

static int __init sha512_mod_init(void)
{
	int ret = 0;

	ret = crypto_register_shash(&sha384);

	if (ret < 0)
		return ret;

	ret = crypto_register_shash(&sha512);

	if (ret < 0)
		crypto_unregister_shash(&sha384);

	return ret;
}

static void __exit sha512_mod_fini(void)
{
	crypto_unregister_shash(&sha384);
	crypto_unregister_shash(&sha512);
}

module_init(sha512_mod_init);
module_exit(sha512_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA512 Secure Hash Algorithm, (ARM)");

MODULE_ALIAS("sha512");
MODULE_ALIAS("sha384");
MODULE_ALIAS("sha512-asm");
MODULE_ALIAS("sha384-asm");
