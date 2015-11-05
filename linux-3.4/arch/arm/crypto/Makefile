#
# Arch-specific CryptoAPI modules.
#

obj-$(CONFIG_CRYPTO_GLUE_HELPER_ARM) += glue_helper.o

obj-$(CONFIG_CRYPTO_AES_ARM) += aes-arm.o
obj-$(CONFIG_CRYPTO_AES_ARM_BS) += aes-arm-bs.o
obj-$(CONFIG_CRYPTO_SHA1_ARM) += sha1-arm.o
obj-$(CONFIG_CRYPTO_SHA1_ARM_NEON) += sha1-arm-neon.o
obj-$(CONFIG_CRYPTO_SHA256_ARM) += sha256-arm.o
obj-$(CONFIG_CRYPTO_SHA256_ARM_NEON) += sha256-arm-neon.o
obj-$(CONFIG_CRYPTO_SHA512_ARM) += sha512-arm.o
obj-$(CONFIG_CRYPTO_SHA512_ARM_NEON) += sha512-arm-neon.o
obj-$(CONFIG_CRYPTO_TWOFISH_ARM) += twofish-arm.o
obj-$(CONFIG_CRYPTO_TWOFISH_ARM_NEON) += twofish-arm-neon.o
obj-$(CONFIG_CRYPTO_SERPENT_ARM) += serpent-arm.o
obj-$(CONFIG_CRYPTO_SERPENT_ARM_NEON) += serpent-arm-neon.o

aes-arm-y	:= aes-armv4.o aes_glue.o
aes-arm-bs-y	:= aesbs-core.o aesbs-glue.o
sha1-arm-y	:= sha1-armv4-large.o sha1_glue.o
sha1-arm-neon-y	:= sha1-armv7-neon.o sha1_neon_glue.o
sha256-arm-y	:= sha256-armv4-large.o sha256_glue.o
sha256-arm-neon-y := sha256-armv7-neon.o sha256_neon_glue.o
sha512-arm-y	:= sha512-armv4-large.o sha512_glue.o
sha512-arm-neon-y := sha512-armv7-neon.o sha512_neon_glue.o
twofish-arm-y	:= twofish-armv4.o twofish_glue.o
twofish-arm-neon-y := twofish-armv7-neon.o twofish_neon_glue.o
serpent-arm-y	:= serpent-armv4.o serpent_glue.o
serpent-arm-neon-y := serpent-armv7-neon.o serpent_neon_glue.o
