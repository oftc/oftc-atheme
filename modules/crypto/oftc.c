/*
 * SPDX-License-Identifier: ISC
 * SPDX-URL: https://spdx.org/licenses/ISC.html
 *
 * Copyright (C) 2009 Atheme Project (http://atheme.org/)
 * Copyright (C) 2019 Atheme Development Group (https://atheme.github.io/)
 *
 * OFTC password verification
 */

#include <atheme.h>

#define OFTC_PREFIX_STR      "$oftc$"
#define OFTC_PREFIX_LEN      strlen(OFTC_PREFIX_STR)
#define OFTC_SALT_LEN        16U
#define OFTC_DIGEST_ALG      DIGALG_SHA1
#define OFTC_DIGEST_LEN      DIGEST_MDLEN_SHA1
#define OFTC_HASH_LEN        BASE64_SIZE_RAW(OFTC_DIGEST_LEN)
#define OFTC_PARAMS_LEN      (OFTC_PREFIX_LEN + OFTC_SALT_LEN + 1U + OFTC_HASH_LEN)
#define OFTC_LOADHASH_FORMAT OFTC_PREFIX_STR "%[A-Za-z]$%[" BASE64_ALPHABET_RFC4648 "]"

static bool ATHEME_FATTR_WUR
atheme_oftc_verify(const char *const restrict password, const char *const restrict parameters,
                      unsigned int *const restrict flags)
{
	bool result = false;
	char salt[OFTC_SALT_LEN + 1];
	char b64hash[OFTC_HASH_LEN + 1];
	char saved_digest[OFTC_DIGEST_LEN];
	char calc_digest[OFTC_DIGEST_LEN];

	if (strncmp(parameters, OFTC_PREFIX_STR, OFTC_PREFIX_LEN) != 0)
	{
		(void) slog(LG_DEBUG, "%s: no prefix match", MOWGLI_FUNC_NAME);
		return false;
	}

	*flags |= PWVERIFY_FLAG_MYMODULE;

	/* Intentionally below PWVERIFY_FLAG_MYMODULE for scrambled passwords --dwfreed */
	if (strlen(parameters) != OFTC_PARAMS_LEN)
	{
		(void) slog(LG_DEBUG, "%s: hash not long enough (scrambled?)", MOWGLI_FUNC_NAME);
		return false;
	}

	if (sscanf(parameters, OFTC_LOADHASH_FORMAT, &salt, &b64hash) != 2)
	{
		(void) slog(LG_DEBUG, "%s: sscanf(3) was unsuccessful", MOWGLI_FUNC_NAME);
		goto cleanup;
	}

	struct digest_vector dig_vector[2] = {0};
	dig_vector[0].ptr = password;
	dig_vector[0].len = strlen(password);
	dig_vector[1].ptr = salt;
	dig_vector[1].len = OFTC_SALT_LEN;

	if (!digest_oneshot_vector(OFTC_DIGEST_ALG, dig_vector, 2, calc_digest, NULL))
	{
		(void) slog(LG_DEBUG, "%s: digest failed", MOWGLI_FUNC_NAME);
		goto cleanup;
	}

	if (base64_decode(b64hash, saved_digest, OFTC_DIGEST_LEN) != OFTC_DIGEST_LEN)
	{
		(void) slog(LG_DEBUG, "%s: base64_decode failed", MOWGLI_FUNC_NAME);
		goto cleanup;
	}

	result = (smemcmp(saved_digest, calc_digest, OFTC_DIGEST_LEN) == 0);

cleanup:
	smemzero(salt, sizeof salt);
	smemzero(b64hash, sizeof b64hash);
	smemzero(saved_digest, sizeof saved_digest);
	smemzero(calc_digest, sizeof calc_digest);

	return result;
}

static const struct crypt_impl crypto_oftc_impl = {

	.id         = "crypto/oftc",
	.verify     = &atheme_oftc_verify,
};

static void
mod_init(struct module *const restrict m)
{
	(void) crypt_register(&crypto_oftc_impl);

	m->mflags |= MODFLAG_DBCRYPTO;
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	(void) crypt_unregister(&crypto_oftc_impl);
}

SIMPLE_DECLARE_MODULE_V1("crypto/oftc", MODULE_UNLOAD_CAPABILITY_OK)
