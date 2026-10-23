/*
 * Standalone frontend checks for the shared SCRAM-SM3 primitives.
 * See README.md for compilation against a configured PostgreSQL build.
 */
#include "postgres_fe.h"

#include "common/cryptohash.h"
#include "common/hmac.h"
#include "common/scram-common.h"

static int failures;

static void
check(bool success, const char *name)
{
	printf("%s: %s\n", success ? "ok" : "FAIL", name);
	if (!success)
		failures++;
}

#ifndef SM3_EXPECT_UNSUPPORTED
static bool
matches_hex(const uint8 *data, const char *hex)
{
	char result[PG_SM3_DIGEST_LENGTH * 2 + 1];
	int i;

	for (i = 0; i < PG_SM3_DIGEST_LENGTH; i++)
		sprintf(result + i * 2, "%02x", data[i]);
	return strcmp(result, hex) == 0;
}

static void
check_hash(const char *input, const char *expected, const char *name)
{
	uint8 result[PG_SM3_DIGEST_LENGTH];
	pg_cryptohash_ctx *ctx = pg_cryptohash_create(PG_SM3);

	check(ctx != NULL && pg_cryptohash_init(ctx) == 0 &&
		  pg_cryptohash_update(ctx, (const uint8 *) input, strlen(input)) == 0 &&
		  pg_cryptohash_final(ctx, result, sizeof(result)) == 0 &&
		  matches_hex(result, expected), name);
	pg_cryptohash_free(ctx);
}
#endif

int
main(void)
{
	const char *errstr = NULL;
	uint8 result[PG_SM3_DIGEST_LENGTH];
	pg_cryptohash_ctx *hash;
	pg_hmac_ctx *hmac;
	char *secret;

#ifdef SM3_EXPECT_UNSUPPORTED
	hash = pg_cryptohash_create(PG_SM3);
	check(hash != NULL && pg_cryptohash_init(hash) == -1 &&
		  pg_cryptohash_update(hash, (const uint8 *) "abc", 3) == -1 &&
		  pg_cryptohash_final(hash, result, sizeof(result)) == -1 &&
		  strstr(pg_cryptohash_error(hash), "not supported") != NULL,
		  "unavailable SM3 hash fails explicitly");
	pg_cryptohash_free(hash);
	hmac = pg_hmac_create(PG_SM3);
	check(hmac != NULL && pg_hmac_init(hmac, (const uint8 *) "key", 3) == -1 &&
		  pg_hmac_update(hmac, (const uint8 *) "abc", 3) == -1 &&
		  pg_hmac_final(hmac, result, sizeof(result)) == -1 &&
		  strstr(pg_hmac_error(hmac), "not supported") != NULL,
		  "unavailable HMAC-SM3 fails explicitly");
	pg_hmac_free(hmac);
	secret = scram_build_secret(PG_SM3, SCRAM_SM3_KEY_LEN,
								"0123456789abcdef", 16, 4096, "pencil", &errstr);
	check(secret == NULL && errstr != NULL, "unavailable SM3 verifier fails");
	free(secret);
#else
	static const struct
	{
		int iterations;
		const char *expected;
	} pbkdf2[] = {
		{1, "4612f922a1fdcefaf4312fc6f8f3322b489cbf24f2ea361b44c2bd8fa2c6dcb0"},
		{2, "fee723a2bc966e11dffb66133f4e8df577383c78ade30e3298edbd3e54ed85b7"},
		{4096, "b6e8f2074c87432b78f62e5ced980fdff89e86af2f693dab1638e2b3683045dd"}
	};
	size_t i;

	check_hash("abc",
			   "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
			   "SM3 standard abc vector");
	check_hash("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
			   "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
			   "SM3 standard 64-byte vector");
	hmac = pg_hmac_create(PG_SM3);
	check(hmac != NULL && pg_hmac_init(hmac, (const uint8 *) "key", 3) == 0 &&
		  pg_hmac_update(hmac, (const uint8 *) "The quick brown fox jumps over the lazy dog", 43) == 0 &&
		  pg_hmac_final(hmac, result, sizeof(result)) == 0 &&
		  matches_hex(result, "bd4a34077888162b210645b8ebf74b9af357303789357a27c7fc457244ebd398"),
		  "HMAC-SM3 vector");
	pg_hmac_free(hmac);
	for (i = 0; i < lengthof(pbkdf2); i++)
	{
		char name[80];

		snprintf(name, sizeof(name), "PBKDF2-HMAC-SM3 %d iterations", pbkdf2[i].iterations);
		check(scram_SaltedPassword("password", PG_SM3, SCRAM_SM3_KEY_LEN,
								   "salt", 4, pbkdf2[i].iterations, result, &errstr) == 0 &&
			  matches_hex(result, pbkdf2[i].expected), name);
	}
	secret = scram_build_secret(PG_SM3, SCRAM_SM3_KEY_LEN,
								"0123456789abcdef", 16, 4096, "pencil", &errstr);
	check(secret != NULL && strcmp(secret,
		  "SCRAM-SM3$4096:MDEyMzQ1Njc4OWFiY2RlZg==$3VDRDUacXR3QJvQMpIW7O977W8zXPkExcnJhfTV9nDA=:wTnMk1YnOhilUCIQlRac05w8NNxo5uKKhAMLmAJk8sk=") == 0,
		  "SCRAM-SM3 verifier format and keys");
	free(secret);
	hash = pg_cryptohash_create(PG_SM3);
	check(hash != NULL && pg_cryptohash_init(hash) == 0 &&
		  pg_cryptohash_final(hash, result, sizeof(result) - 1) == -1,
		  "SM3 refuses undersized output buffer");
	pg_cryptohash_free(hash);
	hmac = pg_hmac_create(PG_SM3);
	check(hmac != NULL && pg_hmac_init(hmac, (const uint8 *) "key", 3) == 0 &&
		  pg_hmac_final(hmac, result, sizeof(result) - 1) == -1,
		  "HMAC-SM3 refuses undersized output buffer");
	pg_hmac_free(hmac);
#endif
	secret = scram_build_secret(PG_SHA256, SCRAM_SHA_256_KEY_LEN,
								"0123456789abcdef", 16, 4096, "pencil", &errstr);
	check(secret != NULL && strcmp(secret,
		  "SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==$nQpbZ77WudtqufPwikHXGRt6g2QJ4zns8bZLw273DRM=:jn2amWP1q1h+jgjy0YTO14S6/F02SV7taipOeB7ef20=") == 0,
		  "SCRAM-SHA-256 verifier stays unchanged");
	free(secret);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
