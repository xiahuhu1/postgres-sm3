/*
 * libpq_testclient.c
 *		A test program for the libpq public API
 *
 * Copyright (c) 2022-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		src/interfaces/libpq/test/libpq_testclient.c
 */

#include "postgres_fe.h"

#include "libpq-fe.h"

static void
print_ssl_library()
{
	const char *lib = PQsslAttribute(NULL, "library");

	if (!lib)
		fprintf(stderr, "SSL is not enabled\n");
	else
		printf("%s\n", lib);
}

static int
test_sm3(const char *conninfo, bool reset_deny)
{
	PGconn	   *conn = PQconnectdb(conninfo);
	PGresult   *res;
	char	   *secret;
	int			result = 1;

	if (PQstatus(conn) != CONNECTION_OK)
		goto done;

	if (reset_deny)
	{
		/* Let the TAP test change the server's authentication family. */
		printf("ready\n");
		fflush(stdout);
		if (getchar() == EOF)
			goto done;
		PQreset(conn);
		if (PQstatus(conn) == CONNECTION_BAD)
		{
			printf("%s", PQerrorMessage(conn));
			result = 0;
		}
		goto done;
	}

	res = PQexec(conn,
				 "SET password_encryption = 'scram-sm3'; SET scram_iterations = 42");
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		PQclear(res);
		goto done;
	}
	PQclear(res);

	secret = PQencryptPasswordConn(conn, "pass", PQuser(conn), "scram-sm3");
	if (secret == NULL)
		goto done;
	if (strncmp(secret, "SCRAM-SM3$42:", strlen("SCRAM-SM3$42:")) != 0)
	{
		PQfreemem(secret);
		goto done;
	}
	PQfreemem(secret);
	printf("explicit SM3 verifier\n");

	secret = PQencryptPasswordConn(conn, "pass", PQuser(conn), NULL);
	if (secret == NULL)
		goto done;
	if (strncmp(secret, "SCRAM-SM3$42:", strlen("SCRAM-SM3$42:")) != 0)
	{
		PQfreemem(secret);
		goto done;
	}
	PQfreemem(secret);
	printf("default SM3 verifier\n");

	res = PQchangePassword(conn, PQuser(conn), "pass");
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		PQclear(res);
		goto done;
	}
	PQclear(res);
	printf("SM3 password changed\n");

	PQreset(conn);
	if (PQstatus(conn) != CONNECTION_OK)
		goto done;
	printf("SM3 reset succeeded\n");
	result = 0;

done:
	if (result != 0)
		fprintf(stderr, "SM3 API test failed: %s", PQerrorMessage(conn));
	PQfinish(conn);
	return result;
}

int
main(int argc, char *argv[])
{
	if ((argc > 1) && !strcmp(argv[1], "--ssl"))
	{
		print_ssl_library();
		return 0;
	}
	if (argc == 3 && (!strcmp(argv[1], "--sm3") ||
					  !strcmp(argv[1], "--sm3-reset-deny")))
		return test_sm3(argv[2], !strcmp(argv[1], "--sm3-reset-deny"));

	printf("expected --ssl, --sm3 CONNINFO or --sm3-reset-deny CONNINFO\n");
	return 1;
}
