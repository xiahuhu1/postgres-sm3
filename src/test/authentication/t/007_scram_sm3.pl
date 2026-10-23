# Copyright (c) 2026, PostgreSQL Global Development Group

# Server-side SCRAM-SM3 storage, authentication family isolation and initdb.
use strict;
use warnings FATAL => 'all';
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

if (!$use_unix_sockets || !check_pg_config('#define HAVE_EVP_SM3 1'))
{
	plan skip_all => 'SCRAM-SM3 requires OpenSSL SM3 and Unix-domain sockets';
}

my $tempdir = PostgreSQL::Test::Utils::tempdir;
my $pwfile = "$tempdir/password";
append_to_file($pwfile, "pass\n");
chmod(0600, $pwfile) or die "chmod: $!";
local $ENV{PGUSER} = 'sm3_admin';
local $ENV{PGPASSWORD} = 'pass';

my $node = PostgreSQL::Test::Cluster->new('sm3_server');
$node->init(extra => [ '-A', 'scram-sm3', '-U', 'sm3_admin', '--pwfile', $pwfile ]);
$node->start;
is($node->safe_psql('postgres', 'SHOW password_encryption'), 'scram-sm3',
	'initdb persists SM3 as the password encryption default');
is($node->safe_psql('postgres', q{
    SELECT rolpassword LIKE 'SCRAM-SM3$%' FROM pg_authid WHERE rolname = 'sm3_admin'
}), 't', 'initdb superuser has an SM3 verifier');
$node->connect_ok('user=sm3_admin require_auth=scram-sm3',
	'initdb superuser authenticates with SM3');

# The empty-password verifier is generated independently with PBKDF2-HMAC-SM3,
# salt "0123456789abcdef", iteration count 2. Prehashed empty passwords must
# be cleared exactly like plaintext empty passwords.
$node->safe_psql('postgres', q{
    CREATE ROLE sm3_user LOGIN PASSWORD 'pass';
    CREATE ROLE null_user LOGIN;
    CREATE ROLE sm3_as_sha LOGIN PASSWORD 'pass';
    CREATE ROLE sm3_as_md5 LOGIN PASSWORD 'pass';
    CREATE ROLE plain_user LOGIN PASSWORD 'pass';
    CREATE ROLE copied_user LOGIN;
    CREATE ROLE invalid_user LOGIN;
    CREATE ROLE empty_user LOGIN PASSWORD
      'SCRAM-SM3$2:MDEyMzQ1Njc4OWFiY2RlZg==$eAFLDm4ySYGThbuCFIbsk6HAQBxDmW9A9nWBlGzRQTg=:PPXVnomjsl5lDJ1/8O/HfuGUCKPE+fWAQs/d5dzoF9E=';
    SET password_encryption = 'scram-sha-256';
    CREATE ROLE sha_user LOGIN PASSWORD 'pass';
    CREATE ROLE sha_as_sm3 LOGIN PASSWORD 'pass';
    DO $do$
    DECLARE verifier text;
    BEGIN
        SELECT rolpassword INTO verifier FROM pg_authid WHERE rolname = 'sm3_user';
        EXECUTE format('ALTER ROLE copied_user PASSWORD %L', verifier);
    END $do$;
    SET password_encryption = 'md5';
    CREATE ROLE md5_user LOGIN PASSWORD 'pass';
});
is($node->safe_psql('postgres', q{
    SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = 'empty_user'
}), 't', 'prehashed SM3 empty password is disabled');
is($node->safe_psql('postgres', q{
    SELECT a.rolpassword = b.rolpassword
    FROM pg_authid a, pg_authid b
    WHERE a.rolname = 'sm3_user' AND b.rolname = 'copied_user'
}), 't', 'an SM3 verifier is preserved under a different encryption setting');

# Invalid iteration fields must not be narrowed into valid positive int values.
for my $iterations ('0', '-1', '2147483648', '4294967297', '999999999999999999999999')
{
	my $secret = 'SCRAM-SM3$' . $iterations .
	  ':MDEyMzQ1Njc4OWFiY2RlZg==$eAFLDm4ySYGThbuCFIbsk6HAQBxDmW9A9nWBlGzRQTg=:PPXVnomjsl5lDJ1/8O/HfuGUCKPE+fWAQs/d5dzoF9E=';
	$node->safe_psql('postgres',
		"ALTER ROLE invalid_user PASSWORD '$secret'");
	is($node->safe_psql('postgres',
		"SELECT rolpassword <> '$secret' FROM pg_authid WHERE rolname = 'invalid_user'"),
		't', "iteration count $iterations is not accepted as a verifier");
}

unlink($node->data_dir . '/pg_hba.conf');
$node->append_conf('pg_hba.conf', q{
local all sm3_as_sha scram-sha-256
local all sm3_as_md5 md5
local all sha_user scram-sha-256
local all md5_user md5
local all plain_user password
local all all scram-sm3
});
$node->reload;

$node->connect_ok('user=sm3_user', 'ordinary SM3 authentication');
$node->connect_ok('user=copied_user', 'copied SM3 verifier authenticates');
$node->connect_ok('user=plain_user', 'plaintext password verifier supports SM3 storage');
$node->connect_ok('user=sha_user', 'SHA256 authentication remains supported');
$node->connect_ok('user=md5_user', 'MD5 authentication remains supported');
for my $role ('sm3_missing', 'null_user', 'empty_user', 'sha_as_sm3', 'sm3_as_sha', 'sm3_as_md5')
{
	$node->connect_fails("user=$role", "$role fails with a generic password error",
		expected_stderr => qr/password authentication failed/);
}
{
	local $ENV{PGPASSWORD} = 'wrong';
	$node->connect_fails('user=sm3_user', 'wrong SM3 password fails',
		expected_stderr => qr/password authentication failed/);
}

# Incompatible bootstrap families fail before creating a partial cluster.
for my $legacy ('md5', 'scram-sha-256')
{
	for my $local_sm3 (0, 1)
	{
		my $datadir = "$tempdir/conflict_${legacy}_${local_sm3}";
		command_fails_like(
			[ 'initdb', '-D', $datadir,
			  '--auth-local', $local_sm3 ? 'scram-sm3' : $legacy,
			  '--auth-host', $local_sm3 ? $legacy : 'scram-sm3',
			  '--pwfile', $pwfile ],
			qr/scram-sm3 cannot be combined/,
			"initdb rejects mixed SM3 and $legacy (local SM3=$local_sm3)");
		ok(!-e $datadir, 'conflicting initdb does not create a data directory');
	}
}

$node->stop;
done_testing();
