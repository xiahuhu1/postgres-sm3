# Copyright (c) 2026, PostgreSQL Global Development Group

# Exercise native SCRAM-SM3 with libpq, including the public password APIs
# and require_auth policies that must distinguish the two SCRAM families.
use strict;
use warnings FATAL => 'all';

use IPC::Run;
use IO::Socket::INET;
use POSIX ();
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

if (!$use_unix_sockets || !check_pg_config('#define HAVE_EVP_SM3 1'))
{
	plan skip_all => 'SCRAM-SM3 requires OpenSSL and Unix-domain sockets';
}

my $node = PostgreSQL::Test::Cluster->new('sm3');
$node->init;
$node->start;
$node->safe_psql('postgres', q{
    SET password_encryption = 'scram-sm3';
    CREATE ROLE sm3_user LOGIN PASSWORD 'pass';
    CREATE ROLE reset_user LOGIN PASSWORD 'pass';
    SET password_encryption = 'scram-sha-256';
    CREATE ROLE sha_user LOGIN PASSWORD 'pass';
});

sub set_hba
{
	my ($reset_method) = @_;
	unlink($node->data_dir . '/pg_hba.conf');
	$node->append_conf('pg_hba.conf', qq{
local all sm3_user scram-sm3
local all sha_user scram-sha-256
local all reset_user $reset_method
local all all trust
});
	$node->reload;
}
set_hba('scram-sm3');

local $ENV{PGPASSWORD} = 'pass';
$node->connect_ok('user=sm3_user', 'ordinary SM3 authentication');
$node->connect_ok('user=sm3_user require_auth=scram-sm3',
	'SM3 explicitly required');
$node->connect_ok('user=sm3_user require_auth=scram-sha-256,scram-sm3',
	'both SCRAM families allowed');
$node->connect_ok('user=sm3_user require_auth=!scram-sha-256',
	'forbidding SHA256 still allows SM3');
$node->connect_fails('user=sm3_user require_auth=scram-sha-256',
	'SHA256-only policy rejects SM3',
	expected_stderr => qr/server did not offer an allowed SASL mechanism/);
$node->connect_fails('user=sm3_user require_auth=!scram-sm3',
	'negative SM3 policy rejects SM3',
	expected_stderr => qr/server did not offer an allowed SASL mechanism/);
$node->connect_fails('user=sha_user require_auth=scram-sm3',
	'SM3-only policy rejects SHA256',
	expected_stderr => qr/server did not offer an allowed SASL mechanism/);
$node->connect_ok('user=sha_user require_auth=scram-sha-256',
	'SHA256 authentication remains supported');
$node->connect_ok('user=sha_user require_auth=!scram-sm3',
	'forbidding SM3 still allows SHA256');
$node->connect_fails('user=sm3_user require_auth=!scram-sha-256,!scram-sm3',
	'both SASL families forbidden',
	expected_stderr => qr/authentication method requirement/);
$node->connect_fails('user=sm3_user require_auth=scram-sm3,scram-sm3',
	'duplicate SM3 policy rejected',
	expected_stderr => qr/method "scram-sm3" is specified more than once/);
$node->connect_fails('user=sm3_user require_auth=!scram-sm3,!scram-sm3',
	'duplicate negative SM3 policy rejected',
	expected_stderr => qr/method "!scram-sm3" is specified more than once/);
$node->connect_fails('user=sm3_user channel_binding=require',
	'ordinary SM3 cannot satisfy required channel binding',
	expected_stderr => qr/channel binding required, but SSL not in use/);
{
	local $ENV{PGPASSWORD} = 'wrong';
	$node->connect_fails('user=sm3_user', 'wrong SM3 password rejected',
		expected_stderr => qr/password authentication failed/);
}

my $conninfo = $node->connstr('postgres') . ' user=sm3_user require_auth=scram-sm3';
command_like([ 'libpq_testclient', '--sm3', $conninfo ],
	qr/explicit SM3 verifier\ndefault SM3 verifier\nSM3 password changed\nSM3 reset succeeded/,
	'password API uses SM3 and the reported iteration count');
is($node->safe_psql('postgres', q{
    SELECT rolpassword LIKE 'SCRAM-SM3$42:%'
    FROM pg_authid WHERE rolname = 'sm3_user'
}), 't', 'PQchangePassword stored an SM3 verifier');

# A successful reconnect alone would not detect a reset that accidentally
# broadened require_auth. Change the server family before reusing the PGconn.
my ($input, $output, $error) = ('', '', '');
my $timeout = IPC::Run::timeout($PostgreSQL::Test::Utils::timeout_default);
my $proc = IPC::Run::start(
	[ 'libpq_testclient', '--sm3-reset-deny',
	  $node->connstr('postgres') . ' user=reset_user require_auth=scram-sm3' ],
	'<', \$input, '>', \$output, '2>', \$error, $timeout);
ok(pump_until($proc, $timeout, \$output, qr/ready\n/),
	'reset test authenticated with SM3');
$node->safe_psql('postgres', q{
    SET password_encryption = 'scram-sha-256';
    ALTER ROLE reset_user PASSWORD 'pass';
});
set_hba('scram-sha-256');
$input = "\n";
ok($proc->finish, 'PQreset rejects a different SCRAM family');
like($output, qr/server did not offer an allowed SASL mechanism/,
	'PQreset preserves SM3-only policy');
is($error, '', 'reset policy test has no unexpected error');

# A loopback fake server exercises failures a real server will not generate.
sub read_exact
{
	my ($socket, $length) = @_;
	my $buffer = '';
	while (length($buffer) < $length)
	{
		my $count = sysread($socket, my $part, $length - length($buffer));
		die 'unexpected end of client message' unless $count;
		$buffer .= $part;
	}
	return $buffer;
}

sub send_auth
{
	my ($socket, $code, $payload) = @_;
	my $packet = 'R' . pack('NN', 8 + length($payload), $code) . $payload;
	while (length($packet))
	{
		my $count = syswrite($socket, $packet);
		die 'could not send authentication request' unless $count;
		substr($packet, 0, $count, '');
	}
}

sub fake_server_test
{
	my ($case, $expected) = @_;
	my $listener = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1', LocalPort => 0,
		Listen => 1, ReuseAddr => 1, Timeout => 10)
	  or die "could not listen: $!";
	my $port = $listener->sockport;
	my $pid = fork();
	die "could not fork: $!" unless defined($pid);
	if ($pid == 0)
	{
		my $ok = eval {
			local $SIG{ALRM} = sub { die 'fake server timeout'; };
			alarm(15);
			my $socket = $listener->accept or die "could not accept: $!";
			my $length = unpack('N', read_exact($socket, 4));
			read_exact($socket, $length - 4);    # StartupMessage
			send_auth($socket, 10, "SCRAM-SM3\0\0");
			read_exact($socket, 1);             # SASLInitialResponse type
			$length = unpack('N', read_exact($socket, 4));
			my $first = read_exact($socket, $length - 4);
			my ($nonce) = $first =~ /,r=([^,]+)$/;
			die 'no client nonce' unless defined($nonce);
			if ($case eq 'early-ok')
			{
				send_auth($socket, 0, '');
			}
			elsif ($case eq 'changed-auth')
			{
				send_auth($socket, 5, 'salt');
			}
			elsif ($case eq 'early-final')
			{
				send_auth($socket, 12, 'v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
			}
			else
			{
				my $iterations = $case eq 'overflow' ? '4294967297' : '4096';
				my $salt = $case eq 'empty-salt' ? '' : 'MDEyMzQ1Njc4OWFiY2RlZg==';
				send_auth($socket, 11,
					"r=${nonce}server,s=$salt,i=$iterations");
				if ($case ne 'overflow' && $case ne 'empty-salt')
				{
					read_exact($socket, 1);       # SASLResponse type
					$length = unpack('N', read_exact($socket, 4));
					read_exact($socket, $length - 4);
					if ($case eq 'missing-final')
					{
						send_auth($socket, 0, '');
					}
					else
					{
						send_auth($socket, 11,
							'v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
					}
				}
			}
			close($socket);
			1;
		};
		warn($@) unless $ok;
		POSIX::_exit($ok ? 0 : 1);
	}
	close($listener);
	command_fails_like(
		[ 'psql', '-X', '-d',
		  "host=127.0.0.1 port=$port dbname=postgres user=sm3_user sslmode=disable gssencmode=disable connect_timeout=5",
		  '-c', 'SELECT 1' ], $expected, "SM3 rejects $case");
	waitpid($pid, 0);
	is($?, 0, "fake server completed $case");
}

fake_server_test('early-ok', qr/server did not complete SCRAM-SM3/);
fake_server_test('missing-final', qr/server did not complete SCRAM-SM3/);
fake_server_test('changed-auth', qr/unexpected authentication request during SCRAM-SM3/);
fake_server_test('early-final', qr/unexpected message in SCRAM-SM3/);
fake_server_test('extra-continue', qr/unexpected message in SCRAM-SM3/);
fake_server_test('overflow', qr/invalid iteration count/);
fake_server_test('empty-salt', qr/invalid salt/);

done_testing();
