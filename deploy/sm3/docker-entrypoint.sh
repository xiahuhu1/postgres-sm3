#!/bin/sh
set -eu
if [ "${1:-}" != postgres ]; then
    exec "$@"
fi
if [ "$(id -u)" = 0 ]; then
    mkdir -p "$PGDATA" /var/run/postgresql
    chmod 700 "$PGDATA"
    chown postgres:postgres "$PGDATA" /var/run/postgresql
    exec gosu postgres "$0" "$@"
fi
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    if [ -z "${POSTGRES_PASSWORD_FILE:-}" ] || [ ! -s "$POSTGRES_PASSWORD_FILE" ]; then
        echo 'New clusters require a nonempty POSTGRES_PASSWORD_FILE.' >&2
        exit 1
    fi
    SM3_INITIAL_PASSWORD=''
    IFS= read -r SM3_INITIAL_PASSWORD < "$POSTGRES_PASSWORD_FILE" || true
    SM3_INITIAL_PASSWORD=$(printf '%s' "$SM3_INITIAL_PASSWORD" | tr -d '\r')
    if [ -z "$SM3_INITIAL_PASSWORD" ]; then
        echo 'The first password file line must not be empty.' >&2
        exit 1
    fi
    unset SM3_INITIAL_PASSWORD
    initdb -D "$PGDATA" --username=postgres --auth-local=peer \
        --auth-host=scram-sm3 --pwfile="$POSTGRES_PASSWORD_FILE" --encoding=UTF8
    cat >> "$PGDATA/postgresql.conf" <<'CONF'
listen_addresses = '*'
password_encryption = 'scram-sm3'
log_connections = on
log_line_prefix = '%m [%p] user=%u db=%d '
unix_socket_directories = '/var/run/postgresql'
CONF
    # initdb only creates loopback host records; remote tests also require a rule.
    printf '\nhost all all 0.0.0.0/0 scram-sm3\nhost all all ::/0 scram-sm3\n' >> "$PGDATA/pg_hba.conf"
fi
if [ "$(cat "$PGDATA/PG_VERSION")" != 17 ]; then
    echo 'This image only accepts PostgreSQL 17 data directories.' >&2
    exit 1
fi
exec "$@" -D "$PGDATA"
