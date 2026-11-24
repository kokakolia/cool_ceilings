#!/bin/sh
set -eu

mkdir -p /run/postgres-tls
cert_dir=$(readlink -f /run/server-tls/active)
cp "$cert_dir/cert.pem" /run/postgres-tls/cert.pem
cp "$cert_dir/key.pem" /run/postgres-tls/key.pem
chown -R postgres:postgres /run/postgres-tls
chmod 600 /run/postgres-tls/key.pem

exec /usr/local/bin/docker-entrypoint.sh postgres \
    -c ssl=on \
    -c ssl_cert_file=/run/postgres-tls/cert.pem \
    -c ssl_key_file=/run/postgres-tls/key.pem \
    -c hba_file=/infra/postgres/pg_hba.conf \
    -c password_encryption=scram-sha-256
