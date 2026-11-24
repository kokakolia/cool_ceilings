#!/bin/sh
set -eu

mkdir -p /etc/rabbitmq/tls
cert_dir=$(readlink -f /run/server-tls/active)
cp "$cert_dir/cert.pem" /etc/rabbitmq/tls/cert.pem
cp "$cert_dir/key.pem" /etc/rabbitmq/tls/key.pem
cp /run/secrets/rabbit_definitions /etc/rabbitmq/definitions.json
cp /infra/rabbitmq/rabbitmq.conf /etc/rabbitmq/rabbitmq.conf
printf '[].\n' > /etc/rabbitmq/enabled_plugins
chown -R rabbitmq:rabbitmq /etc/rabbitmq
chmod 600 /etc/rabbitmq/tls/key.pem /etc/rabbitmq/definitions.json

exec /usr/local/bin/docker-entrypoint.sh rabbitmq-server
