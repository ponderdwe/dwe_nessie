#!/bin/sh
set -e
rm -f /etc/nginx/conf.d/default.conf
# Substitute only ${NESSIE_TOKEN} — nginx vars like $host are left as-is
envsubst '$NESSIE_TOKEN' < /etc/nginx/templates/nessie.conf.template > /etc/nginx/conf.d/nessie.conf
nginx -t
exec nginx -g 'daemon off;'
