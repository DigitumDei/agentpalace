#!/bin/sh
set -eu
umask 077
mkdir -p /var/lib/agentpalace/config /var/lib/agentpalace/palace /var/lib/agentpalace-tokens
if [ ! -e /var/lib/agentpalace-tokens/tokens.json ]; then
    printf '[]\n' > /var/lib/agentpalace-tokens/tokens.json
fi
exec agentpalace serve --bind 0.0.0.0:8765 --token-file /var/lib/agentpalace-tokens/tokens.json