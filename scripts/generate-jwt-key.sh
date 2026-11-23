#!/usr/bin/env bash
# Gera uma chave RSA (3072 bits, PKCS#8) e imprime as variáveis de ambiente do authentication_service.
#
# Uso:   ./scripts/generate-jwt-key.sh >> ../.env
# Rotação: gere uma chave NOVA, mova a pública da antiga para JWT_PUBLIC_KEYS_B64 (ver README) e troque
#          JWT_PRIVATE_KEY_B64/JWT_KEY_ID. A chave privada NUNCA deve ser commitada nem logada.
set -euo pipefail

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$tmp" 2>/dev/null

echo "JWT_PRIVATE_KEY_B64=$(openssl base64 -A -in "$tmp")"
echo "JWT_KEY_ID=$(date +%Y-%m)-a"
echo "# chave pública correspondente (para guardar em JWT_PUBLIC_KEYS_B64 quando esta chave for aposentada):"
echo "# JWT_PUBLIC_KEY_B64=$(openssl pkey -in "$tmp" -pubout 2>/dev/null | openssl base64 -A)"
