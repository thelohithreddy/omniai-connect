#!/usr/bin/env bash
# Generate a 32-byte base64 key for CREDENTIAL_ENCRYPTION_KEY / BETTER_AUTH_SECRET.
set -euo pipefail
openssl rand -base64 32
