#!/bin/bash
# PQC Key Generator - SLHDSA256s + MLKEM1024_X448
# Wrapper script for easy key generation

cd "$(dirname "$0")"

cargo run -p sequoia-openpgp \
  --example pqc_keygen \
  --no-default-features \
  --features crypto-openssl,compression \
  -- "$@"
