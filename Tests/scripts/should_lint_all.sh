#!/usr/bin/env bash

# Simple script to check if build should run all lint

if [ -n "$NIGHTLY" ]; then
    echo "NIGHTLY env var is set: $NIGHTLY"
    exit 0
fi

# all tests passed return 1
exit 1
