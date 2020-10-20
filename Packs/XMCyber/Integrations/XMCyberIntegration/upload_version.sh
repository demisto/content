#!/usr/bin/env bash
rm integration-XMCyberIntegration.yml
demisto-sdk unify -i .
demisto-sdk upload -i integration-XMCyberIntegration.yml --insecure
