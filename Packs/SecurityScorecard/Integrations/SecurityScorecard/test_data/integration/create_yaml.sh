#!/bin/bash

export DEMISTO_BASE_URL=https://10.180.188.128
export DEMISTO_API_KEY=EE81DF1F870DE84DE50CAB3C1C6CBEE5

rm integration-integration.yml
demisto-sdk unify -i .
demisto-sdk upload -i integration-integration.yml --insecure --verbose
