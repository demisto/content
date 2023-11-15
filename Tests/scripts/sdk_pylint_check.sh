#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}Checking for Demisto SDK related Pylint errors${NC}"

pylint_tests_result="$(python3 -m pylint --errors-only ./Tests | grep demisto_sdk)"
pylint_utils_result="$(python3 -m pylint --errors-only ./Utils | grep demisto_sdk)"

if [ -n "${pylint_tests_result}" ] || [ -n "$pylint_utils_result" ]; then
    if [ -n "${pylint_tests_result}" ]; then
        echo -e "${RED}ERROR: Found Pylint result on Tests directory: ${pylint_tests_result}${NC}"
    else
        echo -e "${GREEN}No Pylint result on Tests directory${NC}"
    fi
    if [ -n "$pylint_utils_result" ]; then
        echo -e "${RED}ERROR: Found Pylint result on Utils directory: ${pylint_utils_result}${NC}"
    else
        echo -e "${GREEN}No Pylint result on Utils directory${NC}"
    fi
    exit 1
fi

echo -e "${GREEN}No SDK related Pylint errors${NC}"
exit 0

