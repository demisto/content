#!/bin/bash

echo "Starting flake8 run"
flake8

if [[ $? -ne 0 ]]
  then
    echo "Please fix the aforementioned errors and then commit again"
    exit 1
fi

echo "Finished flake8 run"