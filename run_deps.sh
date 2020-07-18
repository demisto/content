#!/usr/bin/env bash

demisto-sdk find-dependencies -i "./Tests/id_set.json" --include_test_data -p $1
