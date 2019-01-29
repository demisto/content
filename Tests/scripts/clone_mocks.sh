#!/usr/bin/env bash
eval `ssh-agent -s` & ssh-add $1 & git clone git@github.com:demisto/content-test-data.git
