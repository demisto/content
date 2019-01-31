#!/usr/bin/env bash

ssh-keyscan github.com >> ~/.ssh/known_hosts

git clone git@github.com:demisto/content-test-data.git
