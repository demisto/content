#!/bin/bash

set -e

echo "Fixing permissions"
# get current folder name
repo=${PWD##*/}
sudo chown demisto /workspaces /workspaces/$repo
sudo chown -R demisto /workspaces/$repo/.vscode /workspaces/content/.git /workspaces/$repo/.venv /workspaces/$repo/node_modules /workspaces/$repo/package-lock.json

sudo chown -R demisto $HOME

echo "Setting up git safe directory"
git config --global --add safe.directory /workspaces/$repo

echo "Setting up content dependencies"
.hooks/bootstrap

echo "Setting up VSCode"
poetry run demisto-sdk setup-env


echo "Run demisto-sdk pre-commit to cache dependencies"
poetry run demisto-sdk pre-commit --mode=commit >/dev/null 2>&1 || true