#!/bin/sh

set -e

sudo chown -R demisto /workspaces
git config --global --add safe.directory /workspaces/content

cp .devcontainer/settings.json .vscode/settings.json 
touch CommonServerUserPython.py
path=$(printf '%s:' Packs/ApiModules/Scripts/*):$PYTHONPATH
rm -rf .env
echo PYTHONPATH="$path" >> .env
echo MYPYPATH="$path" >> .env
NO_HOOKS=1 .hooks/bootstrap
