#!/bin/bash

set -e

echo "Fixing permissions"

sudo chown -R demisto /workspaces
sudo chown -R demisto $HOME

echo "Setting up VSCode paths"

cp .devcontainer/settings.json .vscode/settings.json 
touch CommonServerUserPython.py
touch DemistoClassApiModule.py
path=$(printf '%s:' Packs/ApiModules/Scripts/*)
rm -f .env
echo "PYTHONPATH=""$path"":$PYTHONPATH" >> .env
echo "MYPYPATH=""$path"":$MYPYPATH" >> .env

echo "Setting up git safe directory"
git config --global --add safe.directory /workspaces/content

echo "Setting up content dependencies"
.hooks/bootstrap

echo "Run demisto-sdk pre-commit to cache dependencies
poetry run demisto-sdk pre-commit > /dev/null 2>&1 || true