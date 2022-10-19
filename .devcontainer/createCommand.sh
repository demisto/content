#!/bin/bash

set -e

echo "Fixing permissions"

sudo chown demisto .venv
sudo chown demisto node_modules
sudo chown -R demisto $HOME
sudo chown -R demisto /workspaces

echo "Setting up git certificate"

sudo git config --system http.sslCAInfo /usr/local/share/ca-certificates/certs.crt

echo "Setting up VSCode paths"

cp .devcontainer/settings.json .vscode/settings.json 
touch CommonServerUserPython.py
path=$(printf '%s:' Packs/ApiModules/Scripts/*)
rm -f .env
echo "PYTHONPATH=""$path"":$PYTHONPATH" >> .env
echo "MYPYPATH=""$path"":$MYPYPATH" >> .env

echo "Setting up content dependencies"

NO_HOOKS=1 .hooks/bootstrap