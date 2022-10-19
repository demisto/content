#!/bin/bash

sudo chown demisto .venv
sudo chown demisto node_modules
sudo chwon demisto $HOME

cp .devcontainer/settings.json .vscode/settings.json 
touch CommonServerUserPython.py
path=$(printf '%s:' Packs/ApiModules/Scripts/*)
rm -f .env
echo "PYTHONPATH=""$path"":$PYTHONPATH" >> .env
echo "MYPYPATH=""$path"":$MYPYPATH" >> .env
NO_HOOKS=1 .hooks/bootstrap