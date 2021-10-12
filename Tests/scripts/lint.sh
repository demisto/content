#!/usr/bin/env bash


# Run flake8 and mypy on all excluding Packs (Integraions and Scripts) - they will be handled in linting

./Tests/scripts/pymypy.sh *.py
for dir in `find . -maxdepth 1 -type d -not \( -path . -o -path ./Packs -o -path ./venv \) | xargs`; do
  ./Tests/scripts/pymypy.sh $dir
  done

#./Tests/scripts/pyflake.sh *.py
#find . -maxdepth 1 -type d -not \( -path . -o -path ./Packs -o -path ./venv \) | xargs ./Tests/scripts/pyflake.sh
#
#
#
./Tests/scripts/pyflake.sh *.py
./Tests/scripts/pyflake.sh ./Tests/*.py
./Tests/scripts/pyflake.sh ./Tests/scripts/*.py
find . -maxdepth 1 -type d -not \( -path . -o -path ./Packs -o -path ./venv -o -path ./Tests \) | xargs ./Tests/scripts/pyflake.sh
find ./Tests -maxdepth 1 -type d -not \( -path ./Tests -o -path ./Tests/scripts \) | xargs ./Tests/scripts/pyflake.sh
find ./Tests/scripts -maxdepth 1 -type d -not \( -path ./Tests/scripts -o -path ./Tests/scripts/awsinstancetool \) | xargs ./Tests/scripts/pyflake.sh
