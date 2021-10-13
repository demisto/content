#!/bin/bash


# Run flake8 and mypy on all excluding Packs (Integraions and Scripts) - they will be handled in linting
errors=0
./Tests/scripts/pymypy.sh *.py || errors=$?
for dir in `find . -maxdepth 1 -type d -not \( -path . -o -path ./Packs -o -path ./venv \) | xargs`; do
    ./Tests/scripts/pymypy.sh $dir || errors=$?
  done

#./Tests/scripts/pyflake.sh *.py
#find . -maxdepth 1 -type d -not \( -path . -o -path ./Packs -o -path ./venv \) | xargs ./Tests/scripts/pyflake.sh
#
#
#
./Tests/scripts/pyflake.sh *.py || errors=$?
./Tests/scripts/pyflake.sh ./Tests/*.py || errors=$?
./Tests/scripts/pyflake.sh ./Tests/scripts/*.py || errors=$?
find . -maxdepth 1 -type d -not \( -path . -o -path ./Packs -o -path ./venv -o -path ./Tests \) | xargs ./Tests/scripts/pyflake.sh || errors=$?
find ./Tests -maxdepth 1 -type d -not \( -path ./Tests -o -path ./Tests/scripts \) | xargs ./Tests/scripts/pyflake.sh || errors=$?
find ./Tests/scripts -maxdepth 1 -type d -not \( -path ./Tests/scripts -o -path ./Tests/scripts/awsinstancetool \) | xargs ./Tests/scripts/pyflake.sh || errors=$?

echo 'Linter exit code:' $errors
if [[ $errors -eq 0 ]]; then
  exit 0
else
  exit 1
fi
