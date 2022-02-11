#!/bin/bash


# Run flake8 pylint and mypy on all excluding Packs, (Integraions and Scripts) - they will be handled in linting
errors=0
all_dirs=$(find . -type d -not \( -path "./.*" -o -path "./Templates*" -o -path "./TestPlaybooks*" -o -path "./node_modules*" -o -path "./venv*" -o -path "./Packs*" -o -path "*infrastructure_tests*" -o -path "*scripts/awsinstancetool*" -o -path "./docs*" \))
all_1_depth_dirs=$(find . -maxdepth 1 -type d -not \( -path . -o -path ./Packs -o -path ./venv -o -path ./Templates -o -path ./TestPlaybooks -o -path ./node_modules -o -path "./.*" -o -path ./docs \))

echo -e "Top level folders to scan (used by flake8):\n${all_1_depth_dirs}\n"
echo -e "Folders to be used for lint scan (used by pylint and mypy):\n${all_dirs}\n"

# run mypy
./Tests/scripts/mypy.sh $all_dirs || errors=$?

# run pylint
./Tests/scripts/pylint.sh $all_dirs || errors=$?

# run flake8
./Tests/scripts/pyflake.sh *.py || errors=$?
./Tests/scripts/pyflake.sh $all_1_depth_dirs || errors=$?


echo 'Linter exit code:' $errors
if [[ $errors -ne 0 ]]; then
  exit 1
fi
