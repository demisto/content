#!/bin/bash


# Run flake8 pylint and mypy on all non-Packs. Packs are handled in pre-commit.
errors=0
all_dirs=$(find . -type d -not \( -path "*cache*" -o -path "./.*" -o -path "./Templates*" -o -path "./TestPlaybooks*" -o -path "./node_modules*" -o -path "./venv*" -o -path "./Packs*" -o -path "./artifacts*" -o -path "*infrastructure_tests*" -o -path "*scripts/awsinstancetool*" -o -path "./docs*" \))
all_1_depth_dirs=$(find . -maxdepth 1 -type d -not \( -path "*cache*" -o -path . -o -path ./Packs -o -path ./venv -o -path ./Templates -o -path ./TestPlaybooks -o -path ./node_modules -o -path "./artifacts*" -o -path "./.*" -o -path ./docs \))

echo -e "Top level folders to scan (used by ruff):\n${all_1_depth_dirs}\n"
echo -e "Folders to be used for lint scan (used by pylint and mypy):\n${all_dirs}\n"

./.circleci/mypy.sh $all_1_depth_dirs || errors=$?
python3 -m ruff $all_1_depth_dirs --select=E,F,PLC,PLE --ignore=PLC1901 || errors=$?


echo 'analyze non-packs files exit code:' $errors
if [[ $errors -ne 0 ]]; then
  exit 1
fi
