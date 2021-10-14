#!/bin/bash


# Run flake8 pylint and mypy on all excluding Packs, (Integraions and Scripts) - they will be handled in linting
errors=0

all_py_files=`find . -path "./*.py" -a -not \( -path "./.*" -o -path "./node_modules*" -o -path "./venv*" -o -path "*test_data*" -o -path "./Packs*" -o -path "*scripts/awsinstancetool*" \) | xargs`
all_dir=`find . -type d -not \( -path "./.*" -o -path "./Templates*" -o -path "./node_modules*" -o -path "./venv*" -o -path "*test_data*" -o -path "./Packs*" -o -path "*scripts/awsinstancetool*" \) | xargs`

for dir in $all_dir; do
    ./Tests/scripts/pymypy.sh $dir || errors=$?
  done

#echo "Run pylint"
#python -m pylint --disable=C0301,C0116,R0801 $all_dir || errors=$?

# run flake8
#./Tests/scripts/pyflake.sh $all_py_files || errors=$?

echo 'Linter exit code:' $errors
if [[ $errors -eq 0 ]]; then
  exit 0
else
  exit 1
fi
