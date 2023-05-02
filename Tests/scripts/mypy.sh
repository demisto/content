#!/bin/bash
errors=0

echo "Starting mypy run"

for dir in $*; do
    errors=$(python3 -m mypy $dir 2>&1)
done

if [[ $errors -ne 0 ]]; then
  echo "*** Finished mypy run, please fix the above errors ***"
  exit 1
fi

echo "Finished mypy run - no errors were found"

