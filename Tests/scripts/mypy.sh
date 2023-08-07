#!/bin/bash

# ignored_messages_file contains patterns of mypy messages we want to ignore

errors=0

echo "Starting mypy run"

for dir in $*; do
  # if dir is PWD or no python files in the directory, skip
  if [[ $dir == "." || $(find $dir -name "*.py" | wc -l) -eq 0 ]]; then
    continue
  fi
  mypy_out=$(python3 -m mypy $dir 2>&1)
  if [[ $? -ne 0 && $? -ne 2 ]]; then

    echo "$mypy_out"
    if [[ $? -eq 0 ]]; then
      errors=1 # some errors founded by grep
    fi

  fi
done

if [[ $errors -ne 0 ]]; then
  echo "*** Finished mypy run, please fix the above errors ***"
  exit 1
fi

echo "Finished mypy run - no errors were found"

