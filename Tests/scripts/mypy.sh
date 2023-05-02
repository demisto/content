#!/bin/bash

# ignored_messages_file contains patterns of mypy messages we want to ignore
ignored_messages_file="./Tests/scripts/.mypy_ignored_messages"

errors=0

echo "Starting mypy run"

for dir in $*; do
  if [[ $dir == "." ]]; then
    continue
  fi
  # check if there are python files in the directory 
  if [[ $(find $dir -name "*.py" -maxdepth 1 | wc -l) -eq 0 ]]; then
    continue
  fi
  echo "Running mypy on $dir"
  mypy_out=$(python3 -m mypy $dir 2>&1)
  if [[ $? -ne 0 && $? -ne 2 ]]; then
    echo -e "$mypy_out" | sort | uniq | grep -v -f $ignored_messages_file
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

