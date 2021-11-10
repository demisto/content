#!/bin/bash

# ignored_messages_file contains patterns of mypy messages we want to ignore
ignored_messages_file="./Tests/scripts/.mypy_ignored_messages"
mypy_flags="--check-untyped-defs --ignore-missing-imports --follow-imports=silent --show-column-numbers --show-error-codes --allow-redefinition --show-absolute-path --cache-dir=/dev/null"

errors=0

echo "Starting mypy run"

for dir in $*; do
    mypy_out=$(python3 -m mypy $dir/*.py $mypy_flags 2>&1)
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

