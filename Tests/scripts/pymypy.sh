#!/bin/bash

# build the unskipped mypy errors pattern from the mypy_ignore_errors file
unskipped_pattern=`awk '!/^$|^#/ {line=line sep $0; sep="|"}END{print "!/"line"|^$/"}' < ./Tests/scripts/.mypy_ignore_errors`

echo "Starting mypy run on: " $*
errors=0
mypy_out=$(python3 -m mypy $* --show-error-codes 2>&1)
mypy_status=$?
if [[ $mypy_status -eq 2 ]]; then
    echo -e "$mypy_out"
    exit 0
fi

if [[ $mypy_status -ne 0 ]]; then
  echo -e "$mypy_out" | sort | uniq | awk "$unskipped_pattern"
fi

echo "Finished mypy run"
