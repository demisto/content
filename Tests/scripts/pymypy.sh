#!/bin/bash

# build the unskipped mypy errors pattern from the mypy_ignore_errors file
unskipped_pattern=`awk '!/^$|^#/ {line=line sep $0; sep="|"}END{print "!/"line"|^$/"}' < ./Tests/scripts/.mypy_ignore_errors`

echo "Starting mypy run"
errors=0
mypy_out=$(python3 -m mypy $* --show-error-codes 2>&1)
mypy_status=$?
if [[ $mypy_status -eq 2 ]]; then
    echo -e "$mypy_out"
    exit 0
fi

#if [[ $mypy_status -ne 0 ]]
#  then
#    # perform second pass with python3
#    for f in `echo  "$mypy_out" | awk "$unskipped_pattern" | awk -F ':' '{print $1}' | sort | uniq`; do
#      echo "Run mypy on: $f"
#      mypy_py3_out=$(python3 -m mypy --show-error-codes $f)"\n$mypy_py3_out"
#      if [[ $? -ne 0 ]]; then # python3 failed
#        errors=1
#      fi
#    done
#fi

if [[ $mypy_status -ne 0 ]]; then
  output=`echo -e "$mypy_out" | sort | uniq | awk "$unskipped_pattern"`
  if [[ ! -z $output ]]; then
    echo "***mypy output:"
    echo $output
    echo "*** Please fix the errors according to the python version you are using"
    exit 1
  fi
fi

echo "Finished mypy run"