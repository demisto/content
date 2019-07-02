#!/bin/bash

echo "Starting flake8 run"
errors=0

flake8_out=$(python -m flake8 $* 2>&1)
if [[ $? -ne 0 ]]
  then
    # perform second pass with python3
    for f in `echo "$flake8_out" | awk -F ':' '{print $1}' | sort | uniq `; do
      flake8_py3_out=$(python3 -m flake8 $f)
      if [[ $? -ne 0 ]]; then # python3 failed
        errors=1
        echo "Failed flake8 for: $f"
        echo "python2 output:"
        echo `echo "$flake8_out" | grep $f`
        echo "python3 output:"
        echo "$flake8_py3_out"
        echo "*** Please fix the errors according to the python version you are using"
      fi
    done
fi

if [[ $errors -ne 0 ]]; then   
  exit 1
fi

echo "Finished flake8 run"