#!/bin/bash

pylint_disabled_errors=C0103,C0114,C0115,C0116,C0122,C0301,C0302,C0325,C0411,C0412,C0413,C0415,E1136,E1205,F0001,F0010,R0201,R0205,R0401,R0801,R0902,R0903,R0904,R0912,R0913,R0914,R0915,R1702,R1705,R1710,R1721,R1725,W0105,W0150,W0212,W0401,W0404,W0511,W0603,W0612,W0613,W0621,W0622,W0703,W1202,W1203
echo "Starting pylint run"

for dir in $*; do
    pylint_out=$(python3 -m pylint --disable=$pylint_disabled_errors 2>&1 $dir/*.py)
    if [[ $? -ne 0 ]]; then
      echo -e "$pylint_out" | sort | uniq | grep ": [A-Z][0-9]*: "
      if [[ $? -eq 0 ]]; then
        errors=1 # some errors founded by grep
      fi
    fi
done

if [[ $errors -ne 0 ]]; then
  echo "*** Finished pylint run, please fix the above errors ***"
  exit 1
fi


echo "Finished pylint run - no errors were found"
