#!/bin/bash

echo "Starting flake8 run"
python3 -m flake8 $* || EXIT_CODE="1"
if [[ $EXIT_CODE -ne 0 ]]
then
  echo "*** Please fix the errors according to the python version you are using ***"
else
  echo "Finished flake8 run - no errors were found"
fi
