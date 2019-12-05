#!/usr/bin/env bash

count=99
if [ $count -eq 100 ]
  then
    echo "count is 100"
  else
    if [ $count -eq 99 ]
      then
        echo "count is 89"
        exit 0
      else
        echo "countttt"
    fi
fi