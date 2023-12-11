#!/bin/bash
pwd
ls -la
# ./darwin -p 9980 &pid=$!
echo "running darwin on pid: $pid"
sleep 5
netstat -p tcp -l -n | grep 9980
kill $pid
echo "killed darwin on pid: $pid"