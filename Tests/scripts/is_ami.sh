#!/usr/bin/env bash
 if [ -n "${AMI_RUN}" ]; then exit 0 ; fi # run with AMI
 exit 1 # should with latest server build
