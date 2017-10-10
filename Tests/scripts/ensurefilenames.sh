#!/bin/bash

### this script ensure all files starts/ends with the right prefix/suffix

foundWrongName=false

# ensures all files in dir starting/ending with prefix/suffix
ensureFilename() {
    dir="$1"
    prefix="$2"
    suffix="$3"
    validate_file="$4"

     # iterate all files in dir
    for entry in $dir/*
    do
        filename=$(basename $entry)
        if ! [[ $filename == $prefix* ]]
        then
        	echo "file $dir/$filename should start with $prefix"
        	foundWrongName=true
        fi

        if ! [[ $filename == *$suffix ]]
        then
        	echo "file $dir/$filename should end with $suffix"
        	foundWrongName=true
        fi
        if ! [ -z "$validate_file" ] && ! [ "$done" = true ]
        then
            python Tests/validate_schema.py "$dir/$filename" "Tests/schemas/$validate_file.yml" d
            if [[ $? -ne 0 ]]
            then
                # done=true
                echo "################### STOP"
                foundMissingField=true
            fi
        fi
    done
}

echo "start ensureFilenames"
ensureFilename Integrations integration- .yml "integration"
ensureFilename Playbooks playbook- .yml "playbook"
ensureFilename Reports report- .json
ensureFilename Scripts script- .yml "script"
ensureFilename Misc reputations .json

if [ "$foundWrongName" = true ] || [ "$foundMissingField" = true ]
then
    echo "ensurefilenames.sh exiting with error"
    exit 1
fi

