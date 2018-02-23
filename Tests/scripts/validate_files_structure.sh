#!/bin/bash

### this script ensure all files starts/ends with the right prefix/suffix
### and validate files by schema

foundWrongName=false

# ensures all files in dir starting/ending with prefix/suffix
# if schema file path provided - validate all files in dir match the schema file
validateFilesStructure() {
    dir="$1"
    prefix="$2"
    suffix="$3"
    validate_schema_file="$4"

    echo "Starting validate $dir..."
     # iterate all files in dir
    for entry in $dir/*
    do
        if [ -d $entry ]
        then continue
        fi

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
        if ! [ -z "$validate_schema_file" ]
        then
            python Tests/validate_schema.py "$dir/$filename" "Tests/schemas/$validate_schema_file.yml"
            if [[ $? -ne 0 ]]
            then
                # python script validate_schema will log error details
                foundMissingField=true
            fi
        fi
    done

    echo "Finished validate $dir"
}

validateFilesStructure Integrations integration- .yml integration
validateFilesStructure Playbooks playbook- .yml playbook
# validateFilesStructure Reports report- .json report
validateFilesStructure Scripts script- .yml script
validateFilesStructure Misc reputations .json
validateFilesStructure Widgets widget- .json widget
validateFilesStructure Dashboards dashboard- .json dashboard

if [ "$foundWrongName" = true ] || [ "$foundMissingField" = true ]
then
    echo "validate_files_structure.sh exiting with error"
    exit 1
fi

