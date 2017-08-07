### this script ensure all files starts/ends with the right prefix/suffix

foundWrongName=false

# ensures all files in dir starting/ending with prefix/suffix
ensureFilename() {
    dir="$1"
    prefix="$2"
    suffix="$3"

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
    done
}

ensureFilename Integrations integration- .yml
ensureFilename Playbooks playbook- .yml
ensureFilename Reports report- .json
ensureFilename Scripts script- .yml
ensureFilename Scripts script- .yml
ensureFilename Misc reputations .json
ensureFilename TestPlaybooks playbook- .yml

if [ "$foundWrongName" = true ]
then
    echo "ensurefilenames.sh exiting with error"
    exit 1
fi

