### this script ensure all files starts with the right prefix

foundWrongPrefix=false

# ensures all files in dir starting with prefix
ensurePrefix() {
    dir="$1"
    prefix="$2"

     # iterate all files in dir
    for entry in $dir/*
    do
        filename=$(basename $entry)
        if ! [[ $filename == $prefix* ]]
        then
        	echo "file $dir/$filename should start with $prefix"
        	foundWrongPrefix=true
        fi
    done
}

ensurePrefix Integrations integration-
ensurePrefix Playbooks playbook-
ensurePrefix Reports report-
ensurePrefix Scripts script-

if [ "$foundWrongPrefix" = true ]
then
    echo "ensurefilenames.sh exiting with error"
    exit 1
fi

