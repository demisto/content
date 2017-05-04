# ensures all files in dir starting with prefix
ensurePrefix() {
    dir="$1"
    prefix="$2"

    for entry in $1/*
    do
        filename=$(basename $entry)
        #echo "$filename"
        if ! [[ $filename == $2* ]]
        then
        	echo "found"
        	echo "$filename"
        fi
    done
}

ensurePrefix Integrations integration-
ensurePrefix Playbooks playbook-
ensurePrefix Reports report-
ensurePrefix Scripts script-

