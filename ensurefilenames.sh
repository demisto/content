# ensure integration
for entry in Integrations/*
do
    filename=$(basename $entry)
    #echo "$filename"
    if ! [[ $filename == integration-* ]]
    then
    	echo "found"
    fi
done

# ensure playbooks
for entry in Playbooks/*
do
    filename=$(basename $entry)
    #echo "$filename"
    if ! [[ $filename == playbook-* ]]
    then
    	echo "found"
    fi
done

# ensure reports
for entry in Reports/*
do
    filename=$(basename $entry)
    #echo "$filename"
    if ! [[ $filename == report-* ]]
    then
    	echo "found"
    fi
done

# ensure scripts
for entry in Scripts/*
do
    filename=$(basename $entry)
    #echo "$filename"
    if ! [[ $filename == scripts-* ]]
    then
    	echo "found"
    fi
done