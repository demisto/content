#! /bin/bash

#=================================
#   Consts
#==================================

export GCS_LOCKS_PATH=gs://xsoar-ci-artifacts/content-locks-xsiam
export LOCK_IDENTIFIER=lock
export ALLOWED_STATES=running
export BUILD_STATUS_API=https://code.pan.run/api/v4/projects/2596/jobs   # disable-secrets-detection
export SELF_LOCK_PATTERN=*-$LOCK_IDENTIFIER-$CI_JOB_ID

#=================================
#   Variables
#==================================

export START=$SECONDS
export QUEUE_FILE_PATH=$GCS_LOCKS_PATH/$GCS_QUEUE_FILE
export QUEUE_LOCK_PATTERN=$GCS_QUEUE_FILE-$LOCK_IDENTIFIER-*
export QUEUE_SELF_LOCK=$GCS_QUEUE_FILE-$LOCK_IDENTIFIER-$CI_JOB_ID

#=================================
#   Functions & helpers
#==================================

function get_build_job_statuses() {
	export BUILD_STATUSES=`echo $1 | tr ' ' '\n' | xargs -I {} curl --header "PRIVATE-TOKEN: $GITLAB_STATUS_TOKEN" $BUILD_STATUS_API/{} -s | jq -c '. | .status' | sed 's/"//g' | tr ' ' '\n' | sort | uniq`
}

function is_status_exists() {
	export EXISTS=`echo $1 $2 | tr ' ' '\n' | sort | uniq -d`
}

function create_lock() {
	touch $QUEUE_SELF_LOCK
	gsutil -m cp $QUEUE_SELF_LOCK $GCS_LOCKS_PATH/$QUEUE_SELF_LOCK
}

function lock_queue() {
	while true
	do
		# get all queue locks
		echo "Getting queue existing locks"
    export QUEUE_LOCK_BUILDS=`gsutil -m ls $GCS_LOCKS_PATH/$QUEUE_LOCK_PATTERN 2> /dev/null | sed 's/.*-'$LOCK_IDENTIFIER'-//'`
		if [ ! -z "$QUEUE_LOCK_BUILDS" ]
		then
			echo -e "The following jobs have locks for queue: \n$QUEUE_LOCK_BUILDS"
			get_build_job_statuses "$QUEUE_LOCK_BUILDS"
  		is_status_exists "$BUILD_STATUSES" "$ALLOWED_STATES"
			if [ -z "$EXISTS" ]
			then
			  # no one is working on the queue file - lock it
			  echo "No active locks found. Locking the queue"
				create_lock
				break
			fi
		else
		  # no one is working on the queue file - lock it
		  echo "No active locks found. Locking the queue"
			create_lock
			break
		fi
		sleep 5
	done
}

function release_queue() {
  if [[ "$LOCK_CHANGED" == "true" ]]
  then
    gsutil cp queue $QUEUE_FILE_PATH
  fi
	gsutil rm $GCS_LOCKS_PATH/$QUEUE_SELF_LOCK
}

function get_number_in_line() {
	export NUMBER_IN_LINE=`cat $1 2> /dev/null | grep -n $CI_JOB_ID | cut -d: -f1`
}

function register_in_line() {
	echo $CI_JOB_ID >> $1
	export LOCK_CHANGED="true"
}

function get_previous_line() {
	export PREVIOUS_BUILD=`sed -n $(($1-1))p $2`
}

function remove_previous_line() {
	sed -i -e $(($1-1))d $2
	export LOCK_CHANGED="true"
}

function handle_previous_builds() {
  get_previous_line "$1" "$2"
  get_build_job_statuses "$PREVIOUS_BUILD"

  is_status_exists "$BUILD_STATUSES" "$ALLOWED_STATES"
  if [ -z $EXISTS ]
  then
    #remove previous line and continue
  	echo -e "The job in place $(($1 - 1)) went stale. Removing it from queue"
  	remove_previous_line "$1" "$2"
  fi
}

function get_build_locks() {
  export BUILDS=`gsutil -m ls $GCS_LOCKS_PATH/$MACHINE_LOCK_PATTERN 2> /dev/null | sed 's/.*-'$LOCK_IDENTIFIER'-//'`
}

function lock_machine() {
        echo "Locking $TEST_MACHINE for testing"
    	  export MACHINE_LOCK_FILE=$TEST_MACHINE-$LOCK_IDENTIFIER-$CI_JOB_ID
    		touch $MACHINE_LOCK_FILE
    		gsutil -m cp $MACHINE_LOCK_FILE $GCS_LOCKS_PATH/$MACHINE_LOCK_FILE
    		echo $TEST_MACHINE > ChosenMachine
}

function poll_for_env() {
  export START=$SECONDS
  # this line remove all existing lock files, even if they runs. CLEAN_XSIAM_LOCKS - gitlab variable
  if [ ! -z $CLEAN_XSIAM_LOCKS ]; then gsutil -m rm "$GCS_LOCKS_PATH/*-$LOCK_IDENTIFIER-*"; fi

  # remove old self locks - this will ensure that in case of retries we won't interfere with other builds or lock a machine out of use
  gsutil -m rm "$GCS_LOCKS_PATH/$SELF_LOCK_PATTERN" 2> /dev/null

  while true;
  do
	# for each machine in machine list do:
	 cat $TEST_MACHINES_LIST | while read TEST_MACHINE; do
    export MACHINE_LOCK_PATTERN=$TEST_MACHINE-$LOCK_IDENTIFIER-*	# {machine_name}-lock-*
    # Get all lock files from GCS and extract their build number
    echo "Getting Build locks for $TEST_MACHINE"
    get_build_locks # lists all files that looks like: MACHINE_LOCK_PATTERN, return arg: BUILDS (id of builds)
		if [ ! -z "$BUILDS" ]	# if BUILDS not empty
		then
		  echo -e "The following jobs have locks for $TEST_MACHINE: \n$BUILDS"
		  # This checks all jobs statuses and eliminates duplicates (we don't care which job has what status, we just need one)
		  get_build_job_statuses "$BUILDS"
      echo -e "Job statuses found are: \n $BUILD_STATUSES"

      # We don't want to interfere with running jobs. The rest are ok
      is_status_exists "$BUILD_STATUSES" "$ALLOWED_STATES"	# ALLOWED_STATES == blocking states, that we cant run if such states exists
      if [ ! -z "$EXISTS" ]
      then
        echo "Environment $TEST_MACHINE in use. Trying another..."
      else
    	  lock_machine	# create lock file, writes ChosenMachine file
      	break
      fi
    else
		  echo "No locks were found for $TEST_MACHINE"
		  lock_machine
		  break
		fi
  done

    # Next step test - if we found a machine, carry on. If not, keep polling...
    # Addition to the test - if we surpassed polling time - fail the script
    export TEST_MACHINE=`cat ChosenMachine`
	  if [ ! -z "$TEST_MACHINE" ]	# machine found!!!!!
	  then
		  break
	  else
	    echo "nothing is free. going to sleep"
	    DURATION=$(( SECONDS - START))
	    if [ $DURATION -ge 7200 ]
	    then
  	    echo "Reached timeout after $DURATION seconds. Giving up"
  	    exit 1
  	  fi
  		sleep 150 #wait two and a half minutes before polling again
  	fi
  done
}

#=================================
#   Main Execution Point
#==================================

touch queue
touch ChosenMachine
touch XSIAMEnvVariables

# copy TestMachines locally for faster perf
gsutil cp $GCS_LOCKS_PATH/$TEST_MACHINES_LIST $TEST_MACHINES_LIST	# copy file from bucket. 3 machines names.
export NUM_OF_TEST_MACHINES=`sed -n '$=' $TEST_MACHINES_LIST`	# reads num of lines in file (this is the num of machines)

echo -e "We have $NUM_OF_TEST_MACHINES machines for testing and a lot more builds to test"
echo -e "If we want to make sure our product stays amazing, we will have to work together and keep an orderly queue"
echo -e "May the tests be in our favour. Good luck to us all"

while true
do
	lock_queue	# locking the queue (it is the file, in the bucket, all builds (waiting and running) listed in line )
  export LOCK_CHANGED="false"
	#copy queue to local for faster performance
	gsutil cp $GCS_LOCKS_PATH/$GCS_QUEUE_FILE queue	# copy locally for better performance
	get_number_in_line queue	# checks if curr build num in the line? returns NUMBER_IN_LINE arg
	# line number smaller then 1 means we have not registered yet
	if [[ "$NUMBER_IN_LINE" -lt 1 ]]	# if not exist
	then
		# register at the end of the line (writes build number in this file at the end)
	  echo -e "We are new in line. Taking a number"
		register_in_line queue
		get_number_in_line queue
	fi

	# prev functions updates NUMBER_IN_LINE arg
	echo -e "Our number in line is $NUMBER_IN_LINE"

  # previous build might have stopped. in that case let's kick it out (Curr build responsible to kick out dead builds)
	if [[ "$NUMBER_IN_LINE" -gt $(($NUM_OF_TEST_MACHINES + 1)) ]] # if I am in line and not the next who should be served (my num is 5+)
	then
    handle_previous_builds "$NUMBER_IN_LINE" queue	# Only need to check if build before me still alive, if no remove it from line.
  fi

  # we are next in line for polling! let's see if anyone has finished
  if [[ "$NUMBER_IN_LINE" -eq $(($NUM_OF_TEST_MACHINES + 1)) ]] # build num 4 have the most responsibility because he is the next to run
  then
    # loop starts from 2 because handle_previous_builds func checks one build before the $i argument we provide to it.
    # So when we provide i=2,3,4 the function handles builds that number 1,2,3 in line.
    for ((i=2;i<=NUM_OF_TEST_MACHINES + 1;i++))
    do
      handle_previous_builds "$i" queue	# checks if builds num 1,2,3 still alive, if no removes them from line.
    done
  fi

	# If curr build in one of $NUM_OF_TEST_MACHINES first places:
	if [[ "$NUMBER_IN_LINE" -le $NUM_OF_TEST_MACHINES ]]
	then
		# there should be free env waiting for us. let's find out which.
		echo "Polling for available testing environments"
		release_queue	# writes the lines file to gcp
		poll_for_env	#	finds free machine
		break
	fi

  release_queue

	#polling phase
	export DURATION=$(( SECONDS - START))
	if [ $DURATION -ge 7200 ]	# 7200 sec timeout for this polling
	then
		echo "Reached timeout after $DURATION seconds. Giving up"
	    	exit 1	# error
	else
		sleep 10 # wait ten seconds before polling again
	fi
done

export XSIAM_CHOSEN_MACHINE_ID=`cat ChosenMachine`	# ChosenMachine it is the file with free machine. machine name will be written there.
# export vars to file
echo -e "export XSIAM_CHOSEN_MACHINE_ID=$XSIAM_CHOSEN_MACHINE_ID" >>  XSIAMEnvVariables

