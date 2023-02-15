#! /bin/bash
# Script that locks cloud machines for testing.
# We lock one machine for each job. The lock identifier contains $CI_JOB_ID.
# We release the lock after the job ends. Other jobs check that the job's status that locking the machine is not `running`.
# If there is a lock for some machine, and its job status is not running, the lock is removed.
# If we want to lock specific machine, set $LOCK_MACHINE_NAME=requested_machine_to_lock variable.
# If we want to lock the machine for the entire pipeline(build) and not only for one job, set the $LOCK_BY_PIPELINE_ID variable.
# (I am just checking that this var is not empty during the script).
# Other jobs will check that the pipeline is still running, and not only if the job is running.

#=================================
#   Consts
#==================================

export LOCK_IDENTIFIER=lock
export ALLOWED_STATES=running
export JOBS_STATUS_API=https://code.pan.run/api/v4/projects/2596/jobs   # disable-secrets-detection # check jobs in content repo
export PIPELINE_STATUS_API=https://code.pan.run/api/v4/projects/3734/pipelines  # disable-secrets-detection # check pipelines in content-test-conf repo
export SELF_LOCK_PATTERN=*-$LOCK_IDENTIFIER-$CI_JOB_ID

#=================================
#   Variables
#==================================

export START=$SECONDS
export QUEUE_FILE_PATH=$GCS_LOCKS_PATH/$GCS_QUEUE_FILE
export QUEUE_LOCK_PATTERN=$GCS_QUEUE_FILE-$LOCK_IDENTIFIER-*
export QUEUE_SELF_LOCK=$GCS_QUEUE_FILE-$LOCK_IDENTIFIER-$CI_JOB_ID

#=================================
#   Main Execution Point
#==================================

touch queue
touch ChosenMachine
touch CloudEnvVariables

# copy TestMachines locally for faster perf
gsutil cp $GCS_LOCKS_PATH/$TEST_MACHINES_LIST $TEST_MACHINES_LIST	# copy file from bucket. 3 machines names.
export NUM_OF_TEST_MACHINES=`sed -n '$=' $TEST_MACHINES_LIST`	# reads num of lines in file (this is the num of machines)

TEST_MACHINES_LIST_STRING=`cat $TEST_MACHINES_LIST`
echo "All existing machines: $TEST_MACHINES_LIST_STRING"

if [ -z $TEST_MACHINES_LIST_STRING ];
then
  echo "No machines in Test Machines List."
  exit 1
fi

if [[ $TEST_MACHINES_LIST_STRING != *"$LOCK_MACHINE_NAME"* ]];
then
  echo "Machine that you trying to lock: '$LOCK_MACHINE_NAME' is not exist in Test Machines List."
  exit 1
fi

if ! [ -z $LOCK_BY_PIPELINE_ID ]; then
  echo "Locking machine by pipeline_id: $CI_PIPELINE_ID, *$LOCK_BY_PIPELINE_ID*"
else
  echo "Locking machine by job_id: $CI_JOB_ID, *$LOCK_BY_PIPELINE_ID*"
fi

echo -e "We have $NUM_OF_TEST_MACHINES machines for testing and a lot more builds to test"
echo -e "If we want to make sure our product stays amazing, we will have to work together and keep an orderly queue"
echo -e "May the tests be in our favour. Good luck to us all"

python3 ./Tests/scripts/utils/lock_cloud_machines.py --service_account $GCS_ARTIFACTS_KEY --gcs_locks_path $GCS_LOCKS_PATH  --ci_job_id $CI_JOB_ID  --test_machines_list $TEST_MACHINES_LIST_STRING  --gitlab_status_token $GITLAB_STATUS_TOKEN > CLOUD_CHOSEN_MACHINE_ID

# export vars to file
echo -e "export CLOUD_CHOSEN_MACHINE_ID=$CLOUD_CHOSEN_MACHINE_ID" >>  CloudEnvVariables

