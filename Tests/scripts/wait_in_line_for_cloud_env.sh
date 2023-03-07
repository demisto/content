#! /bin/bash
# Script that locks cloud machines for testing.
# We lock one machine for each job. The lock identifier contains $CI_JOB_ID.
# We release the lock after the job ends. Other jobs check that the job's status that locking the machine is not `running`.
# If there is a lock for some machine, and its job status is not running, the lock is removed.
# If we want to lock specific machine, set $LOCK_MACHINE_NAME=requested_machine_to_lock variable.

#=================================
#   Main Execution Point
#==================================

touch CloudEnvVariables

gsutil cp gs://xsoar-ci-artifacts/$GCS_LOCKS_PATH/$TEST_MACHINES_LIST $TEST_MACHINES_LIST # copy TestMachines locally for faster perf
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
  echo "Machine that you trying to lock: '$LOCK_MACHINE_NAME' does not exist in Test Machines List.."
  exit 1
fi

echo -e "Locking machine by job_id: $CI_JOB_ID"
echo -e "We have $NUM_OF_TEST_MACHINES machines for testing and a lot more builds to test"
echo -e "If we want to make sure our product stays amazing, we will have to work together and keep an orderly queue"
echo -e "May the tests be in our favour. Good luck to us all"

python3 ./Tests/scripts/lock_cloud_machines.py --service_account $GCS_ARTIFACTS_KEY --gcs_locks_path $GCS_LOCKS_PATH  --ci_job_id $CI_JOB_ID  --test_machines_path "test-machines-ga"  --gitlab_status_token $GITLAB_STATUS_TOKEN --lock_machine_name "$LOCK_MACHINE_NAME" --number_machines_to_lock 1 --response_machine CloudEnvVariables
