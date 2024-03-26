#! /bin/bash
# Script that locks cloud machines for testing.
# We lock one machine for each job. The lock identifier contains $CI_JOB_ID.
# We release the lock after the job ends. Other jobs check that the job's status that locking the machine is not `running`.
# If there is a lock for some machine, and its job status is not running, the lock is removed.
# If we want to lock specific machine, set $LOCK_MACHINE_NAME=requested_machine_to_lock variable.

#=================================
#   Main Execution Point
#==================================
set -e

touch CloudEnvVariables

# Filter out not enabled and unnecessary machines
if [ -n "${CLOUD_SERVERS_FILE}" ]; then
  CLOUD_SERVERS_PATH=$(cat "${CLOUD_SERVERS_FILE}")
  echo "CLOUD_SERVERS_PATH is set to: ${CLOUD_SERVERS_PATH}"
else
  echo "CLOUD_SERVERS_FILE is not set, exiting"
  exit 1
fi

TEST_MACHINES_LIST=$(jq --arg flow_type "$1" 'to_entries | map(select(.value.enabled == true and .value.flow_type == $flow_type)) | from_entries' "$CLOUD_SERVERS_PATH")

# Get the number of existing machines
NUM_OF_TEST_MACHINES=$(echo "$TEST_MACHINES_LIST" | jq 'length')
export NUM_OF_TEST_MACHINES
echo "requested flow type is: $1, Number of available machines is: $NUM_OF_TEST_MACHINES, Number of machines to lock is: ${CLOUD_MACHINES_COUNT}"

# Print all available machines
TEST_MACHINES_LIST_STRING=$(echo "$TEST_MACHINES_LIST" | jq -r 'keys | join(",")')
echo "All existing machines: $TEST_MACHINES_LIST_STRING"

if [[ -z $TEST_MACHINES_LIST_STRING ]]; then
  echo "No machines in Test Machines List."
  exit 1
fi

if [[ $TEST_MACHINES_LIST_STRING != *"$LOCK_MACHINE_NAME"* ]]; then
  echo "Machine that you're trying to lock: '$LOCK_MACHINE_NAME' does not exist in Test Machines List."
  exit 1
fi

if [[ "${NUM_OF_TEST_MACHINES}" -eq 0 ]]; then
  echo "No machines are available for testing."
  exit 1
fi

if [[ -z "${CLOUD_MACHINES_COUNT}" ]]; then
  echo "Number of machines to lock is not set."
  exit 1
fi

if [[ "${CLOUD_MACHINES_COUNT}" == "all" ]]; then
  echo "Got request to lock all available machines, locking: ${NUM_OF_TEST_MACHINES} machines"
  CLOUD_MACHINES_COUNT="${NUM_OF_TEST_MACHINES}"
fi

if [[ "${CLOUD_MACHINES_COUNT}" -gt "${NUM_OF_TEST_MACHINES}" ]]; then
  echo "Number of machines to lock is greater than the number of available machines."
  exit 1
fi

echo -e "Locking machine by job_id: ${CI_JOB_ID} and pipeline_id ${CI_PIPELINE_ID}"
echo -e "We have ${NUM_OF_TEST_MACHINES} machines for testing and a lot more builds to test"
echo -e "If we want to make sure our product stays amazing, we will have to work together and keep an orderly queue"
echo -e "May the tests be in our favour. Good luck to us all"

python3 ./Tests/scripts/lock_cloud_machines.py --service_account $GCS_ARTIFACTS_KEY --gcs_locks_path $GCS_LOCKS_PATH  --ci_job_id $CI_JOB_ID  --ci_pipeline_id $CI_PIPELINE_ID --test_machines $TEST_MACHINES_LIST_STRING  --gitlab_status_token $GITLAB_STATUS_TOKEN --lock_machine_name "${LOCK_MACHINE_NAME}" --number_machines_to_lock ${CLOUD_MACHINES_COUNT} --response_machine CloudEnvVariables
