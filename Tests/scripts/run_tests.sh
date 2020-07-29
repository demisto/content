#!/usr/bin/env bash

echo "start content tests"

SECRET_CONF_PATH=$(cat secret_conf_path)
CONF_PATH="./Tests/conf.json"
DEMISTO_API_KEY=$(cat $SECRET_CONF_PATH | jq '.temp_apikey')

temp="${DEMISTO_API_KEY%\"}"
temp="${temp#\"}"
DEMISTO_API_KEY=$temp

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false

code_1=0
code_2=0

echo "starting configure_and_test_integration_instances"
PREVIOUS_JOB_NUMBER=`cat create_instances_build_num.txt`

python3 ./Tests/configure_and_test_integration_instances.py -u "$USERNAME" -p "$PASSWORD" -c "$CONF_PATH" -s "$SECRET_CONF_PATH" -g "$GIT_SHA1" --ami_env "$1" -n $IS_NIGHTLY --branch "$CIRCLE_BRANCH" --build-number "$PREVIOUS_JOB_NUMBER"
code_1=$?

echo 'export GOOGLE_APPLICATION_CREDENTIALS="creds.json"' >> $BASH_ENV
source $BASH_ENV
cat <<EOF > "$GOOGLE_APPLICATION_CREDENTIALS"
$GCS_ARTIFACTS_KEY
EOF

if [ $code_1 -ne 1 ] ; then
  if [ -n "${NON_AMI_RUN}" ]; then
    # non AMI
    python3 ./Tests/test_content.py -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CIRCLE_BUILD_NUM" -g "$CIRCLE_BRANCH" -m "$MEM_CHECK" -d "$1"
  else
    # AMI
    python3 ./Tests/test_content.py -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CIRCLE_BUILD_NUM" -g "$CIRCLE_BRANCH" -m "$MEM_CHECK" --isAMI true -d "$1"
  fi
fi

code_2=$?
let "exit_code = $code_1 + $code_2"
rm $GOOGLE_APPLICATION_CREDENTIALS

exit $exit_code
