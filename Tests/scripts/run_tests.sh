#!/usr/bin/env bash

SECRET_CONF_PATH=$(cat secret_conf_path)
CONF_PATH="./Tests/conf.json"

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false
[ -n "${MEM_CHECK}" ] && MEM_CHECK=true || MEM_CHECK=false
[ -z "${NON_AMI_RUN}" ] && IS_AMI_RUN=true || IS_AMI_RUN=false

PREVIOUS_JOB_NUMBER=`cat create_instances_build_num.txt`

echo 'export GOOGLE_APPLICATION_CREDENTIALS="creds.json"' >> $BASH_ENV
source $BASH_ENV
cat <<EOF > "$GOOGLE_APPLICATION_CREDENTIALS"
$GCS_ARTIFACTS_KEY
EOF

python3 Tests/test_content_v2.py -k "$DEMISTO_API_KEY" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CIRCLE_BUILD_NUM" -g "$CIRCLE_BRANCH" -m "$MEM_CHECK" --isAMI $IS_AMI_RUN -d "$1"

RETVAL=$?
rm $GOOGLE_APPLICATION_CREDENTIALS

if [ $RETVAL -eq 0 ]; then
  role="$(echo -e "$1" | tr -d '[:space:]')"
  filepath="./Tests/is_build_passed_${role}.txt"
  touch "$filepath"
fi

exit $RETVAL
