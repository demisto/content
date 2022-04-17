#export BUILD_STATUS_API=https://code.pan.run/api/v4/projects/2596/jobs   # disable-secrets-detection
#
#
#function get_build_job_statuses() {
#	export BUILD_STATUSES=`echo $1 | tr ' ' '\n' | xargs -I {} curl --header "PRIVATE-TOKEN: $GITLAB_STATUS_TOKEN" $BUILD_STATUS_API/{}/jobs -s | jq -c '.[] | select(.name=="xsiam_server_master" or .name=="install-packs-in-server6_1") | .status' | sed 's/"//g' | tr ' ' '\n' | sort | uniq`
#}
#
#BUILDS="$( echo -e '2762133\n2759618' )"
#echo "$BUILDS"
#get_build_job_statuses "$BUILDS"
#echo -e "Build statuses found are: \n $BUILD_STATUSES"
#
#
##2762133 # cancelled
##2759618 # done

echo "Build id: $CI_BUILD_ID"
echo "Pipline id: $CI_PIPELINE_ID"
echo "Job id: $CI_JOB_ID"

echo "Job finished, removing lock file"
gcloud auth activate-service-account --key-file="$GCS_ARTIFACTS_KEY" > auth.out 2>&1
gsutil rm "gs://xsoar-ci-artifacts/content-locks-xsiam/*-lock-*"

echo "Finished removing lock file"