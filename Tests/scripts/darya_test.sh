export BUILD_STATUS_API=https://code.pan.run/api/v4/projects/2596/jobs   # disable-secrets-detection


function get_build_job_statuses() {
	export BUILD_STATUSES=`echo $1 | tr ' ' '\n' | xargs -I {} curl --header "PRIVATE-TOKEN: $GITLAB_STATUS_TOKEN" $BUILD_STATUS_API/{} -s | jq -c '. | .status' | sed 's/"//g' | tr ' ' '\n' | sort | uniq`
}

BUILDS="$( echo -e '12248062\n12248066\n12248063' )"
echo "$BUILDS"
get_build_job_statuses "$BUILDS"
echo -e "Build statuses found are: \n $BUILD_STATUSES"


curl --header "PRIVATE-TOKEN: $GITLAB_STATUS_TOKEN" $BUILD_STATUS_API/12248062

#12248063 # cancelled
#12248066 # failed
#12248062 #done

#echo "Build id: $CI_BUILD_ID"
#echo "Pipline id: $CI_PIPELINE_ID"
#echo "Job id: $CI_JOB_ID"
#
#echo "Job finished, removing lock file"
#gcloud auth activate-service-account --key-file="$GCS_ARTIFACTS_KEY" > auth.out 2>&1
#gsutil rm "gs://xsoar-ci-artifacts/content-locks-xsiam/*-lock-*"

#echo "export GOOGLE_APPLICATION_CREDENTIALS=$GCS_ARTIFACTS_KEY" >> $BASH_ENV
#source $BASH_ENV
#python3 ./Tests/gcp.py

echo "Finished!!"