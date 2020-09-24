import zipfile as z
import requests
import os
import json
from google.cloud import storage
import argparse
import shutil

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

ACCEPT_TYPE = 'application/json'
CONTENT_API_WORKFLOWS_URI = 'https://circleci.com/api/v2/insights/gh/demisto/content/workflows/commit'
ARTIFACTS_PATH = '/home/circleci/project/artifacts/'
STORAGE_BUCKET_NAME = 'xsoar-ci-artifacts'
CIRCLE_STATUS_TOKEN = os.environ.get('CIRCLECI_STATUS_TOKEN', '')
FILES_TO_REMOVE = ['content-descriptor.json', 'doc-CommonServer.json', 'doc-howto.json', 'reputations.json',
                   'tools-o365.zip', 'tools-exchange.zip', 'tools-winpmem.zip']
CONTENT_ZIP_PATH = f'{ARTIFACTS_PATH}/content_new.zip'
ORIGINAL_CONTENT_ZIP_PATH = f'{ARTIFACTS_PATH}/original_content_new.zip'


def http_request(method, url, params=None):

    r = requests.request(
        method=method,
        url=url,
        auth=(CIRCLE_STATUS_TOKEN, ''),
        verify=False,
        params=params,
        headers={
            'Content-Type': ACCEPT_TYPE
        },
    )
    if r.status_code not in {200, 201}:
        try:
            error = r.json().get('error')
            msg = error['message'] if 'message' in error else r.reason
            print('Error in API call[%d] - %s' % (r.status_code, msg))
        except ValueError:
            msg = r.text if r.text else r.reason
            print('Error in API call [%d] - %s' % (r.status_code, msg))
    try:
        return r.json()
    except ValueError:
        return {}


def get_recent_workflows_data_request(feature_branch_name):
    """Retrieves the last 10 successful builds for the given branch.

    Args:
        feature_branch_name (str): Feature branch name

    Returns:
        list. List of last 10 successful builds.
    """
    cmd_url = f"{CONTENT_API_WORKFLOWS_URI}?branch={feature_branch_name}"
    params = {'limit': 20}
    response = http_request('GET', cmd_url, params=params)
    return response


def get_last_successful_workflow(feature_branch_name):
    """Retrieves the last successful build number of the given branch.

    Args:
        feature_branch_name (str): Name of the feature branch

    Returns:
        Last successful build number of the given branch
    """
    recent_workflows = get_recent_workflows_data_request(feature_branch_name).get('items')
    for workflow in recent_workflows:
        if workflow.get('status') == "success":
            return workflow.get('id')


def get_workflow_jobs_request(workflow_id):
    """Retrieves the workflow jobs.

    Args:
        workflow_id (str):  ID of the workflow

    Returns:
        str.
    """
    cmd_url = f"https://circleci.com/api/v2/workflow/{workflow_id}/job"
    response = http_request('GET', cmd_url)
    return response


def get_job_num(workflow_id):
    """Retrieves the create instances stage job number.

    Args:
        workflow_id (str): ID of the workflow

    Returns:
        Create instances stage job number of the given branch
    """

    jobs_data = get_workflow_jobs_request(workflow_id)['items']
    for job in jobs_data:
        if job['name'] == 'Create Instances':
            return job['job_number']
    return ''


def download_zip_file_from_gcp(current_feature_content_zip_file_path, zip_destination_path):
    """Save the content_new.zip file from the feature branch into artifacts folder.

    Args:
        current_feature_content_zip_file_path (str): Content_new.zip file path in google cloud.
        zip_destination_path: The folder path to download the content_new.zip file to.

    Returns:
        The new path of the content_new.zip file.
    """

    file_path = "creds.json"
    json_content = json.loads(os.environ.get('GCS_ARTIFACTS_KEY'))
    with open(file_path, "w") as file:
        json.dump(json_content, file)
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = file_path
    storage_client = storage.Client()

    storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)

    index_blob = storage_bucket.blob(current_feature_content_zip_file_path)
    os.remove(file_path)
    if not os.path.exists(zip_destination_path):
        os.mkdir(zip_destination_path)
    index_blob.download_to_filename(f'{zip_destination_path}/content_new.zip')

    if os.path.exists(f'{zip_destination_path}/content_new.zip'):
        return f'{zip_destination_path}/content_new.zip'

    return ''


def merge_zip_files(feature_branch_content_zip_file_path):
    """Merge content_new zip files and remove the unnecessary files.

    Args:
        feature_branch_content_zip_file_path: Feature content_new.zip file path

    """
    os.rename(CONTENT_ZIP_PATH, ORIGINAL_CONTENT_ZIP_PATH)
    unified_zip = z.ZipFile(CONTENT_ZIP_PATH, 'a', z.ZIP_DEFLATED)
    with z.ZipFile(ORIGINAL_CONTENT_ZIP_PATH, 'r') as master_zip:
        feature_zip = z.ZipFile(feature_branch_content_zip_file_path, 'r')
        for name in feature_zip.namelist():
            if name not in FILES_TO_REMOVE:
                unified_zip.writestr(name, feature_zip.open(name).read())
        for name in master_zip.namelist():
            unified_zip.writestr(name, master_zip.open(name).read())

    master_zip.close()
    feature_zip.close()


def get_new_feature_zip_file_path(feature_branch_name, job_num):
    """Merge content_new zip files and remove the unnecessary files.

    Args:
        feature_branch_name (str): The name of the feature branch.
        job_num (str): Last successful create instance job of the feature branch.

    """
    current_feature_content_zip_file_path = f'content/{feature_branch_name}/{job_num}/0/content_new.zip'
    zip_destination_path = f'{ARTIFACTS_PATH}feature_content_new_zip'
    new_feature_content_zip_file_path = download_zip_file_from_gcp(current_feature_content_zip_file_path,
                                                                   zip_destination_path)
    return new_feature_content_zip_file_path, zip_destination_path


def remove_directory(dir_path):
    shutil.rmtree(dir_path, ignore_errors=True)


def option_handler():
    parser = argparse.ArgumentParser(description='Merging two content_new.zip files from different builds.')
    parser.add_argument('-f', '--feature_branch', help='The name of the feature branch', required=True)

    options = parser.parse_args()

    return options


def main():
    options = option_handler()
    feature_branch_name = options.feature_branch

    feature_branch_successful_workflow_id = get_last_successful_workflow(feature_branch_name)
    if not feature_branch_successful_workflow_id:
        print("Couldn't find successful workflow for this branch")

    create_instances_job_num = get_job_num(feature_branch_successful_workflow_id)
    new_feature_content_zip_file_path, zip_destination_path = \
        get_new_feature_zip_file_path(feature_branch_name, create_instances_job_num)

    if new_feature_content_zip_file_path:
        merge_zip_files(new_feature_content_zip_file_path)
        remove_directory(zip_destination_path)

        print('Done merging content_new.zip files')
    else:
        print(f'Failed to download content_new.zip from feature branch {feature_branch_name}')


if __name__ == "__main__":
    main()
