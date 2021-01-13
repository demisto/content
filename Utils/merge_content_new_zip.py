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
CONTENT_API_WORKFLOWS_URI = 'https://circleci.com/api/v2/insights/gh/demisto/content/workflows'
ARTIFACTS_PATH = '/home/circleci/project/artifacts/'
STORAGE_BUCKET_NAME = 'xsoar-ci-artifacts'
CIRCLE_STATUS_TOKEN = os.environ.get('CIRCLECI_STATUS_TOKEN', '')
FILES_TO_REMOVE = ['content-descriptor.json', 'doc-CommonServer.json', 'doc-howto.json', 'reputations.json',
                   'tools-o365.zip', 'tools-exchange.zip', 'tools-winpmem.zip']
CONTENT_NEW_ZIP_PATH = f'{ARTIFACTS_PATH}/content_new.zip'
ALL_CONTENT_ZIP_PATH = f'{ARTIFACTS_PATH}/all_content.zip'

ORIGINAL_CONTENT_NEW_ZIP_PATH = f'{ARTIFACTS_PATH}/original_content_new.zip'
ORIGINAL_ALL_CONTENT_ZIP_PATH = f'{ARTIFACTS_PATH}/original_all_content.zip'


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
    print(f"sent url {cmd_url}")
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
    print(feature_branch_name)
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


def download_zip_file_from_gcp(current_feature_branch_zip_file_path, zip_destination_path, zip_name):
    """Save the zip file from the feature branch into artifacts folder.

    Args:
        current_feature_branch_zip_file_path (str): The feature branch zip file path in google cloud.
        zip_destination_path: The folder path to download the zip file to.
        zip_name: The name of the zip to download

    Returns:
        The new path of the zip file.
    """

    file_path = "creds.json"
    json_content = json.loads(os.environ.get('GCS_ARTIFACTS_KEY'))
    with open(file_path, "w") as file:
        json.dump(json_content, file)
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = file_path
    storage_client = storage.Client()

    storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)

    index_blob = storage_bucket.blob(current_feature_branch_zip_file_path)
    os.remove(file_path)
    if not os.path.exists(zip_destination_path):
        os.mkdir(zip_destination_path)
    index_blob.download_to_filename(f'{zip_destination_path}/{zip_name}.zip')

    if os.path.exists(f'{zip_destination_path}/{zip_name}.zip'):
        return f'{zip_destination_path}/{zip_name}.zip'

    return ''


def merge_zip_files(feature_branch_content_zip_file_path, artifacts_zip_path, original_zip_path):
    """Merge zip files and remove the unnecessary files.

    Args:
        feature_branch_content_zip_file_path: Feature content_new.zip file path

    """
    os.rename(artifacts_zip_path, original_zip_path)
    unified_zip = z.ZipFile(artifacts_zip_path, 'a', z.ZIP_DEFLATED)
    with z.ZipFile(original_zip_path, 'r') as master_zip:
        feature_zip = z.ZipFile(feature_branch_content_zip_file_path, 'r')
        for name in feature_zip.namelist():
            if name not in FILES_TO_REMOVE:
                unified_zip.writestr(name, feature_zip.open(name).read())
        for name in master_zip.namelist():
            unified_zip.writestr(name, master_zip.open(name).read())

    master_zip.close()
    feature_zip.close()


def get_feature_branch_zip_file_path(feature_branch_name, job_num, zip_name):
    """Get the feature branch zip file.

    Args:
        feature_branch_name (str): The name of the feature branch.
        job_num (str): Last successful create instance job of the feature branch.
        zip_name (str): The zip we want to download (all_content or content_new).

    """
    current_feature_branch_zip_file_path = f'content/{feature_branch_name}/{job_num}/0/{zip_name}.zip'
    zip_destination_path = f'{ARTIFACTS_PATH}feature_{zip_name}_zip'
    feature_zip_file_path = download_zip_file_from_gcp(current_feature_branch_zip_file_path, zip_destination_path,
                                                       zip_name)
    return feature_zip_file_path, zip_destination_path


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

    feature_branch_content_new_zip_file_path, content_new_zip_destination_path = \
        get_feature_branch_zip_file_path(feature_branch_name, create_instances_job_num, 'content_new')

    feature_branch_all_content_zip_file_path, all_content_zip_destination_path = \
        get_feature_branch_zip_file_path(feature_branch_name, create_instances_job_num, 'all_content')

    if feature_branch_content_new_zip_file_path:
        merge_zip_files(feature_branch_content_new_zip_file_path, artifacts_zip_path=CONTENT_NEW_ZIP_PATH,
                        original_zip_path=ORIGINAL_CONTENT_NEW_ZIP_PATH)
        remove_directory(content_new_zip_destination_path)
        print('Done merging content_new.zip files')
    else:
        print(f'Failed to download content_new.zip from feature branch {feature_branch_name}')

    if feature_branch_all_content_zip_file_path:
        merge_zip_files(feature_branch_all_content_zip_file_path, artifacts_zip_path=ALL_CONTENT_ZIP_PATH,
                        original_zip_path=ORIGINAL_ALL_CONTENT_ZIP_PATH)
        remove_directory(all_content_zip_destination_path)
        print('Done merging all_content.zip files')
    else:
        print(f'Failed to download all_content.zip from feature branch {feature_branch_name}')


if __name__ == "__main__":
    main()
