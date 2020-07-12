import zipfile as z
import requests
import os
from google.cloud import storage
import google.auth
import warnings
import argparse

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

ACCEPT_TYPE = "Accept: application/json"
CONTENT_API_URI = "https://circleci.com/api/v1/project/demisto/content"
ARTIFACTS_PATH = '/home/circleci/project/artifacts/'
STORAGE_BUCKET_NAME = 'xsoar-ci-artifacts'


def init_storage_client(service_account=None):
    """Initialize google cloud storage client.

    In case of local dev usage the client will be initialized with user default credentials.
    Otherwise, client will be initialized from service account json that is stored in CirlceCI.

    Args:
        service_account (str): full path to service account json.

    Return:
        storage.Client: initialized google cloud storage client.
    """
    if service_account:
        storage_client = storage.Client.from_service_account_json(service_account)
        print("Created gcp service account")

        return storage_client
    else:
        # in case of local dev use, ignored the warning of non use of service account.
        warnings.filterwarnings("ignore", message=google.auth._default._CLOUD_SDK_CREDENTIALS_WARNING)
        credentials, project = google.auth.default()
        storage_client = storage.Client(credentials=credentials, project=project)
        print("Created gcp private account")

        return storage_client


def http_request(method, url_suffix, params=None):
    full_url = CONTENT_API_URI + url_suffix

    r = requests.request(
        method=method,
        url=full_url,
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


def get_recent_builds_data_request(feature_branch_name):
    """Retrieves the last 10 successful builds for the given branch.

    Args:
        feature_branch_name (str): Feature branch name

    Returns:
        list. List of last 10 successful builds.
    """
    cmd_url = f"/tree/{feature_branch_name}"
    params = {'limit': 10, 'filter': 'successful'}
    response = http_request('GET', cmd_url, params=params)
    return response


def get_last_successful_build_num(feature_branch_name):
    """Retrieves the last successful build number of the given branch.

    Args:
        feature_branch_name (str): Name of the feature branch

    Returns:
        Last successful build number of the given branch
    """
    recent_successful_builds = get_recent_builds_data_request(feature_branch_name)
    last_successful_build_num = recent_successful_builds[0]['build_num']
    return last_successful_build_num


def download_zip_file_from_gcp(current_feature_content_zip_file_path, zip_destination_path,
                               gcp_service_account=None):
    """Save the content_new.zip file from the feature branch into artifacts folder.

    Args:
        current_feature_content_zip_file_path (str): Content_new.zip file path in google cloud.
        zip_destination_path: The folder path to download the content_new.zip file to.
        gcp_service_account: Full path to service account json.

    Returns:
        The new path of the content_new.zip file.
    """
    storage_client = init_storage_client(gcp_service_account)
    storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)

    index_blob = storage_bucket.blob(current_feature_content_zip_file_path)

    if not os.path.exists(zip_destination_path):
        os.mkdir(zip_destination_path)
    index_blob.download_to_filename(zip_destination_path)

    if os.path.exists(f'{zip_destination_path}/content_new.zip'):
        return f'{zip_destination_path}/content_new.zip'

    return ''


def merge_zip_files(master_branch_content_zip_file_path, feature_branch_content_zip_file_path, files_to_remove):
    """Merge content_new zip files and remove the unnecessary files.

    Args:
        master_branch_content_zip_file_path (str): Master content_new.zip file path
        feature_branch_content_zip_file_path: Feature content_new.zip file path
        files_to_remove (list): The list of the file to remove from the feature branch's content_new.zip

    """

    feature_branch_content_dir = z.ZipFile(feature_branch_content_zip_file_path, 'r')
    master_content_zip = z.ZipFile(master_branch_content_zip_file_path, 'w')
    extract_dir = f'{ARTIFACTS_PATH}/feature_content_new_dir'
    feature_branch_content_dir.extractall(extract_dir)
    feature_content_zip_files = os.listdir(extract_dir)

    for file_name in feature_content_zip_files:
        if file_name not in files_to_remove:
            master_content_zip.write(f'{extract_dir}/{file_name}')
    master_content_zip.close()
    feature_branch_content_dir.close()


def get_new_feature_zip_file_path(feature_branch_name, build_num, gcp_service_account):
    """Merge content_new zip files and remove the unnecessary files.

    Args:
        feature_branch_name (str): The name of the feature branch.
        build_num (str): Last successful build number of the feature branch.
        gcp_service_account: Full path to service account json.

    """
    current_feature_content_zip_file_path = f'/content/{feature_branch_name}/{build_num}/0/content_new.zip'
    zip_destination_path = f'{ARTIFACTS_PATH}/feature_content_new_zip'
    new_feature_content_zip_file_path = download_zip_file_from_gcp(current_feature_content_zip_file_path,
                                                                   zip_destination_path, gcp_service_account)
    return new_feature_content_zip_file_path


def option_handler():
    parser = argparse.ArgumentParser(description='Merging two content_new.zip files from different builds.')
    parser.add_argument('-f', '--feature_branch', help='The name of the feature branch', required=True)
    parser.add_argument('-g', '--gcp', help='full path to service account json', required=False)
    parser.add_argument('-v', '--version', help='The version which was entered in content creator. for example 4_1',
                        required=True)

    options = parser.parse_args()

    return options


def main():
    options = option_handler()
    feature_branch_name = options.feature_branch
    gcp_service_account = options.gcp
    version = options.version

    build_num = get_last_successful_build_num(feature_branch_name)
    if not build_num:
        print("Couldn't find successful build in this branch")

    new_feature_content_zip_file_path = get_new_feature_zip_file_path(feature_branch_name, build_num,
                                                                      gcp_service_account)

    files_to_remove = [f'content-descriptor_{version}.json', f'doc-CommonServer_{version}.json',
                       f'doc-howto_{version}.json', f'reputations_{version}.json']

    master_content_zip_path = f"{ARTIFACTS_PATH}/content_new.zip"

    if new_feature_content_zip_file_path:
        merge_zip_files(master_content_zip_path, new_feature_content_zip_file_path, files_to_remove)
        print('Done merging content_new.zip files')
    else:
        print(f'Failed to download content_new.zip from feature branch {feature_branch_name}')


if __name__ == "__main__":
    main()
