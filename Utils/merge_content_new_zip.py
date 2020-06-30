import zipfile as z
import sys
import requests
import os
from google.cloud import storage
import google.auth
import warnings
# disable insecure warnings
requests.packages.urllib3.disable_warnings()


ACCEPT_TYPE = "Accept: application/json"
CONTENT_API_URI = "https://circleci.com/api/v1/project/demisto/content"
FILES_TO_REMOVE_LIST = ['content-descriptor.json', 'doc-CommonServer.json', 'doc-howto.json']
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


def download_zip_file_from_gc(current_feature_content_zip_file_path, extract_destination_path):
    """Save the content_new.zip file from the feature branch into artifacts folder.

    Args:
        gc_service_account: full path to service account json.
        current_feature_content_zip_file_path (str): Content_new.zip file path in google cloud.
        extract_destination_path: The folder path to download the content_new.zip file to.

    Returns:
        The new path of the content_new.zip file.
    """
    storage_client = init_storage_client()
    storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)

    index_blob = storage_bucket.blob(current_feature_content_zip_file_path)

    if not os.path.exists(extract_destination_path):
        os.mkdir(extract_destination_path)
    index_blob.download_to_filename(extract_destination_path)

    if os.path.exists(f'{extract_destination_path}/content_new.zip'):
        return f'{extract_destination_path}/content_new.zip'

    return ''


def merge_zip_files(master_branch_content_zip_file_path, feature_branch_content_zip_file_path):
    """Merge content_new zip files and remove the unnecessary files.

    Args:
        master_branch_content_zip_file_path (str): Content_new.zip file path
        feature_branch_content_zip_file_path:

    """

    feature_branch_content_dir = z.ZipFile(feature_branch_content_zip_file_path, 'r')
    master_content_zip = z.ZipFile(master_branch_content_zip_file_path, 'w')
    feature_branch_content_dir.extractall(feature_branch_content_zip_file_path)
    feature_content_zip_files = os.listdir(feature_branch_content_zip_file_path)

    for file_name in feature_content_zip_files:
        if file_name not in FILES_TO_REMOVE_LIST:
            master_content_zip.write(f'{feature_branch_content_dir}/{file_name}')
    master_content_zip.close()


def main(argv):
    if len(argv) < 2:
        print("")
        sys.exit(1)
    feature_branch_name = argv[0]
    master_content_new_zip_path = argv[1]
    if len(argv) == 3:
        gc_service_account = argv[2]
    build_num = get_last_successful_build_num(feature_branch_name)
    if not build_num:
        print("Couldn't find successful build in this branch")
    current_feature_content_zip_file_path = f'/content/{feature_branch_name}/{build_num}/0/content_new.zip'
    extract_destination_path = f'{ARTIFACTS_PATH}/feature_content_new_zip'
    new_feature_content_zip_file_path = download_zip_file_from_gc(current_feature_content_zip_file_path, extract_destination_path)
    if new_feature_content_zip_file_path:
        merge_zip_files(master_content_new_zip_path, new_feature_content_zip_file_path)
    else:
        print('error')


if __name__ == "__main__":
    main(sys.argv[1:])

