import os
from warnings import filterwarnings
from argparse import ArgumentParser, Namespace
from google.cloud.storage import Client, Bucket
import google.auth


def init_storage_client(service_account=None) -> Client:
    """Initialize google cloud storage client.

    In case of local dev usage the client will be initialized with user default credentials.
    Otherwise, client will be initialized from service account json that is stored in CirlceCI.

    Args:
        service_account (str): full path to service account json.

    Return:
        google.cloud.storage.Client: initialized google cloud storage client.
    """
    if service_account:
        storage_client = Client.from_service_account_json(service_account)
        print("Created GCP service account successfully")

        return storage_client
    else:
        # in case of local dev use, ignored the warning of non use of service account.
        filterwarnings("ignore", message=google.auth._default._CLOUD_SDK_CREDENTIALS_WARNING)
        credentials, project = google.auth.default()
        storage_client = Client(credentials=credentials, project=project)
        print("Created GCP private account successfully")

        return storage_client


def create_sub_directory(storage_bucket: Bucket, branch_name: str, ci_build_number: str):
    sub_dir_path = os.path.join('content', 'builds', branch_name, ci_build_number, 'test')
    blob = storage_bucket.blob(sub_dir_path)
    blob.upload_from_string('', content_type='application/x-www-form-urlencoded;charset=UTF-8')
    print(f'Created sub-dir {sub_dir_path} successfully')


def option_handler() -> Namespace:
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.
    """
    parser = ArgumentParser(description="Prepare content packs for testing.")
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=True)
    parser.add_argument('-g', '--branch_name', help="GitHub branch name.", required=True)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    return parser.parse_args()


def main():
    option = option_handler()
    bucket_name = option.bucket_name
    ci_build_number = option.ci_build_number
    branch_name = option.branch_name
    service_account = option.service_account

    print("Preparing content packs for testing")

    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(bucket_name)

    create_sub_directory(storage_bucket, branch_name, ci_build_number)


if __name__ == '__main__':
    main()
