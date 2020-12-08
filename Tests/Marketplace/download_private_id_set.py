import os
import json
import argparse
from google.cloud import storage
from Tests.Marketplace.marketplace_services import init_storage_client, GCPConfig


STORAGE_BUCKET_NAME = 'marketplace-dist-private-test'
STORAGE_ID_SET_PATH = 'content/id_set.json'
ARTIFACTS_PATH = '/home/circleci/project/artifacts/'


def download_private_id_set_from_gcp(public_storage_bucket):

    # file_path = "creds.json"
    # json_content = json.loads(os.environ.get('GCS_ARTIFACTS_KEY'))
    # with open(file_path, "w") as file:
    #     json.dump(json_content, file)
    # os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = file_path
    # storage_client = storage.Client()
    #
    # storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)

    index_blob = public_storage_bucket.blob(STORAGE_ID_SET_PATH)

    if not os.path.exists(ARTIFACTS_PATH):
        os.mkdir(ARTIFACTS_PATH)
    index_blob.download_to_filename(f'{ARTIFACTS_PATH}/private_id_set.json')

    if os.path.exists(f'{ARTIFACTS_PATH}/private_id_set.json'):
        return f'{ARTIFACTS_PATH}/private_id_set.json'

    return 'bla bla'


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-b', '--public_bucket_name', help="CI public bucket name", required=True)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)

    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    upload_config = option_handler()
    service_account = upload_config.service_account
    storage_client = init_storage_client(service_account)
    public_bucket_name = upload_config.public_bucket_name
    public_storage_bucket = storage_client.bucket(public_bucket_name)
    private_id_set = download_private_id_set_from_gcp(public_storage_bucket)
    return private_id_set


if __name__ == '__main__':
    main()
