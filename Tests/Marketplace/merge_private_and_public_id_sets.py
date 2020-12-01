import os
import argparse
from Tests.Marketplace.marketplace_services import init_storage_client


STORAGE_BUCKET_NAME = 'marketplace-dist-private-test'
STORAGE_ID_SET_PATH = 'content/id_set.json'
ARTIFACTS_PATH = '/home/circleci/project/artifacts/'


def option_handler():
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    return parser.parse_args()


def download_private_id_set_from_gcp():
    """Save the zip file from the feature branch into artifacts folder.

    Returns:
        The new path of the zip file.
    """

    upload_config = option_handler()
    service_account = upload_config.service_account
    storage_client = init_storage_client(service_account)

    storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)

    index_blob = storage_bucket.blob(STORAGE_ID_SET_PATH)

    if not os.path.exists(ARTIFACTS_PATH):
        os.mkdir(ARTIFACTS_PATH)
    index_blob.download_to_filename(f'{ARTIFACTS_PATH}/private_id_set.json')

    if os.path.exists(f'{ARTIFACTS_PATH}/private_id_set.json'):
        return f'{ARTIFACTS_PATH}/private_id_set.json'

    return ''


def main():
    private_id_set = download_private_id_set_from_gcp()
    return private_id_set


if __name__ == '__main__':
    main()
