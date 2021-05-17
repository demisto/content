import os
import json
import argparse
from Tests.Marketplace.marketplace_services import init_storage_client


def create_empty_id_set_in_artifacts(private_id_set_path):
    empty_id_set = {
        "scripts": [],
        "playbooks": [],
        "integrations": [],
        "TestPlaybooks": [],
        "Classifiers": [],
        "Dashboards": [],
        "IncidentFields": [],
        "IncidentTypes": [],
        "IndicatorFields": [],
        "IndicatorTypes": [],
        "Layouts": [],
        "Reports": [],
        "Widgets": [],
        "Mappers": []
    }
    with open(private_id_set_path, 'w') as id_set:
        json.dump(empty_id_set, id_set)


def id_set_file_exists_in_bucket(public_storage_bucket, storage_id_set_path):
    blob = public_storage_bucket.blob(storage_id_set_path)
    return blob.exists()


def download_private_id_set_from_gcp(public_storage_bucket):
    """Downloads private ID set file from cloud storage.

    Args:
        public_storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where private_id_set.json
        is stored.
    Returns:
        str: private ID set file full path.
    """

    storage_id_set_path = 'content/private_id_set.json'
    private_artifacts_path = '/home/runner/work/content-private/content-private/content/artifacts'
    private_id_set_path = private_artifacts_path + '/private_id_set.json'

    if not os.path.exists(private_artifacts_path):
        os.mkdir(private_artifacts_path)

    is_private_id_set_file_exist = id_set_file_exists_in_bucket(public_storage_bucket, storage_id_set_path)

    if is_private_id_set_file_exist:
        index_blob = public_storage_bucket.blob(storage_id_set_path)
        index_blob.download_to_filename(private_id_set_path)

    else:
        create_empty_id_set_in_artifacts(private_id_set_path)

    return private_id_set_path if os.path.exists(private_id_set_path) else ''


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
    options = option_handler()
    service_account = options.service_account
    storage_client = init_storage_client(service_account)
    public_bucket_name = options.public_bucket_name
    public_storage_bucket = storage_client.bucket(public_bucket_name)
    private_id_set = download_private_id_set_from_gcp(public_storage_bucket)
    return private_id_set


if __name__ == '__main__':
    main()
