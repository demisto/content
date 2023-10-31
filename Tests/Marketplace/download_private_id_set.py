import os
import json
import argparse
from pathlib import Path

from Tests.Marketplace.marketplace_services import init_storage_client


def create_empty_id_set_in_artifacts(private_id_set_path):
    empty_id_set: dict = {
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


def download_private_id_set_from_gcp(public_storage_bucket, storage_base_path):
    """Downloads private ID set file from cloud storage.

    Args:
        public_storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where private_id_set.json
        is stored.
        storage_base_path (str): The storage base path of the bucket.
    Returns:
        str: private ID set file full path.
    """

    storage_id_set_path = os.path.join(storage_base_path, 'content/private_id_set.json') if storage_base_path else \
        'content/private_id_set.json'
    private_artifacts_server_type_path = '/home/runner/work/content-private/content-private/content/artifacts/server_type_XSOAR'
    private_id_set_path = f'{private_artifacts_server_type_path}/private_id_set.json'
    if os.path.exists(private_artifacts_server_type_path):
        print(f'Directory: {private_artifacts_server_type_path} already exists.')  # noqa: T201
    else:
        print(f'Creating directory: {private_artifacts_server_type_path}')  # noqa: T201
        Path(private_artifacts_server_type_path).mkdir(parents=True, exist_ok=True)

    is_private_id_set_file_exist = id_set_file_exists_in_bucket(public_storage_bucket, storage_id_set_path)

    if is_private_id_set_file_exist:
        print(f'Downloading private_id_set from:{storage_id_set_path} to: {private_id_set_path}')  # noqa: T201
        index_blob = public_storage_bucket.blob(storage_id_set_path)
        index_blob.download_to_filename(private_id_set_path)

    else:
        print(f'Private id set file does not exist in bucket: {public_storage_bucket.name}.')  # noqa: T201
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
    parser.add_argument('-sb', '--storage_base_path', help="Storage base path of the bucket.",
                        required=False)

    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    options = option_handler()
    service_account = options.service_account
    storage_client = init_storage_client(service_account)
    storage_base_path = options.storage_base_path
    public_bucket_name = options.public_bucket_name
    public_storage_bucket = storage_client.bucket(public_bucket_name)
    private_id_set = download_private_id_set_from_gcp(public_storage_bucket, storage_base_path)
    return private_id_set


if __name__ == '__main__':
    main()
