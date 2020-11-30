import os
import json
import argparse
from google.cloud import storage


STORAGE_BUCKET_NAME = 'marketplace-dist-private-test'
STORAGE_ID_SET_PATH = 'content/id_set.json'
ARTIFACTS_PATH = '/home/circleci/project/artifacts/'


def option_handler():
    parser = argparse.ArgumentParser(description='Merging two content_new.zip files from different builds.')
    parser.add_argument('-f', '--feature_branch', help='The name of the feature branch', required=True)

    options = parser.parse_args()

    return options


def download_private_id_set_from_gcp():
    """Save the zip file from the feature branch into artifacts folder.

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

    index_blob = storage_bucket.blob(STORAGE_ID_SET_PATH)
    os.remove(file_path)

    index_blob.download_to_filename(ARTIFACTS_PATH)

    if os.path.exists(ARTIFACTS_PATH):
        return ARTIFACTS_PATH

    return ''


def main():
    private_id_set = download_private_id_set_from_gcp()
    return private_id_set


if __name__ == '__main__':
    main()
