import os
import json
from google.cloud import storage


STORAGE_BUCKET_NAME = 'marketplace-dist-private'
STORAGE_ID_SET_PATH = 'content/id_set.json'
ARTIFACTS_PATH = '/home/circleci/project/artifacts/'


def download_private_id_set_from_gcp():

    file_path = "creds.json"
    json_content = json.loads(os.environ.get('GCS_ARTIFACTS_KEY'))
    with open(file_path, "w") as file:
        json.dump(json_content, file)
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = file_path
    storage_client = storage.Client()

    storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)

    index_blob = storage_bucket.blob(STORAGE_ID_SET_PATH)

    if not os.path.exists(ARTIFACTS_PATH):
        os.mkdir(ARTIFACTS_PATH)
    index_blob.download_to_filename(f'{ARTIFACTS_PATH}/private_id_set.json')

    if os.path.exists(f'{ARTIFACTS_PATH}/private_id_set.json'):
        return f'{ARTIFACTS_PATH}/private_id_set.json'

    return 'bla bla'


def main():
    private_id_set = download_private_id_set_from_gcp()
    return private_id_set


if __name__ == '__main__':
    main()
