import os
import argparse
import logging
from Tests.Marketplace.marketplace_services import init_storage_client, GCPConfig

STORAGE_BUCKET_NAME = 'xsoar-ci-artifacts'
PRIVATE_ID_SET_PATH = ''


def upload_private_id_set(storage_bucket, private_id_set_path):
    """
        Uploads the private_id_set.json artifact to the bucket.

        Args:
            storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where core packs config is uploaded.
            private_id_set_path: path to the private_id_set.json file
        """
    if not private_id_set_path:
        logging.info("Skipping upload of private id set to gcs.")
        return

    private_id_set_gcs_path = os.path.join(os.path.dirname(GCPConfig.STORAGE_PRIVATE_ID_SET_PATH),
                                           'private_id_set.json')

    blob = storage_bucket.blob(private_id_set_gcs_path)

    with open(private_id_set_path, mode='r') as f:
        blob.upload_from_file(f)
    logging.success("Finished uploading id_set.json to storage.")


def options_handler():
    parser = argparse.ArgumentParser(description='Returns the new pack name')
    parser.add_argument('-ispk', '--id_set_path', help='Private ID set path', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()

    storage_bucket_name = STORAGE_BUCKET_NAME
    service_account = options.service_account
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)
    upload_private_id_set(storage_bucket, PRIVATE_ID_SET_PATH)


if __name__ == '__main__':
    main()
