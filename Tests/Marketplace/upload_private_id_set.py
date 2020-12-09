import os
import argparse
import logging
from Tests.Marketplace.marketplace_services import init_storage_client, GCPConfig

STORAGE_BUCKET_NAME = 'xsoar-ci-artifacts'


def upload_private_id_set_to_bucket(storage_bucket, private_id_set_path):
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

    with open(private_id_set_path, mode='r') as private_id_set:
        blob.upload_from_file(private_id_set)
    logging.success("Finished uploading id_set.json to storage.")


def options_handler():
    parser = argparse.ArgumentParser(description='Upload private ID set to cloud storage')
    parser.add_argument('-pis', '--private_id_set_path', help='Private ID set path', required=True)

    # disable-secrets-detection-start
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    # disable-secrets-detection-end

    options = parser.parse_args()
    return options


def main():
    options = options_handler()

    private_id_set_path = options.private_id_set_path
    service_account = options.service_account
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)
    upload_private_id_set_to_bucket(storage_bucket, private_id_set_path)


if __name__ == '__main__':
    main()
