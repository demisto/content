import sys
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


def main():
    install_logging('Create_GCP.log', logger=logging)
    logging.info('Starting create bucket folder')
    from google.cloud import storage
    storage_client = storage.Client()
    # storage_client = storage.Client.from_service_account_json(sys.argv[1])

    bucket = storage_client.bucket('xsoar-ci-artifacts')

    blob = bucket.blob('xsiam-ci-locks/queue')
    downloaded_blob = blob.download_as_string()
    logging.info(f'{downloaded_blob=}')

    blob2 = bucket.blob('xsiam-ci-locks/TestMachines')
    downloaded_blob2 = blob2.download_as_string()
    logging.info(f'{downloaded_blob2=}')

    # blob = bucket.blob('xsiam-ci-locks')
    # blob.delete()
    # logging.info('File deleted successfully.')


if __name__ == '__main__':
    main()
