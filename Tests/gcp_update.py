import sys
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


def main():
    install_logging('Create_GCP.log', logger=logging)
    logging.info('Starting create bucket folder')
    from google.cloud import storage
    # storage_client = storage.Client()
    storage_client = storage.Client.from_service_account_json(sys.argv[1])

    bucket = storage_client.bucket('xsoar-ci-artifacts')

    # all_blobs = list(storage_client.list_blobs('xsoar-ci-artifacts'))
    # logging.info(f'All blobs: {all_blobs}')

    blob = bucket.blob('xsiam-ci-locks/TestMachines')
    s = """qa2-test-999733383500\nqa2-test-9994443226862\nqa2-test-9997461765391"""
    blob.upload_from_string(s)
    logging.info('Created bucket folder successfully.')

    blob = bucket.blob('xsiam-ci-locks')
    blob.delete()
    logging.info('File deleted successfully.')


if __name__ == '__main__':
    main()
