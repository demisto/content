from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


def main():
    install_logging('Create_GCP.log', logger=logging)
    logging.info('Starting create bucket folder')
    from google.cloud import storage
    storage_client = storage.Client()

    all_blobs = list(storage_client.list_blobs('xsoar-ci-artifacts'))
    logging.info(f'All blobs: {all_blobs}')

    bucket = storage_client.bucket('xsoar-ci-artifacts')
    blob = bucket.blob('xsiam-ci-locks')
    blob.delete()
    logging.info('File deleted successfully.')

    blob = bucket.blob('xsiam-ci-locks/')
    # blob.upload_from_string('queue')
    # logging.info('Created bucket folder successfully.')

    # logging.info('Creating new file"')
    s = """qa2-test-999733383500\nqa2-test-9994443226862\nqa2-test-9997461765391"""
    with open('TestMachines', 'w') as f:
        f.write(s)

    # blob.upload_from_filename('TestMachines')


if __name__ == '__main__':
    main()
