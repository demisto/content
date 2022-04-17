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

    blob = bucket.blob('content-locks-xsiam/queue-master')
    blob.upload_from_string('')
    logging.info('Created file')

    blob = bucket.blob('content-locks-xsiam/queue')
    blob.delete()
    logging.info('Deleted file.')

    blob = bucket.blob('content-locks-xsiam/TestMachines')
    test_machines = blob.download_as_string()
    blob.delete()
    logging.info('Deleted file.')
    logging.info(f'{test_machines=}')

    blob = bucket.blob('content-locks-xsiam/test-machines-master')
    blob.upload_from_string(test_machines)
    logging.info('Created file')


if __name__ == '__main__':
    main()
