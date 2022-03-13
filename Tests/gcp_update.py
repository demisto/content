import sys
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

STR = """qa2-test-9997333835008
qa2-test-9994443226862
qa2-test-9997461765391
"""


def main():
    install_logging('Create_GCP.log', logger=logging)
    logging.info('Starting create bucket folder')
    from google.cloud import storage
    storage_client = storage.Client()

    bucket = storage_client.bucket('xsoar-ci-artifacts')

    blob = bucket.blob('content-locks-xsiam/queue')
    blob.upload_from_string('')
    logging.info('Created file queue')

    blob = bucket.blob('content-locks-xsiam/TestMachines')
    blob.upload_from_string(STR)
    logging.info('Created file TestMachines')

    s = blob.download_as_string()
    logging.info(f'{s=}')

    # blob = bucket.blob('content-locks/test123')
    # blob.delete()
    # logging.info('Delted folder.')


if __name__ == '__main__':
    main()
