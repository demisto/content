import sys
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

STR = """qa2-test-9997333835008
qa2-test-9994443226862
qa2-test-9997461765391
"""
MARKETPLACE_TEST_BUCKET = 'marketplace-ci-build/content/builds'
MARKETPLACE_XSIAM_BUCKETS = 'marketplace-v2-dist-dev/upload-flow/builds-xsiam'


def main():
    install_logging('Create_GCP.log', logger=logging)
    logging.info('Starting create bucket folder')
    from google.cloud import storage
    storage_client = storage.Client()

    bucket = storage_client.bucket('marketplace-ci-build')
    destination_bucket = storage_client.bucket('marketplace-v2-dist-dev')
    from_bucket = 'content/builds/xsiam-build-instances/2576350/marketplacev2/content'
    blob = bucket.blob(from_bucket)
    to_bucket = 'upload-flow/builds-xsiam/xsoar-content-1/'

    copied_index = bucket.copy_blob(
        blob=blob, destination_bucket=destination_bucket, new_name=to_bucket
    )
    if copied_index.exists():
        logging.success(f"Finished uploading to storage.")

    # blob = bucket.blob('upload-flow/builds-xsiam/')
    # blob.upload_from_string('')
    # logging.info('Created folder for xsiambuilds')

    # blob = bucket.blob('upload-flow/builds-xsiam/qa2-test-9994443226862/')
    # blob.upload_from_string('')
    # logging.info('Created folder qa2-test-9997333835008')
    #
    # s = blob.download_as_string()
    # logging.info(f'{s=}')
    #
    # blob = bucket.blob('content-locks-xsiam/test123')
    # blob.upload_from_string('')
    # logging.info('Created file test123')
    # blob.delete()
    # logging.info('Deleted file test123')

    # blob = bucket.blob('content-locks/test123')
    # blob.delete()
    # logging.info('Delted folder.')


if __name__ == '__main__':
    main()
