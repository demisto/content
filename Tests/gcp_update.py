import subprocess
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

STR = """qa2-test-9997333835008
qa2-test-9994443226862
qa2-test-9997461765391
"""
MARKETPLACE_TEST_BUCKET = 'marketplace-ci-build/content/builds'
MARKETPLACE_XSIAM_BUCKETS = 'marketplace-v2-dist-dev/upload-flow/builds-xsiam'
ARTIFACTS_FOLDER_MPV2 = "/builds/xsoar/content/artifacts/marketplacev2"


def main():
    install_logging('Create_GCP.log', logger=logging)
    logging.info('Starting create bucket folder')
    from google.cloud import storage
    storage_client = storage.Client()

    # logging.info('Copying build bucket to xsiam_instance_bucket.')
    # from_bucket = f'{MARKETPLACE_TEST_BUCKET}/xsiam-build-instances/2613454/marketplacev2/content'
    # to_bucket = f'{MARKETPLACE_XSIAM_BUCKETS}/xsoar-content-1'
    # output_file = f'{ARTIFACTS_FOLDER_MPV2}/Copy_prod_bucket_to_xsiam_machine.log'
    # cmd = f'gsutil -m cp -r gs://{from_bucket} gs://{to_bucket}/'
    #
    # with open(output_file, "w") as outfile:
    #     subprocess.run(cmd.split(), stdout=outfile, stderr=outfile)
    # logging.info('Finished copying successfully.')

    # bucket = storage_client.bucket('marketplace-ci-build')
    bucket = storage_client.bucket('marketplace-v2-dist-dev')
    # blob = bucket.blob('upload-flow/builds-xsiam/')
    # blob.upload_from_string('')
    # logging.info('Created folder for xsiambuilds')

    blob = bucket.blob('upload-flow/builds-xsiam/qa2-test-9994443226862/')
    blob.upload_from_string('')
    logging.info('Created folder qa2-test-9994443226862')

    blob = bucket.blob('upload-flow/builds-xsiam/qa2-test-9997461765391/')
    blob.upload_from_string('')
    logging.info('Created folder qa2-test-9997461765391')

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
