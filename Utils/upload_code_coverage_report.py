
from datetime import datetime
import json
import os

from google.cloud import storage

from typing import Dict

# TODO Initialize the Storage Client. See upload_packs.py
# from Tests.Marketplace.marketplace_services import init_storage_client

def create_minimal_report(source_file: str, destination_file: str):
    with open(source_file, 'r') as cov_util_output:
        data = json.load(cov_util_output)

    # TODO Check that we were able to read the json report corretly

    minimal_coverage_contents_files: Dict[str, float] = {}
    for current_file_name in data.get('files').keys():
        minimal_coverage_contents_files[current_file_name] = data['files'][current_file_name]['summary']['percent_covered']
    minimal_coverage_contents: Dict[str, any] = {}
    minimal_coverage_contents['files'] = minimal_coverage_contents_files
    minimal_coverage_contents['last_updated'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    with open(destination_file, 'w') as minimal_output:
        minimal_output.write(json.dumps(minimal_coverage_contents))


# https://storage.cloud.google.com/marketplace-dist-dev/code-coverage/coverage_data.json
def upload_code_cov_report(source_file_name: str, bucket_name: str = 'marketplace-dist-dev', destination_blob_name: str = 'code-coverage/coverage_data.json'):
    """Uploads the Code Coverage report to the bucket."""
    upload_file_to_google_cloud_storage(bucket_name=bucket_name, source_file_name=source_file_name, destination_blob_name=destination_blob_name)


def upload_file_to_google_cloud_storage(bucket_name: str, source_file_name: str, destination_blob_name: str):
    """Uploads a file to the bucket."""

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    print(
        "File {} uploaded to {}.".format(
            source_file_name, destination_blob_name
        )
    )
