
import argparse
from datetime import datetime
import json
from typing import Dict

from Tests.Marketplace.marketplace_services import init_storage_client


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


def upload_file_to_google_cloud_storage(service_account: str,
                                        bucket_name: str,
                                        source_file_name: str,
                                        destination_blob_name: str,
                                        ):
    """Uploads a file to the bucket."""

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    print(
        "File {} uploaded to {}.".format(
            source_file_name, destination_blob_name
        )
    )


def options_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, "
                              "For uploading the coverage report to Google Cloud Storage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=True)

    parser.add_argument('-b', '--bucket_name',
                        help=("Name of the bucket in Google Cloud Storage. "
                              "Default value is marketplace-dist-dev."),
                        required=False)

    # TODO Pass specific arguments to methods (and no "options")
    parser.add_argument('-f', '--source_file_name',
                        default='coverage.json',
                        help=("Path to the Coverage report in json format. "
                              "Default value is coverage.json."),
                        required=False)

    parser.add_argument('-m', '--minimal_file_name',
                        default='coverage_data.json',
                        help=("Filename of a minimal coverage report. "
                              "It is a subset of the source_file_name. "
                              "Default value is coverage_data.json."),
                        required=False)

    parser.add_argument('-d', '--destination_blob_name',
                        default='code-coverage/coverage_data.json',
                        help=("Blob Name in Google Cloud Storage. "
                              "Default value is code-coverage/coverage_data.json."),
                        required=False)

    parser.add_argument('-cov', '--cov_bin_dir',
                        default='code-coverage/coverage_data.json',
                        help=("Blob Name in Google Cloud Storage. "
                              "Default value is code-coverage/coverage_data.json."),
                        required=False)

    return parser.parse_args()


def coverage_json(cov_file, json_file):
    # this method will be removed when merge to sdk
    from coverage import Coverage
    Coverage(data_file=cov_file).json_report(outfile=json_file)


def main():
    options = options_handler()
    coverage_json(options.cov_bin_dir, options.source_file_name)

    create_minimal_report(source_file=options.source_file_name,
                          destination_file=options.minimal_file_name,
                          )

    upload_file_to_google_cloud_storage(service_account=options.service_account,
                                        bucket_name=options.bucket_name,
                                        source_file_name=options.source_file_name,
                                        destination_blob_name=options.destination_blob_name,
                                        )


if __name__ == '__main__':
    main()
