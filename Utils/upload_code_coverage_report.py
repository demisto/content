
import argparse
from datetime import datetime
import json
from typing import Dict

from Tests.Marketplace.marketplace_services import init_storage_client


DATE_FORMAT = '%Y-%m-%d'
TIMESTAMP_FORMAT_SECONDS = '%Y-%m-%dT%H:%M:%SZ'
TIMESTAMP_FORMAT_MICROSECONDS = '%Y-%m-%dT%H:%M:%S.%f'


def create_minimal_report(source_file: str, destination_file: str):
    with open(source_file, 'r') as cov_util_output:
        data = json.load(cov_util_output)

    # TODO Check that we were able to read the json report correctly

    minimal_coverage_contents_files: Dict[str, float] = {}
    files = data['files']
    for current_file_name, current_file_data in files.items():
        minimal_coverage_contents_files[current_file_name] = round(current_file_data['summary']['percent_covered'], 2)

    timestamp_from_file = data['meta']['timestamp']
    datetime_from_timestamp: datetime = datetime.strptime(timestamp_from_file, TIMESTAMP_FORMAT_MICROSECONDS)
    str_from_datetime: str = datetime.strftime(datetime_from_timestamp, TIMESTAMP_FORMAT_SECONDS)

    minimal_coverage_contents = {
        'files': minimal_coverage_contents_files,
        'last_updated': str_from_datetime,
        'total_coverage': data['totals']['percent_covered']
    }
    with open(destination_file, 'w') as minimal_output:
        minimal_output.write(json.dumps(minimal_coverage_contents))


def upload_file_to_google_cloud_storage(service_account: str,
                                        bucket_name: str,
                                        minimal_file_name: str,
                                        destination_blob_dir: str,
                                        ):
    """Uploads a file to the bucket."""
    json_dest = '{}/coverage-min.json'.format(destination_blob_dir)
    with open(minimal_file_name, 'r') as data_file:
        updated = datetime.strptime(json.load(data_file)['last_updated'], TIMESTAMP_FORMAT_SECONDS)
    historic_data_dest = '{}/history/coverage-min-{}.json'.format(destination_blob_dir, updated.strftime(DATE_FORMAT))

    upload_list = [json_dest, historic_data_dest]
    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    bucket = storage_client.bucket(bucket_name)

    for file_to_upload in upload_list:
        upload_file_to_bucket(bucket, file_to_upload, minimal_file_name)

    print(
        "File {} uploaded to {}.".format(
            minimal_file_name, ', '.join(upload_list)
        )
    )


def upload_file_to_bucket(bucket_obj, path_in_bucket, local_path):
    blob = bucket_obj.blob(path_in_bucket)
    blob.upload_from_filename(local_path)


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
                        default="marketplace-dist-dev",
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

    parser.add_argument('-d', '--destination_blob_dir',
                        default='code-coverage',
                        help=("Blob Name in Google Cloud Storage. "
                              "Default value is code-coverage."),
                        required=False)

    parser.add_argument('-cov', '--cov_bin_dir',
                        default='code-coverage/coverage_data.json',
                        required=False)

    return parser.parse_args()


def coverage_json(cov_file, json_file):
    # this method will be removed when merge to sdk
    from coverage import Coverage
    cov = Coverage(data_file=cov_file, auto_data=False)
    cov.load()
    cov.json_report(outfile=json_file)


def main():
    options = options_handler()
    coverage_json(options.cov_bin_dir, options.source_file_name)

    create_minimal_report(source_file=options.source_file_name,
                          destination_file=options.minimal_file_name,
                          )

    upload_file_to_google_cloud_storage(service_account=options.service_account,
                                        bucket_name=options.bucket_name,
                                        minimal_file_name=options.minimal_file_name,
                                        destination_blob_dir=options.destination_blob_dir,
                                        )


if __name__ == '__main__':
    main()
