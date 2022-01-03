import zipfile as z
import os
from google.cloud import storage
import argparse
import shutil


ARTIFACTS_PATH = os.environ.get('ARTIFACTS_FOLDER')
STORAGE_BUCKET_NAME = 'xsoar-ci-artifacts'
FILES_TO_REMOVE = ['content-descriptor.json', 'doc-CommonServer.json', 'doc-howto.json', 'reputations.json',
                   'tools-o365.zip', 'tools-exchange.zip', 'tools-winpmem.zip']
CONTENT_NEW_ZIP_PATH = f'{ARTIFACTS_PATH}/content_new.zip'
ALL_CONTENT_ZIP_PATH = f'{ARTIFACTS_PATH}/all_content.zip'

ORIGINAL_CONTENT_NEW_ZIP_PATH = f'{ARTIFACTS_PATH}/original_content_new.zip'
ORIGINAL_ALL_CONTENT_ZIP_PATH = f'{ARTIFACTS_PATH}/original_all_content.zip'


def download_zip_file_from_gcp(current_feature_branch_zip_file_path, zip_destination_path, zip_name):
    """Save the zip file from the feature branch into artifacts folder.

    Args:
        current_feature_branch_zip_file_path (str): The feature branch zip file path in google cloud.
        zip_destination_path: The folder path to download the zip file to.
        zip_name: The name of the zip to download

    Returns:
        The new path of the zip file.
    """
    file_path = os.environ.get('GCS_ARTIFACTS_KEY')
    if file_path:
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = file_path
    storage_client = storage.Client()

    storage_bucket = storage_client.bucket(STORAGE_BUCKET_NAME)

    index_blob = storage_bucket.blob(current_feature_branch_zip_file_path)
    if not os.path.exists(zip_destination_path):
        os.mkdir(zip_destination_path)
    index_blob.download_to_filename(f'{zip_destination_path}/{zip_name}.zip')

    if os.path.exists(f'{zip_destination_path}/{zip_name}.zip'):
        return f'{zip_destination_path}/{zip_name}.zip'

    return ''


def merge_zip_files(feature_branch_content_zip_file_path, artifacts_zip_path, original_zip_path):
    """Merge zip files and remove the unnecessary files.

    Args:
        feature_branch_content_zip_file_path: Feature content_new.zip file path

    """
    os.rename(artifacts_zip_path, original_zip_path)
    unified_zip = z.ZipFile(artifacts_zip_path, 'a', z.ZIP_DEFLATED)
    with z.ZipFile(original_zip_path, 'r') as master_zip:
        feature_zip = z.ZipFile(feature_branch_content_zip_file_path, 'r')
        for name in feature_zip.namelist():
            if name not in FILES_TO_REMOVE:
                unified_zip.writestr(name, feature_zip.open(name).read())
        for name in master_zip.namelist():
            unified_zip.writestr(name, master_zip.open(name).read())

    master_zip.close()
    feature_zip.close()


def get_feature_branch_zip_file_path(feature_branch_build_path, zip_name):
    """Get the feature branch zip file.

    Args:
        feature_branch_build_path (str): The path to last successful feature branch build.
        zip_name (str): The zip we want to download (all_content or content_new).

    """
    current_feature_branch_zip_file_path = f'{feature_branch_build_path}/0/{zip_name}.zip'
    zip_destination_path = f'{ARTIFACTS_PATH}/feature_{zip_name}_zip'
    feature_zip_file_path = download_zip_file_from_gcp(current_feature_branch_zip_file_path, zip_destination_path,
                                                       zip_name)
    return feature_zip_file_path, zip_destination_path


def remove_directory(dir_path):
    shutil.rmtree(dir_path, ignore_errors=True)


def option_handler():
    parser = argparse.ArgumentParser(description='Merging two content_new.zip files from different builds.')
    parser.add_argument('-f', '--feature_branch', help='The name of the feature branch', required=True)
    parser.add_argument('-b', '--build_number', help='The last successful build number of the feature branch',
                        required=True)

    options = parser.parse_args()

    return options


def main():
    options = option_handler()
    feature_branch_name = options.feature_branch
    last_successful_feature_branch_build = options.build_number

    feature_branch_content_new_zip_file_path, content_new_zip_destination_path = \
        get_feature_branch_zip_file_path(last_successful_feature_branch_build, 'content_new')

    feature_branch_all_content_zip_file_path, all_content_zip_destination_path = \
        get_feature_branch_zip_file_path(last_successful_feature_branch_build, 'all_content')

    if feature_branch_content_new_zip_file_path:
        merge_zip_files(feature_branch_content_new_zip_file_path, artifacts_zip_path=CONTENT_NEW_ZIP_PATH,
                        original_zip_path=ORIGINAL_CONTENT_NEW_ZIP_PATH)
        remove_directory(content_new_zip_destination_path)
        print('Done merging content_new.zip files')
    else:
        print(f'Failed to download content_new.zip from feature branch {feature_branch_name}')

    if feature_branch_all_content_zip_file_path:
        merge_zip_files(feature_branch_all_content_zip_file_path, artifacts_zip_path=ALL_CONTENT_ZIP_PATH,
                        original_zip_path=ORIGINAL_ALL_CONTENT_ZIP_PATH)
        remove_directory(all_content_zip_destination_path)
        print('Done merging all_content.zip files')
    else:
        print(f'Failed to download all_content.zip from feature branch {feature_branch_name}')


if __name__ == "__main__":
    main()
