import argparse
import os
import uuid
import json
import tempfile
import logging
from Tests.Marketplace.upload_packs import init_storage_client, download_and_extract_index, upload_index_to_storage
from Tests.Marketplace.marketplace_services import GCPConfig, Pack
from Tests.scripts.utils.log_util import install_logging


def option_handler():
    """Validates and parses script arguments.
    Returns:
        Namespace: Parsed arguments object.
    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-sb', '--storage_bash_path', help="Storage base path of the directory to normalize paths.",
                        required=True)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    # disable-secrets-detection-end
    return parser.parse_args()


def switch_image_path(image_path, original_base_path):
    """ Switches the original storage base path to newly defined in GCPConfig.STORAGE_BASE_PATH.
    Args:
        image_path (str): gcp integration image path.
        original_base_path (str): original base storage path (content/packs).
    Returns:
        str: switched integration image path.
    """
    relative_image_path = os.path.relpath(image_path, original_base_path)
    return os.path.join(GCPConfig.STORAGE_BASE_PATH, relative_image_path)


def normalize_pack_integration_urls(pack, original_base_path):
    """ Reads pack metadata.json, fixes the wrong path and writes the result back to metadata file.
    Args:
        pack (DirEntry): pack sub-folder inside index.
        original_base_path (str): original base storage path (content/packs).
    """
    if pack.is_dir():  # skipping if current entry is not a folder
        metadata_path = os.path.join(pack.path, Pack.METADATA)  # packs full path

        if not os.path.exists(metadata_path):
            return  # pack metadata was not found

        with open(metadata_path, "r") as metadata_file:
            metadata = json.load(metadata_file)

        integration_images_section = metadata.pop('integrations', [])

        for integration_image_data in integration_images_section:
            image_path = integration_image_data.get('imagePath', '')

            if image_path.startswith(original_base_path):
                integration_image_data['imagePath'] = switch_image_path(image_path=image_path,
                                                                        original_base_path=original_base_path)

        # set back integration section
        metadata['integrations'] = integration_images_section
        # check author image
        author_image = metadata.get('authorImage', '')
        # normalize author path if needed
        if author_image.startswith(original_base_path):
            metadata['authorImage'] = switch_image_path(image_path=author_image,
                                                        original_base_path=original_base_path)

        with open(metadata_path, "w") as metadata_file:
            json.dump(metadata, metadata_file, indent=4)


def main():
    install_logging('Prepare_Content_Packs_For_Testing.log')
    option = option_handler()
    storage_bucket_name = option.bucket_name
    service_account = option.service_account
    build_number = str(uuid.uuid4())
    extract_destination_path = tempfile.mkdtemp()

    # store original base storage path
    original_base_path = GCPConfig.STORAGE_BASE_PATH
    # set new storage base path for content test builds
    GCPConfig.STORAGE_BASE_PATH = os.path.normpath(option.storage_bash_path)

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)

    # download and extract index from test bucket
    index_folder_path, index_blob, _ = download_and_extract_index(storage_bucket, extract_destination_path)

    logging.info(f"Starting iterating over packs in {GCPConfig.INDEX_NAME} and normalizing packs integration URLs")
    # starting iterating over packs folders inside index

    for pack in os.scandir(index_folder_path):
        normalize_pack_integration_urls(pack=pack, original_base_path=original_base_path)

    # finished iteration over packs inside index
    logging.info(f"Finished iterating over packs in {GCPConfig.INDEX_NAME}")

    upload_index_to_storage(index_folder_path=index_folder_path, extract_destination_path=extract_destination_path,
                            index_blob=index_blob, build_number=build_number, private_packs=[])


if __name__ == "__main__":
    main()
