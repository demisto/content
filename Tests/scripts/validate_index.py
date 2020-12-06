"""Run validation on the index.json file.

Check index.json file inside the index.zip archive in the cloud.
Validate no missing ids are found and that all packs have a positive price.
Validate commit hash is in master's history.
"""
import argparse
import logging
import json
import sys
import git
import os

from Tests.Marketplace.marketplace_services import init_storage_client, GCPConfig, CONTENT_ROOT_PATH
from Tests.Marketplace.upload_packs import download_and_extract_index, get_content_git_client
from Tests.scripts.utils.log_util import install_logging
from pprint import pformat

INDEX_FILE_PATH = 'index.json'
DEFAULT_PAGE_SIZE = 50


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating integration instances')
    parser.add_argument('-e', '--extract_path',
                        help=f'Full path of folder to extract the {GCPConfig.INDEX_NAME}.zip to',
                        required=True)
    parser.add_argument('-pb', '--production_bucket_name', help='Production bucket name', required=True)
    parser.add_argument('-sa', '--service_account', help='Path to gcloud service account', required=True)

    options = parser.parse_args()
    return options


def log_message_if_statement(statement: bool, error_message: str, success_message: str = None) -> bool:
    """Log error message if statement is false, Log success otherwise

    Args:
        statement: The boolean statement to check.
        error_message: The error message to log if statement is false
        success_message: The success message to log if statement is true

    Returns: The statements boolean value.
    """
    if not statement:
        logging.error(error_message)
    elif success_message:
        logging.success(success_message)
    return statement


def check_index_data(index_data: dict) -> bool:
    """Check index.json file inside the index.zip archive in the cloud.

    Validate by running verify_pack on each pack.

    Args:
        index_data: Dictionary of the index.json contents.

    Returns: True if all packs are valid, False otherwise.
    """
    logging.info("Found index data in index file. Checking...")
    logging.debug(f"Index data is:\n {pformat(index_data)}")

    packs_list_exists = log_message_if_statement(statement=(len(index_data.get("packs", [])) != 0),
                                                 error_message="Found 0 packs in index file."
                                                               "\nAborting the rest of the check.")
    if not packs_list_exists:
        return False

    packs_are_valid = True
    for pack in index_data["packs"]:
        pack_is_good = verify_pack(pack)
        if not pack_is_good:
            packs_are_valid = False

    return packs_are_valid


def verify_pack(pack: dict) -> bool:
    """Verify the pack id is not empty and it's price is positive.

    Args:
        pack: The pack to verify.

    Returns: True if pack is valid, False otherwise.
    """
    id_exists = log_message_if_statement(statement=(pack.get("id", "") != ""),
                                         error_message="There is a missing pack id.")
    price_is_valid = log_message_if_statement(statement=(pack.get("price", -1) > 0),
                                              error_message=f"The price on the pack {pack['id']} is 0 or less.",
                                              success_message=f"The price on the pack {pack['id']} is valid.")
    return all([id_exists, price_is_valid])


def get_hexsha(commit: git.repo.commit) -> str:
    """Return hash of the git commit object"""
    return commit.hexsha


def check_commit_in_master_history(index_commit_hash: str) -> bool:
    """Assert commit hash is in master history.

    Args:
        index_commit_hash: commit hash

    Returns: True if commit hash is in master history, False otherwise.
    """
    content_repo = get_content_git_client(CONTENT_ROOT_PATH)
    master_commits = list(map(get_hexsha, list(content_repo.iter_commits("master"))))

    return log_message_if_statement(statement=(index_commit_hash in master_commits),
                                    error_message=f"Commit hash {index_commit_hash} is not in master history",
                                    success_message="Commit hash in index file is valid.")


def get_index_json_data(service_account: str, production_bucket_name: str, extract_path: str) -> (dict, str):
    """Retrieve the index.json file from production bucket.

    Args:
        service_account: Path to gcloud service account
        production_bucket_name: Production bucket name
        extract_path: Full path of folder to extract the index.zip to

    Returns:
        (Dict: content of the index.json, Str: path to index.json)
    """
    logging.info('Downloading and extracting index.zip from the cloud')
    storage_client = init_storage_client(service_account)
    production_bucket = storage_client.bucket(production_bucket_name)
    index_folder_path, build_index_blob, build_index_generation = \
        download_and_extract_index(production_bucket, extract_path)

    logging.info("Retrieving the index file")
    index_file_path = os.path.join(index_folder_path, f"{GCPConfig.INDEX_NAME}.json")
    with open(index_file_path, 'r') as index_file:
        index_data = json.load(index_file)

    return index_data, index_file_path


def main():
    install_logging("Validate index.log")
    options = options_handler()
    index_data, index_file_path = get_index_json_data(service_account=options.service_account,
                                                      production_bucket_name=options.production_bucket_name,
                                                      extract_path=options.extract_path)

    # Validate index.json file
    index_is_valid = check_index_data(index_data)
    log_message_if_statement(statement=index_is_valid,
                             error_message=f"The packs in the {index_file_path} file were found invalid.",
                             success_message=f"{index_file_path} file was found valid")

    # Validate commit hash in master history
    commit_hash_is_valid = check_commit_in_master_history(index_data.get("commit", ""))

    if not all([index_is_valid, commit_hash_is_valid]):
        logging.critical("Index content is invalid. Aborting.")
        sys.exit(1)


if __name__ == '__main__':
    main()
