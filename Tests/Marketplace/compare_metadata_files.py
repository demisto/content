import argparse
import json
import os
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from zipfile import ZipFile


IGNORE_FIELDS = [
    'marketplaces',
    'integrations',
    'searchRank',
    'downloads',
    'fromversion',
    'deprecated'
]


def option_handler():
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-cp', '--content_packs', required=True)
    parser.add_argument('-up', '--uploaded_packs', required=True)
    parser.add_argument('-mt1', '--metadata_1', required=False)
    parser.add_argument('-mt2', '--metadata_2', required=False)
    return parser.parse_args()


def read_metadata(metadata_path):
    with open(metadata_path) as f:
        return json.loads(f.read())


def check_dict_in_list(existing_value: dict, new_val: list, missing_in: str, parent_key):
    field = 'id' if 'id' in existing_value else 'name'
    found = False
    for i in new_val:
        if existing_value.get(field) == i.get(field):
            found = True
            get_diff(existing_value, i, missing_in, f"'{parent_key}'---'id={i.get('id')}'")
    return found


def add_diff_to_list(key, parent_key, different_keys, different_ignored_keys):
    if key in IGNORE_FIELDS:
        different_ignored_keys.append(f"{parent_key} => {key}")
    else:
        different_keys.append(f"{parent_key} => {key}")


def get_diff(existing_metadata: dict, new_metadata: dict, missing_in: str, parent_key=None):
    different_keys: list = []
    different_ignored_keys: list = []
    for key, val in existing_metadata.items():
        if key in IGNORE_FIELDS:
            continue

        if key not in new_metadata:
            add_diff_to_list(key, parent_key, different_keys, different_ignored_keys)
            logging.debug(f"Key {key} not found in {missing_in} - {parent_key=}\n")
        else:
            if isinstance(val, dict):
                get_diff(val, new_metadata.get(key), missing_in, key)  # type:ignore[arg-type]
            elif isinstance(val, list):
                if val and isinstance(val[0], dict):
                    new_val = new_metadata.get(key)
                    for i in val:
                        if not check_dict_in_list(i, new_val, missing_in, key):  # type:ignore[arg-type]
                            add_diff_to_list(key, parent_key, different_keys, different_ignored_keys)
                            logging.debug(f"Value of key '{key}' is different in {missing_in}: '{i}' not in '{new_val}' - "
                                          f"{parent_key=}\n")
                else:
                    for i in val:
                        if i not in new_metadata.get(key):  # type:ignore[operator]
                            add_diff_to_list(key, parent_key, different_keys, different_ignored_keys)
                            logging.debug(f"Value '{i}' with key '{key}' is not in {missing_in} - {parent_key=}\n")
            else:
                if val != new_metadata.get(key):
                    add_diff_to_list(key, parent_key, different_keys, different_ignored_keys)
                    logging.debug(f"Value of key '{key}' is different in {missing_in}: '{val}' != '{new_metadata.get(key)}' - "
                                  f"{parent_key=}\n")
    return different_keys, different_ignored_keys


def main():
    install_logging('compare_metadata_files_logger.log', logger=logging)
    options = option_handler()

    with ZipFile(options.content_packs) as packs_artifacts:
        packs_artifacts.extractall("./content_packs")

    for pack_dir in os.scandir(options.uploaded_packs):
        pack_dir_name = pack_dir.name.split('.zip')[0]

        if not pack_dir.name.endswith(".zip"):
            logging.debug(f"{pack_dir} is not a zip")
            continue

        new_pack_dir = f"{options.uploaded_packs}/{pack_dir_name}"
        with ZipFile(pack_dir) as pack_dir_zip:
            pack_dir_zip.extractall(new_pack_dir)

        existing_metadata = read_metadata(f"{new_pack_dir}/metadata.json")
        new_metadata = read_metadata(f"content_packs/{pack_dir_name}/metadata.json")

        logging.info(f"Starting to compare metadata files {new_pack_dir}/metadata.json---content_packs/{pack_dir_name}"
                     "/metadata.json")
        different_keys, different_ignored_keys = get_diff(existing_metadata, new_metadata, options.content_packs)

        if different_keys:
            logging.error(f"Found different values in 'content_packs/{pack_dir_name}/metadata.json' for keys '{different_keys}'")
        elif different_ignored_keys:
            logging.debug(f"Found different (ignored) values in 'content_packs/{pack_dir_name}/metadata.json' for keys "
                          f"'{different_ignored_keys}'")
        else:
            logging.success("Found the metadata files equal")


if __name__ == '__main__':
    main()
