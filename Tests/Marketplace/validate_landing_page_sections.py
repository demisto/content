import argparse
import json
import os
import sys
from glob import glob

from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

LANDING_PAGE_SECTIONS_PAGE_PATH = 'Tests/Marketplace/landingPage_sections.json'


def main():
    parser = argparse.ArgumentParser(description="Validates landingPage_sections.json file")
    parser.add_argument('-i', '--index-path', help="Path of the unzipped content of the index.zip file", required=True)
    options = parser.parse_args()

    landing_page_sections_json: dict = parse_landing_page_sections_to_json()
    validate_file_keys(landing_page_sections_json)

    bucket_pack_names = {os.path.basename(pack_name) for pack_name in glob(f'{options.index_path}/index/*')}
    content_repo_pack_names = {os.path.basename(pack_name) for pack_name in glob('Packs/*')}
    valid_packs = bucket_pack_names | content_repo_pack_names
    validate_valid_packs_in_sections(landing_page_sections_json, valid_packs)
    logging.success('Validation finished successfully')


def validate_valid_packs_in_sections(landing_page_sections_json: dict, valid_pack_names: set) -> None:
    """
    Validates all packs in the sections of the file are valid packs according to the latest index.zip file
    Args:
        landing_page_sections_json: The content of the landingPage_sections.json file
        valid_pack_names: A set containing all valid pack names from latest index.zip file and content repo
    """
    logging.info('validating packs in sections appear in latest index.zip file')
    for section_name, packs_in_section in landing_page_sections_json.items():
        if section_name in {'description', 'sections'}:
            continue
        for pack_name in packs_in_section:
            assert pack_name in valid_pack_names, f'Pack {pack_name} was not found in latest index.zip file, ' \
                                                  f'Make sure you uploaded the pack'


def validate_file_keys(landing_page_sections_json: dict) -> None:
    """
    Validates that besides the 'description' and 'sections' keys - all keys in the file are sections names that appear
    in the 'sections' part of the file.
    Raises: Exception if the file has non allowed key.
    Args:
        landing_page_sections_json: The content of the landingPage_sections.json file
    """
    logging.info('Validating file keys are valid sections')
    allowed_keys = {'description', 'sections'}
    allowed_keys.update(landing_page_sections_json['sections'])
    not_allowed_key = [key for key in landing_page_sections_json.keys() if key not in allowed_keys]
    assert not not_allowed_key, f'Unsupported keys found: {not_allowed_key}, please add ' \
                                f'these keys under the "sections" key or remove them.'


def parse_landing_page_sections_to_json():
    try:
        with open(LANDING_PAGE_SECTIONS_PAGE_PATH, 'r') as file:
            return json.load(file)
    except Exception:
        logging.critical('Could not parse the file as json file')
        sys.exit(1)


if __name__ in ("__main__", "__builtin__", "builtins"):
    install_logging('ValidateLandingPageSections.log', logger=logging)
    main()
