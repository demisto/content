import json
import os

from demisto_sdk.commands.common.constants import (PACK_METADATA_SUPPORT, PACKS_DIR, PACKS_PACK_META_FILE_NAME)

SKIPPED_PACKS = ['DeprecatedContent', 'NonSupported']


def get_pack_metadata(file_path: str) -> dict:
    """
    Args:
        file_path: The Pack metadata file path

    Returns:
        dict: The pack metadata file content
    """
    with open(file_path) as pack_metadata:
        return json.load(pack_metadata)


def is_pack_xsoar_supported(pack_path: str) -> bool:
    """Checks whether the pack is XSOAR supported.
    Tests are not being collected for non XSOAR  packs.

    Args:
        pack_path (str): The pack path

    Returns:
        True if the pack is certified, False otherwise
    """
    pack_metadata_path = os.path.join(pack_path, PACKS_PACK_META_FILE_NAME)
    if not os.path.isfile(pack_metadata_path):
        return False
    pack_metadata = get_pack_metadata(pack_metadata_path)
    return pack_metadata.get(PACK_METADATA_SUPPORT, '').lower() == "xsoar"


def should_test_content_pack(pack_name: str) -> bool:
    """Checks if content pack should be tested in the build:
        - Content pack is not in skipped packs
        - Content pack is certified

    Args:
        pack_name (str): The pack name to check if it should be tested

    Returns:
        bool: True if should be tested, False otherwise
    """
    if not pack_name:
        return False
    pack_path = os.path.join(PACKS_DIR, pack_name)
    return pack_name not in SKIPPED_PACKS and is_pack_xsoar_supported(pack_path)
