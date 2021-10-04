import os
from pathlib import PosixPath
from typing import Tuple, Union

import demisto_sdk.commands.common.tools as tools
from demisto_sdk.commands.common.constants import (PACK_METADATA_SUPPORT, PACKS_DIR, PACKS_PACK_META_FILE_NAME)

SKIPPED_PACKS = ['DeprecatedContent', 'NonSupported']
IGNORED_FILES = ['__init__.py', 'ApiModules', 'NonSupported']  # files to ignore inside Packs folder


def is_pack_xsoar_supported(file_path: Union[str, PosixPath]) -> bool:
    """Checks whether the file belongs to a pack that is XSOAR supported.
    Tests are not being collected for non XSOAR  packs.

    Args:
        file_path (Union[str, PosixPath]): The file path.

    Returns:
        True if the pack that the file path resides in is certified, False otherwise
    """
    str_file_path: str = str(file_path)
    pack_metadata = tools.get_pack_metadata(str_file_path)
    return pack_metadata.get(PACK_METADATA_SUPPORT, '').lower() == "xsoar"


def is_pack_deprecated(pack_path: str) -> bool:
    """Checks whether the pack is deprecated.
    Tests are not being collected for deprecated packs and the pack is not installed in the build process.

    Args:
        pack_path (str): The pack path

    Returns:
        True if the pack is deprecated, False otherwise
    """
    pack_metadata_path = os.path.join(pack_path, PACKS_PACK_META_FILE_NAME)
    if not os.path.isfile(pack_metadata_path):
        return True
    pack_metadata = tools.get_pack_metadata(pack_metadata_path)
    return pack_metadata.get('hidden', False)


def should_test_content_pack(pack_name: str) -> Tuple[bool, str]:
    """Checks if content pack should be tested in the build:
        - Content pack is not in skipped packs
        - Content pack is certified
        - Content pack is not deprecated

    Args:
        pack_name (str): The pack name to check if it should be tested

    Returns:
        bool: True if should be tested, False otherwise
    """
    if not pack_name:
        return False, 'Invalid pack name'
    pack_path = os.path.join(PACKS_DIR, pack_name)
    if pack_name in SKIPPED_PACKS:
        return False, 'Pack is either the "NonSupported" pack or the "DeprecatedContent" pack.'
    if not is_pack_xsoar_supported(pack_path):
        return False, 'Pack is not XSOAR supported'
    if is_pack_deprecated(pack_path):
        return False, 'Pack is Deprecated'
    return True, ''


def should_install_content_pack(pack_name: str) -> Tuple[bool, str]:
    """Checks if content pack should be installed:
        - Content pack is not in skipped packs
        - Content pack is not deprecated

    Args:
        pack_name (str): The pack name to check if it should be tested

    Returns:
        bool: True if should be installed, False otherwise
    """
    if not pack_name:
        return False, 'Invalid pack name'
    pack_path = os.path.join(PACKS_DIR, pack_name)
    if pack_name in SKIPPED_PACKS:
        return False, 'Pack is either the "NonSupported" pack or the "DeprecatedContent" pack.'
    if pack_name in IGNORED_FILES:
        return False, f'Pack should be ignored as it one of the files to ignore: {IGNORED_FILES}'
    if is_pack_deprecated(pack_path):
        return False, 'Pack is Deprecated'
    return True, ''
