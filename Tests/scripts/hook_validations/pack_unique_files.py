"""
This module is designed to validate the existence and structure of content pack essential files in content.
"""
import os
import io
import re
import json

from Tests.test_utils import pack_name_to_path
from Tests.scripts.constants import PACKS_WHITELIST_FILE_NAME, PACKS_PACK_IGNORE_FILE_NAME, PACKS_PACK_META_FILE_NAME, \
    PACKS_README_FILE_NAME


class PackUniqueFilesValidator():
    """PackUniqueFilesValidator is designed to validate the correctness of pack's files structure.
    Existence and validity of this files is essential."""

    def __init__(self, pack):
        self.pack = pack
        self.pack_path = pack_name_to_path(self.pack)
        self.secrets_file = PACKS_WHITELIST_FILE_NAME
        self.pack_ignore_file = PACKS_PACK_IGNORE_FILE_NAME
        self.pack_meta_file = PACKS_PACK_META_FILE_NAME
        self.readme_file = PACKS_README_FILE_NAME
        self._errors = []

    # error handling
    def _add_error(self, error):
        """Adds error entry to a list under pack's name"""
        if error:
            self._errors.append(error)

    def get_errors(self, raw=False):
        """Get the dict version or string version for print"""
        errors = []
        if raw:
            errors = self._errors
        elif self._errors:
            errors = '@@@Issues with unique files in pack: {}\n  {}'.format(self.pack, '\n  '.join(self._errors))

        return errors

    # file utils
    def _get_pack_file_path(self, file_name=''):
        """Returns the full file path to pack's file"""
        return os.path.join(self.pack_path, file_name)

    def _is_pack_file_exists(self, file):
        """Check if .secrets-ignore exists"""
        if not os.path.isfile(self._get_pack_file_path(file)):
            self._add_error('"{}" file does not exist, create one in the root of the pack.'.format(file))
            return False

        return True

    # secrets validation
    def validate_secrets_file(self):
        """Validate everything related to .secrets-ignore file"""
        if self._is_pack_file_exists(self.secrets_file):
            self._is_secrets_file_structure_valid()

    def _is_secrets_file_structure_valid(self):
        """Check if .secrets-ignore structure is parse-able"""
        try:
            with io.open(self._get_pack_file_path(self.secrets_file), mode="r", encoding="utf-8") as secrets_file:
                if secrets_file.read().split('\n'):
                    return True
        except (IOError, ValueError):
            self._add_error('Could not parse the contents of "{}" file'.format(self.secrets_file))

        return False

    # pack ignore validation
    def validate_pack_ignore_file(self):
        """Validate everything related to .pack-ignore file"""
        if self._is_pack_file_exists(self.pack_ignore_file):
            self._is_pack_ignore_file_structure_valid()

    def _is_pack_ignore_file_structure_valid(self):
        """Check if .pack-ignore structure is parse-able & has valid regex"""
        try:
            with io.open(self._get_pack_file_path(self.pack_ignore_file), mode="r", encoding="utf-8") \
                    as pack_ignore_file:
                if all(re.compile(regex) for regex in pack_ignore_file.read().split('\n')):
                    return True
        except (IOError, ValueError):
            self._add_error('Could not fetch {} file contents'.format(self.pack_ignore_file))
        except re.error:
            self._add_error('Detected none valid regex in {} file'.format(self.pack_ignore_file))

        return False

    # pack metadata validation
    def validate_pack_meta_file(self):
        """Validate everything related to pack-metadata.json file"""
        if self._is_pack_file_exists(self.pack_meta_file):
            self._is_pack_meta_file_structure_valid()

    def _is_pack_meta_file_structure_valid(self):
        """Check if pack-metadata.json structure is json parse-able"""
        try:
            with io.open(self._get_pack_file_path(self.pack_meta_file), mode="r", encoding="utf-8") as pack_meta_file:
                if json.loads(pack_meta_file.read()):
                    return True
        except (IOError, ValueError):
            self._add_error('Could not parse {} file contents to json format'.format(self.pack_meta_file))

        return False

    # pack README.md validation
    def validate_readme_file(self):
        """Validate everything related to README.md file"""
        self._is_pack_file_exists(self.readme_file)

    def validate_pack_unique_files(self):
        """Main Execution Method"""
        self.validate_secrets_file()
        self.validate_pack_ignore_file()
        self.validate_pack_meta_file()
        self.validate_readme_file()
