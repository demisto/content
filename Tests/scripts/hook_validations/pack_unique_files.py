"""
This module is designed to validate the existence and structure of content pack essential files in content.
"""
import os

from Tests.test_utils import pack_name_to_path
from Tests.scripts.constants import PACKS_WHITELIST_FILE_NAME


class PackUniqueFilesValidator(object):
    """PackUniqueFilesValidator is designed to validate the correctness of pack's files structure.
    Existence and validity of this files is essential."""

    def __init__(self, packs):
        self.packs = packs
        self._errors = {}
        self.current_pack = ''

    def add_error(self, error):
        """Adds error entry to a list under pack's name"""
        if error:
            if self.current_pack not in self._errors:
                self._errors[self.current_pack] = []
            self._errors[self.current_pack].append(error)

    def get_errors(self, raw=False):
        """Get the dict version or string version for print"""
        errors = ''
        if raw:
            errors = self._errors
        elif self._errors:
            errors = '@@@ Issues with unique files in packs:'
            for pack in self._errors:
                errors += ('\n~Pack Name: ' + pack + '\n    ')
                errors += '\n    '.join(self._errors[pack])

        return errors

    def validate_secrets_file(self):
        """Validate everything related to .secrets-ignore file"""
        self._is_secrets_file_exists()

    def _is_secrets_file_exists(self):
        """Check if .secrets-ignore exists"""
        pack_path = os.path.join(pack_name_to_path(self.current_pack), PACKS_WHITELIST_FILE_NAME)
        if not os.path.isfile(pack_path):
            self.add_error('".secrets-ignore" file does not exist, create one in the root of the pack.')

    def validate_pack_unique_files(self):
        """Main Execution Method"""
        for pack in self.packs:
            self.current_pack = pack
            self.validate_secrets_file()
