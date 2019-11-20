"""
This module is designed to validate the existence and structure of content pack essential files in content.
"""


class PackUniqueFilesValidator(object):
    """PackUniqueFilesValidator is designed to validate the correctness of pack's files structure.
    Existence and validity of this files is essential."""

    def __init__(self, packs):
        self.packs = packs
        self._errors = ''

    def is_secrets_ignore_exists(self):
        """Check if .secrets-ignore exists"""
        self.add_error('sade')

    def add_error(self, error):
        if error:
            self._errors += error + '\n'

    def get_errors(self):
        return self._errors

    def validate_pack_unique_files(self):
        """Main Execution Method"""
        pass
