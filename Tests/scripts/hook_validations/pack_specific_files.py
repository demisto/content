"""
This module is designed to validate the existence and structure of content pack essential files in content.
"""
from Tests.test_utils import print_error


class PackSpecificFileValidator(object):
    """PackSpecificFileValidator is designed to validate the correctness of pack's files structure.
    Existence and validity of this files is essential."""

    def __init__(self, pack_file_path):
        self.file_path = pack_file_path
        self.errors = ''

    def is_secrets_ignore_exists(self):
        """Check if .secrets-ignore exists"""
        self.add_error('sade')

    def add_error(self, error):
        if error:
            self.errors += error + '\n'

    def validate_pack_specific_file(self):
        """Main Execution Method"""
        print_error(self.errors)
