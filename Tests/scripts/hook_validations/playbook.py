import re

from Tests.scripts.hook_validations.error_constants import Errors
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.test_utils import get_yaml, print_error


class PlaybookValidator(StructureValidator):
    scheme_name = 'playbook'

    def __init__(self, file_path, **kwargs):
        super(PlaybookValidator, self).__init__(file_path, **kwargs)
        self.current_file = get_yaml(file_path)

    def is_file_valid(self, validate_rn=True, *args, **kwargs):
        self.is_scheme_valid(self.scheme_name)
        self.is_valid_path()
        self.is_valid_version()

    def is_valid_version(self, expected_file_version=-1):
        if self.current_file.get('version') != -1:
            print_error(Errors.wrong_version(self.file_path, expected_file_version))
            self.is_valid = False
            return False
        return True

    def is_valid_path(self):
        if any([re.search()])
