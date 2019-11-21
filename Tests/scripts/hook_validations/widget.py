from Tests.scripts.error_constants import Errors
from Tests.scripts.hook_validations.base_validator import BaseValidator
from Tests.test_utils import print_error


class WidgetValidator(BaseValidator):
    def is_valid_version(self):
        if self.current_file.get('version') != self.DEFAULT_VERSION:
            print_error(Errors.wrong_version(self.file_path, self.DEFAULT_VERSION))
            self.is_valid = False
            return False
        return True
