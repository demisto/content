from Tests.scripts.constants import Errors
from Tests.scripts.hook_validations.base_validator import BaseValidator
from Tests.test_utils import print_error


class LayoutValidator(BaseValidator):
    def is_valid_version(self):
        # type: () -> bool
        """Return if version is valid. uses default method.

        Returns:
            True if version is valid, else False.
        """
        if self.current_file.get('layout', {}).get('version') != self.DEFAULT_VERSION:
            print_error(Errors.wrong_version(self.file_path, self.DEFAULT_VERSION))
            self.is_valid = False
            return False
        return True
