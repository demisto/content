from Tests.scripts.error_constants import Errors
from Tests.scripts.hook_validations.base_validator import BaseValidator
from Tests.test_utils import print_error


class LayoutValidator(BaseValidator):
    def is_valid_version(self):
        # type: () -> bool
        """Return if version is valid. uses default method.

        Returns:
            True if version is valid, else False.
        """
        return self._is_valid_version()
