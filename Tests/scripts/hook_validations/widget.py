from Tests.scripts.hook_validations.base_validator import BaseValidator


class WidgetValidator(BaseValidator):
    def is_valid_version(self):
        """Return if version is valid. uses default method.

        Returns:
            True if version is valid, else False.
        """
        return self._is_valid_version()
