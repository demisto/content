from abc import abstractmethod

from Tests.scripts.error_constants import Errors
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.test_utils import print_error


class BaseValidator(object):
    DEFAULT_VERSION = -1

    def __init__(self, structure_validator):
        # type: (StructureValidator) -> None
        self.structure_validator = structure_validator
        self.current_file = structure_validator.current_file
        self.old_file = structure_validator.old_file
        self.file_path = structure_validator.file_path
        self.is_valid = structure_validator.is_valid

    def is_valid_file(self):
        self.is_valid_version()

    @abstractmethod
    def is_valid_version(self):
        # type: () -> bool
        pass

    def _is_valid_version(self):
        # type: () -> bool
        """Base is_valid_version method for files that version is their root.

        Return:
            True if version is valid, else False
        """
        if self.current_file.get('version') != self.DEFAULT_VERSION:
            print_error(Errors.wrong_version(self.file_path, self.DEFAULT_VERSION))
            self.is_valid = False
            return False
        return True
