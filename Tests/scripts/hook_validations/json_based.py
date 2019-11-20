from abc import abstractmethod

from Tests.scripts.hook_validations.structure import StructureValidator


class JSONBasedValidator(object):
    DEFAULT_VERSION = -1

    def __init__(self, structure_validator):
        # type: (StructureValidator) -> None
        self.structure_validator = structure_validator
        self.current_file = structure_validator.current_file
        self.file_path = structure_validator.file_path
        self.is_valid = structure_validator.is_valid

    def is_file_valid(self):
        self.is_valid_version()

    @abstractmethod
    def is_valid_version(self):
        # type: () -> bool
        pass
