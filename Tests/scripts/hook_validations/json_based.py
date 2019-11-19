import json
from abc import abstractmethod

from Tests.scripts.hook_validations.structure import StructureValidator


class JSONBasedValidator(StructureValidator):
    @abstractmethod
    def is_valid_version(self):
        pass