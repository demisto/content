import json
from abc import abstractmethod

from Tests.scripts.hook_validations.structure import StructureValidator


class JSONBasedValidator(StructureValidator):
    @abstractmethod
    def is_valid_version(self):
        pass

    def is_file_valid(self, validate_rn=True):
        super(JSONBasedValidator, self).is_file_valid(validate_rn=validate_rn)

    def load_data_from_file(self, load_function=json.load):
        return super(JSONBasedValidator, self).load_data_from_file(load_function)