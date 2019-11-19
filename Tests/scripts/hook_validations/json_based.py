from abc import abstractmethod

from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.test_utils import get_json


class JSONBasedValidator(StructureValidator):
    def load_data_from_file(self):
        return get_json(self.file_path)

    @abstractmethod
    def is_valid_version(self, expected_file_version):
        pass
