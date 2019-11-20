import pytest

from Tests.scripts.hook_validations.reputation import ReputationValidator
from Tests.scripts.hook_validations.structure import StructureValidator


class TestIsVersion:
    INPUTS = [
        ()
    ]
    @pytest.mark.parametrize('path', INPUTS)
    def test_is_valid_version(self, path):
        structure = StructureValidator()