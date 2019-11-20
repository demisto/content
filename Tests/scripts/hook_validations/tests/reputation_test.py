import os
from shutil import copyfile

import pytest

from Tests.scripts.hook_validations.reputation import ReputationValidator
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.tests_constants import VALID_REPUTATION_PATH, INVALID_REPUTATION_PATH


class TestReputationValidator:
    TARGET = "./Misc/reputations.json"
    INPUTS_IS_VALID_VERSION = [
        (VALID_REPUTATION_PATH, TARGET, True),
        (INVALID_REPUTATION_PATH, TARGET, False)
    ]

    @pytest.mark.parametrize('source, target, answer', INPUTS_IS_VALID_VERSION)
    def test_is_valid_version(self, source, target, answer):
        copyfile(source, target)
        structure = StructureValidator(source)
        reputation_validator = ReputationValidator(structure)
        assert reputation_validator.is_valid_version() is answer
        os.remove(target)
