import os
from shutil import copyfile

import pytest

from Tests.scripts.hook_validations.layout import LayoutValidator
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.tests_constants import VALID_LAYOUT_PATH, INVALID_LAYOUT_PATH


class TestLayoutValidator:
    TARGET = "./Layouts/layout-mock.json"
    INPUTS_IS_VALID_VERSION = [
        (VALID_LAYOUT_PATH, TARGET, True),
        (INVALID_LAYOUT_PATH, TARGET, False)
    ]

    @pytest.mark.parametrize('source, target, answer', INPUTS_IS_VALID_VERSION)
    def test_is_valid_version(self, source, target, answer):
        copyfile(source, target)
        structure = StructureValidator(source)
        validator = LayoutValidator(structure)
        assert validator.is_valid_version() is answer
        os.remove(target)
