import os
from shutil import copyfile

import pytest

from Tests.scripts.hook_validations.widget import WidgetValidator
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.tests_constants import VALID_WIDGET_PATH, INVALID_WIDGET_PATH


class TestWidgetValidator:
    TARGET = "./Widgets/widget-mocks.json"
    INPUTS_IS_VALID_VERSION = [
        (VALID_WIDGET_PATH, TARGET, True),
        (INVALID_WIDGET_PATH, TARGET, False)
    ]

    @pytest.mark.parametrize('source, target, answer', INPUTS_IS_VALID_VERSION)
    def test_is_valid_version(self, source, target, answer):
        copyfile(source, target)
        structure = StructureValidator(source)
        reputation_validator = WidgetValidator(structure)
        assert reputation_validator.is_valid_version() is answer
        os.remove(target)
