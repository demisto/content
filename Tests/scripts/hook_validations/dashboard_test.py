import os
from shutil import copyfile

import pytest

from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.tests_constants import VALID_DASHBOARD_PATH, INVALID_DASHBOARD_PATH
from Tests.scripts.hook_validations.widget import WidgetValidator


class TestWidgetValidator:
    TARGET = "./Dashboards/dashboard-mocks.json"
    INPUTS_IS_VALID_VERSION = [
        (VALID_DASHBOARD_PATH, TARGET, True),
        (INVALID_DASHBOARD_PATH, TARGET, False)
    ]

    @pytest.mark.parametrize('source, target, answer', INPUTS_IS_VALID_VERSION)
    def test_is_valid_version(self, source, target, answer):
        copyfile(source, target)
        structure = StructureValidator(source)
        reputation_validator = WidgetValidator(structure)
        assert reputation_validator.is_valid_version() is answer
        os.remove(target)
