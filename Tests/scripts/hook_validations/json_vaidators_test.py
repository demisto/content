import os
from shutil import copyfile

import pytest
from typing import Any, Generic, Type

from Tests.scripts.hook_validations.base_validator import BaseValidator
from Tests.scripts.hook_validations.dashboard import DashboardValidator
from Tests.scripts.hook_validations.layout import LayoutValidator
from Tests.scripts.hook_validations.reputation import ReputationValidator
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.tests_constants import VALID_LAYOUT_PATH, INVALID_LAYOUT_PATH, \
    VALID_REPUTATION_PATH, INVALID_REPUTATION_PATH, VALID_WIDGET_PATH, INVALID_WIDGET_PATH, VALID_DASHBOARD_PATH, \
    INVALID_DASHBOARD_PATH
from Tests.scripts.hook_validations.widget import WidgetValidator


class TestValidators:
    LAYOUT_TARGET = "./Layouts/layout-mock.json"
    REPUTATION_TARGET = "./Misc/reputations.json"
    WIDGET_TARGET = "./Widgets/widget-mocks.json"
    DASHBOARD_TARGET = "./Dashboards/dashboard-mocks.json"
    INPUTS_IS_VALID_VERSION = [
        (VALID_LAYOUT_PATH, LAYOUT_TARGET, True, LayoutValidator),
        (INVALID_LAYOUT_PATH, LAYOUT_TARGET, False, LayoutValidator),
        (VALID_REPUTATION_PATH, REPUTATION_TARGET, True, ReputationValidator),
        (INVALID_REPUTATION_PATH, REPUTATION_TARGET, False, ReputationValidator),
        (VALID_WIDGET_PATH, WIDGET_TARGET, True, WidgetValidator),
        (INVALID_WIDGET_PATH, WIDGET_TARGET, False, WidgetValidator),
        (VALID_DASHBOARD_PATH, DASHBOARD_TARGET, True, DashboardValidator),
        (INVALID_DASHBOARD_PATH, DASHBOARD_TARGET, False, DashboardValidator)
    ]

    @pytest.mark.parametrize('source, target, answer, validator', INPUTS_IS_VALID_VERSION)
    def test_is_valid_version(self, source, target, answer, validator):
        # type: (str, str, Any, Type[BaseValidator]) -> None
        try:
            copyfile(source, target)
            structure = StructureValidator(source)
            validator = validator(structure)
            assert validator.is_valid_version() is answer
        finally:
            os.remove(target)
