import os
from shutil import copyfile
from typing import Any, Type

import pytest

from Tests.scripts.hook_validations.base_validator import BaseValidator
from Tests.scripts.hook_validations.dashboard import DashboardValidator
from Tests.scripts.hook_validations.incident_field import IncidentFieldValidator
from Tests.scripts.hook_validations.layout import LayoutValidator
from Tests.scripts.hook_validations.reputation import ReputationValidator
from Tests.scripts.hook_validations.script import ScriptValidator
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.tests_constants import VALID_LAYOUT_PATH, INVALID_LAYOUT_PATH, \
    VALID_REPUTATION_PATH, INVALID_REPUTATION_PATH, VALID_WIDGET_PATH, INVALID_WIDGET_PATH, VALID_DASHBOARD_PATH, \
    VALID_SCRIPT_PATH, INVALID_SCRIPT_PATH, INVALID_DASHBOARD_PATH, VALID_INCIDENT_FIELD_PATH, \
    INVALID_INCIDENT_FIELD_PATH
from Tests.scripts.hook_validations.widget import WidgetValidator


class TestValidators:
    LAYOUT_TARGET = "./Layouts/layout-mock.json"
    REPUTATION_TARGET = "./Misc/reputations.json"
    WIDGET_TARGET = "./Widgets/widget-mocks.json"
    DASHBOARD_TARGET = "./Dashboards/dashboard-mocks.json"
    PLAYBOOK_TARGET = "Playbooks/playbook-test.yml"
    INTEGRATION_TARGET = "Integrations/integration-test.yml"
    INCIDENT_FIELD_TARGET = "IncidentFields/incidentfield-test.json"
    PLAYBOOK_PACK_TARGET = "Packs/Int/Playbooks/playbook-test.yml"
    SCRIPT_TARGET = "./Scripts/script-test.yml"
    INPUTS_IS_VALID_VERSION = [
        (VALID_LAYOUT_PATH, LAYOUT_TARGET, True, LayoutValidator),
        (INVALID_LAYOUT_PATH, LAYOUT_TARGET, False, LayoutValidator),
        (VALID_WIDGET_PATH, WIDGET_TARGET, True, WidgetValidator),
        (INVALID_WIDGET_PATH, WIDGET_TARGET, False, WidgetValidator),
        (VALID_DASHBOARD_PATH, DASHBOARD_TARGET, True, DashboardValidator),
        (INVALID_DASHBOARD_PATH, DASHBOARD_TARGET, False, DashboardValidator),
        (VALID_INCIDENT_FIELD_PATH, INCIDENT_FIELD_TARGET, True, IncidentFieldValidator),
        (INVALID_INCIDENT_FIELD_PATH, INCIDENT_FIELD_TARGET, False, IncidentFieldValidator),
        (INVALID_DASHBOARD_PATH, DASHBOARD_TARGET, False, DashboardValidator),
        (VALID_SCRIPT_PATH, SCRIPT_TARGET, True, ScriptValidator),
        (INVALID_SCRIPT_PATH, SCRIPT_TARGET, False, ScriptValidator),
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

    INPUTS_LOCKED_PATHS = [
        (VALID_REPUTATION_PATH, True, ReputationValidator),
        (INVALID_REPUTATION_PATH, False, ReputationValidator),
    ]

    @pytest.mark.parametrize('source, answer, validator', INPUTS_LOCKED_PATHS)
    def test_is_valid_version_locked_paths(self, source, answer, validator):
        """Tests locked path (as reputations.json) so we won't override the file"""
        structure = StructureValidator(source)
        validator = validator(structure)
        assert validator.is_valid_version() is answer

    @pytest.mark.parametrize('source, target, answer, validator', INPUTS_IS_VALID_VERSION)
    def test_is_file_valid(self, source, target, answer, validator):
        # type: (str, str, Any, Type[BaseValidator]) -> None
        try:
            copyfile(source, target)
            structure = StructureValidator(source)
            validator = validator(structure)
            assert validator.is_valid_file(validate_rn=False) is answer
        finally:
            os.remove(target)
