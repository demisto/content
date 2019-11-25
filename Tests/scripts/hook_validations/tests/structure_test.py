import os
from os.path import isfile
from shutil import copyfile
from typing import List, Tuple

import pytest
import yaml

from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.tests.validators_test import TestValidators
from Tests.scripts.hook_validations.tests_constants import VALID_TEST_PLAYBOOK_PATH, INVALID_PLAYBOOK_PATH, \
    VALID_INTEGRATION_TEST_PATH, VALID_INTEGRATION_ID_PATH, INVALID_INTEGRATION_ID_PATH, VALID_PLAYBOOK_ID_PATH, \
    INVALID_PLAYBOOK_ID_PATH, VALID_REPUTATION_PATH, VALID_LAYOUT_PATH, INVALID_LAYOUT_PATH, INVALID_WIDGET_PATH, \
    VALID_WIDGET_PATH, VALID_DASHBOARD_PATH, INVALID_DASHBOARD_PATH, INVALID_REPUTATION_PATH


class TestStructureValidator:
    SCHEME_VALIDATION_INPUTS = [
        (VALID_TEST_PLAYBOOK_PATH, 'playbook', True, "Found a problem in the scheme although there is no problem"),
        (INVALID_PLAYBOOK_PATH, 'playbook', False, "Found no problem in the scheme although there is a problem")
    ]

    @pytest.mark.parametrize("path, scheme, answer, error", SCHEME_VALIDATION_INPUTS)
    def test_scheme_validation_playbook(self, path, scheme, answer, error, mocker):
        mocker.patch.object(StructureValidator, 'scheme_of_file_by_path', return_value=scheme)
        validator = StructureValidator(file_path=path)
        assert validator.is_valid_scheme() is answer, error

    INPUTS_VALID_FROM_VERSION_MODIFIED = [
        (VALID_TEST_PLAYBOOK_PATH, INVALID_PLAYBOOK_PATH, False),
        (INVALID_PLAYBOOK_PATH, VALID_PLAYBOOK_ID_PATH, False),
        (INVALID_PLAYBOOK_PATH, INVALID_PLAYBOOK_PATH, True)
    ]

    @pytest.mark.parametrize('path, old_file_path, answer', INPUTS_VALID_FROM_VERSION_MODIFIED)
    def test_fromversion_update_validation_yml_structure(self, path, old_file_path, answer):
        validator = StructureValidator(file_path=path)
        with open(old_file_path) as f:
            validator.old_file = yaml.safe_load(f)
            assert validator.is_valid_fromversion_on_modified() is answer

    INPUTS_IS_ID_MODIFIED = [
        (INVALID_PLAYBOOK_PATH, VALID_PLAYBOOK_ID_PATH, True, "Didn't find the id as updated in file"),
        (VALID_PLAYBOOK_ID_PATH, VALID_PLAYBOOK_ID_PATH, False, "Found the ID as changed although it is not")
    ]

    @pytest.mark.parametrize("current_file, old_file, answer, error", INPUTS_IS_ID_MODIFIED)
    def test_is_id_modified(self, current_file, old_file, answer, error):
        validator = StructureValidator(file_path=current_file)
        with open(old_file) as f:
            validator.old_file = yaml.safe_load(f)
            assert validator.is_id_modified() is answer, error

    POSITIVE_ERROR = "Didn't find a slash in the ID even though it contains a slash."
    NEGATIVE_ERROR = "found a slash in the ID even though it not contains a slash."
    INPUTS_IS_FILE_WITHOUT_SLASH = [
        (VALID_INTEGRATION_ID_PATH, True, POSITIVE_ERROR),
        (INVALID_INTEGRATION_ID_PATH, False, NEGATIVE_ERROR),
        (VALID_PLAYBOOK_ID_PATH, True, POSITIVE_ERROR),
        (INVALID_PLAYBOOK_ID_PATH, False, NEGATIVE_ERROR)

    ]

    @pytest.mark.parametrize('path, answer, error', INPUTS_IS_FILE_WITHOUT_SLASH)
    def test_integration_file_with_valid_id(self, path, answer, error):
        validator = StructureValidator(file_path=path)
        assert validator.is_file_id_without_slashes() is answer, error

    INPUTS_IS_PATH_VALID = [
        ("Reports/report-sade.json", True),
        ("Notinregex/report-sade.json", False),
        ("Packs/Test/Integrations/Cymon/Cymon.yml", True),
    ]

    @pytest.mark.parametrize('path, answer', INPUTS_IS_PATH_VALID)
    def test_is_valid_file_path(self, path, answer, mocker):
        mocker.patch.object(StructureValidator, "load_data_from_file", return_value=None)
        structure = StructureValidator(path)
        structure.scheme_name = None
        assert structure.is_valid_file_path() is answer

    INPUTS_IS_VALID_FILE = [
        (VALID_LAYOUT_PATH, TestValidators.LAYOUT_TARGET, True),
        (INVALID_LAYOUT_PATH, TestValidators.LAYOUT_TARGET, False),
        (INVALID_WIDGET_PATH, TestValidators.WIDGET_TARGET, False),
        (VALID_WIDGET_PATH, TestValidators.WIDGET_TARGET, True),
        (VALID_DASHBOARD_PATH, TestValidators.DASHBOARD_TARGET, True),
        (INVALID_DASHBOARD_PATH, TestValidators.DASHBOARD_TARGET, False),
        (VALID_TEST_PLAYBOOK_PATH, TestValidators.PLAYBOOK_TARGET, True),
        (VALID_INTEGRATION_TEST_PATH, TestValidators.INTEGRATION_TARGET, True),
        (INVALID_PLAYBOOK_PATH, TestValidators.INTEGRATION_TARGET, False),
    ]  # type: List[Tuple[str, str, bool]]

    @pytest.mark.parametrize('source, target, answer', INPUTS_IS_VALID_FILE)
    def test_is_file_valid(self, source, target, answer):
        try:
            copyfile(source, target)
            structure = StructureValidator(target)
            assert structure.is_valid_file() is answer
        finally:
            os.remove(target)

    INPUTS_LOCKED_PATHS = [
        (VALID_REPUTATION_PATH, "reputations", True),
        (INVALID_REPUTATION_PATH, "reputations", False),
    ]

    @pytest.mark.parametrize('source, scheme_name, answer', INPUTS_LOCKED_PATHS)
    def test_is_file_valid_locked_paths(self, source, scheme_name, answer, mocker):
        """Tests locked path (as reputations.json) so we won't override the file"""
        mocker.patch.object(StructureValidator, "is_valid_file_path", return_value=answer)
        structure = StructureValidator(source)
        StructureValidator.scheme_name = scheme_name
        assert structure.is_valid_file() is answer


class TestGeneral:
    INPUTS = [
        TestValidators.LAYOUT_TARGET,
        TestValidators.DASHBOARD_TARGET,
        TestValidators.WIDGET_TARGET,
        TestValidators.PLAYBOOK_TARGET,
        TestValidators.INTEGRATION_TARGET,
        TestValidators.INCIDENT_FIELD_TARGET,
        TestValidators.PLAYBOOK_PACK_TARGET,
    ]

    @pytest.mark.parametrize('target', INPUTS)
    def test_file_not_exists_on_test_path(self, target):
        """Check that all the paths used for tests are'nt exists so we won't break builds #MakesSadeHappy"""
        assert isfile(target) is False
