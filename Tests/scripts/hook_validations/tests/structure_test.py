import os
from shutil import copyfile

import pytest

from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.tests_constants import VALID_TEST_PLAYBOOK_PATH, INVALID_PLAYBOOK_PATH, \
    VALID_INTEGRATION_TEST_PATH, VALID_INTEGRATION_ID_PATH, INVALID_INTEGRATION_ID_PATH, VALID_PLAYBOOK_ID_PATH, \
    INVALID_PLAYBOOK_ID_PATH


class IsValidScheme:
    SCHEME_VALIDATION_INPUTS = [
        (VALID_TEST_PLAYBOOK_PATH, 'playbook', True, "Found a problem in the scheme although there is no problem"),
        (INVALID_PLAYBOOK_PATH, 'playbook', False, "Found no problem in the scheme although there is a problem")
    ]

    @pytest.mark.parametrize("path, scheme, answer, error", SCHEME_VALIDATION_INPUTS)
    def test_scheme_validation_playbook(self, path, scheme, answer, error, mocker):
        mocker.patch.object(StructureValidator, 'scheme_of_file_by_path', return_value=scheme)
        validator = StructureValidator(file_path=path)
        assert validator.is_valid_scheme() is answer, error


class TestIsValidFromversionOnModified:
    INPUTS = [
        (VALID_TEST_PLAYBOOK_PATH, "+ fromversion: sometext", False,
         "Didn't find the fromversion as updated in yml file"),
        (
            INVALID_PLAYBOOK_PATH, "+ \"fromVersion\": \"123", False,
            "Didn't find the fromVersion as updated in json file"),
        (INVALID_PLAYBOOK_PATH, "some other text", True, "Didn't find the fromversion as updated in yml file")
    ]

    @pytest.mark.parametrize('path, change_string, answer, error', INPUTS)
    def test_fromversion_update_validation_yml_structure(self, path, change_string, answer, error):
        validator = StructureValidator(file_path=path)
        assert validator.is_valid_fromversion_on_modified(change_string=change_string) is answer, error


class TestIsIDModified:
    IS_ID_MODIFIED_LIST = [
        (INVALID_PLAYBOOK_PATH, True, "+  id: text", "Didn't find the id as updated in file"),
        (INVALID_PLAYBOOK_PATH, True, "-  id: text", "Didn't find the id as updated in file"),
        (INVALID_PLAYBOOK_PATH, False, "some other text", "Found the ID as changed although it is not")
    ]

    @pytest.mark.parametrize("path, answer, change_string, error", IS_ID_MODIFIED_LIST)
    def test_is_id_modified(self, path, answer, change_string, error):
        validator = StructureValidator(file_path=path)
        assert validator.is_id_modified(change_string=change_string) is answer, error


class TestIsFileValid:
    INPUTS = [
        (
            VALID_TEST_PLAYBOOK_PATH, "Playbooks/playbook-test.yml", True, True,
            "Found a problem in the scheme although there is no problem"
        ),
        (
            VALID_INTEGRATION_TEST_PATH, "Integrations/integration-test.yml", False, False,
            "Didn't find a problem in the file although it is not valid"
        ),
    ]

    @pytest.mark.parametrize('source, target, answer, is_added_file, error', INPUTS)
    def test_valid_file_examination(self, source, target, answer, is_added_file, error):
        copyfile(source, target)
        validator = StructureValidator(file_path=target, is_added_file=is_added_file)
        assert validator.is_file_valid() is answer, error
        os.remove(target)


class TestIsFileIDWithoutSlashes:
    POSITIVE_ERROR = "Didn't find a slash in the ID even though it contains a slash."
    NEGATIVE_ERROR = "Didn't find a slash in the ID even though it contains a slash."
    INPUTS = [
        (VALID_INTEGRATION_ID_PATH, True, POSITIVE_ERROR),
        (INVALID_INTEGRATION_ID_PATH, False, NEGATIVE_ERROR),
        (VALID_PLAYBOOK_ID_PATH, True, POSITIVE_ERROR),
        (INVALID_PLAYBOOK_ID_PATH, False, NEGATIVE_ERROR)

    ]
    @pytest.mark.parametrize('path, answer, error', INPUTS)
    def test_integration_file_with_valid_id(self, path, answer, error):
        validator = StructureValidator(file_path=path)
        assert validator.is_file_id_without_slashes() is answer, error
