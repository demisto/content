import os
import pytest
from shutil import copyfile

from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.constants import PLAYBOOK_REGEX

INVALID_PLAYBOOK_PATH = "./Tests/setup/Playbooks.playbook-invalid.yml"
VALID_TEST_PLAYBOOK_PATH = "./Tests/setup/Playbooks.playbook-test.yml"

SCHEME_VALIDATION_INPUTS = [
    (VALID_TEST_PLAYBOOK_PATH, PLAYBOOK_REGEX, True, "Found a problem in the scheme although there is no problem"),
    (INVALID_PLAYBOOK_PATH, PLAYBOOK_REGEX, False, "Found no problem in the scheme although there is a problem")
]


@pytest.mark.parametrize("path, regex, answer, error", SCHEME_VALIDATION_INPUTS)
def test_scheme_validation_playbook(path, regex, answer, error):
    validator = StructureValidator(file_path=path)
    assert validator.is_valid_scheme(regex) is answer, error


VERSION_VALIDATION_INPUTS = [
    (VALID_TEST_PLAYBOOK_PATH, -1, True, "Found an incorrect version although the version is -1")
]


@pytest.mark.parametrize("path, version, answer, error", VERSION_VALIDATION_INPUTS)
def test_version_validation(path, version, answer, error):
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-test.yml")
    assert validator.is_valid_version(version) is answer, error


def test_incorrect_version_validation():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-invalid.yml")

    assert validator.is_valid_version() is False, \
        "Found an a correct version although the version is 123"


def test_fromversion_update_validation_yml_structure():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-test.yml")

    change_string = "+ fromversion: sometext"
    assert validator.is_valid_fromversion_on_modified(change_string=change_string) is False, \
        "Didn't find the fromversion as updated in yml file"


def test_fromversion_update_validation_json_structure():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-invalid.yml")

    change_string = "+ \"fromVersion\": \"123"
    assert validator.is_valid_fromversion_on_modified(change_string=change_string) is False, \
        "Didn't find the fromVersion as updated in json file"


def test_fromversion_no_update_validation():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-invalid.yml")

    change_string = "some other text"
    assert validator.is_valid_fromversion_on_modified(change_string=change_string), \
        "Didn't find the fromversion as updated in yml file"


IS_ID_MODIFIED_LIST = [
    (INVALID_PLAYBOOK_PATH, True, "+  id: text", "Didn't find the id as updated in file"),
    (INVALID_PLAYBOOK_PATH, True, "-  id: text", "Didn't find the id as updated in file"),
    (INVALID_PLAYBOOK_PATH, False, "some other text", "Found the ID as changed although it is not")
]


@pytest.mark.parametrize("path, answer, change_string, error", IS_ID_MODIFIED_LIST)
def test_is_id_modified(path, answer, change_string, error):
    validator = StructureValidator(file_path=path)
    assert validator.is_id_modified(change_string=change_string) is answer, error


def test_valid_file_examination():
    copyfile("./Tests/setup/Playbooks.playbook-test.yml", "Playbooks/playbook-test.yml")
    validator = StructureValidator(file_path="Playbooks/playbook-test.yml", is_added_file=True)

    assert validator.is_file_valid(), \
        "Found a problem in the scheme although there is no problem"

    os.remove("Playbooks/playbook-test.yml")


def test_invalid_file_examination():
    copyfile("./Tests/setup/integration-test.yml", "Integrations/integration-test.yml")
    validator = StructureValidator(file_path="Integrations/integration-test.yml")

    assert validator.is_file_valid() is False, \
        "Didn't find a problem in the file although it is not valid"

    os.remove("Integrations/integration-test.yml")


def test_integration_file_with_valid_id():
    validator = StructureValidator(file_path="./Tests/setup/integration-valid-id-test.yml")
    assert validator.is_file_id_without_slashes(), \
        "Found a slash in the file's ID even though it contains no slashes.."


def test_integration_file_with_invalid_id():
    validator = StructureValidator(file_path="./Tests/setup/integration-invalid-id-test.yml")
    assert not validator.is_file_id_without_slashes(), \
        "Didn't find a slash in the ID even though it contains a slash."


def test_playbook_file_with_valid_id():
    validator = StructureValidator(file_path="./Tests/setup/playbook-valid-id-test.yml")
    assert validator.is_file_id_without_slashes(), \
        "Didn't find a slash in the ID even though it contains a slash."


def test_playbook_file_with_invalid_id():
    validator = StructureValidator(file_path="./Tests/setup/playbook-invalid-id-test.yml")
    assert not validator.is_file_id_without_slashes(), \
        "Didn't find a slash in the ID even though it contains a slash."
