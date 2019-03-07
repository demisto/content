import os
import pytest
from shutil import copyfile

from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.constants import PLAYBOOK_REGEX


def test_scheme_validation_playbook():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-test.yml")

    assert validator.is_valid_scheme(matching_regex=PLAYBOOK_REGEX), \
        "Found a problem in the scheme although there is no problem"


def test_scheme_validation_invalid_playbook():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-invalid.yml")

    try:
        validator.is_valid_scheme(matching_regex=PLAYBOOK_REGEX)
    except TypeError as exc:
        pytest.raises(TypeError, exc)


def test_version_validation():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-test.yml")

    assert validator.is_valid_version(), \
        "Found an incorrect version although the version is -1"


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


def test_updated_id_validation():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-invalid.yml")

    change_string = "+  id: text"
    assert validator.is_id_not_modified(change_string=change_string) is False, \
        "Didn't find the id as updated in file"


def test_removed_id_validation():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-invalid.yml")

    change_string = "-  id: text"
    assert validator.is_id_not_modified(change_string=change_string) is False, \
        "Didn't find the id as updated in file"


def test_not_touched_id_validation():
    validator = StructureValidator(file_path="./Tests/setup/Playbooks.playbook-invalid.yml")

    change_string = "some other text"
    assert validator.is_id_not_modified(change_string=change_string), \
        "Found the ID as changed although it is not"


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
