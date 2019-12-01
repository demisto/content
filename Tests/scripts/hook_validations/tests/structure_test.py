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


single_line_good_rn = 'Some rn.'
single_line_bad_rn_1 = '  - Some rn.'
single_line_bad_rn_2 = 'Some rn'
single_line_list_good_rn = 'List rn.\n' \
                           '  - item #1.\n' \
                           '\t- item #2.'
single_line_list_bad_rn_1 = 'List rn.\n' \
                            '  -item #1.\n' \
                            '\t- item #2.'
single_line_list_bad_rn_2 = 'List rn.\n' \
                            '  item #1.\n' \
                            '\t- item #2.'
multi_line_good_rn = '  - comment 1.\n' \
                     '\t- comment 2..'
multi_line_bad_rn_1 = ' - comment 1\n' \
                      '  - comment 2.'
multi_line_bad_rn_2 = 'comment 1.\n' \
                      'comment 2.'
rn_structure_test_package = [(single_line_good_rn, True),
                             (single_line_bad_rn_1, False),
                             (single_line_bad_rn_2, False),
                             (single_line_list_good_rn, True),
                             (single_line_list_bad_rn_1, False),
                             (single_line_list_bad_rn_2, False),
                             (multi_line_good_rn, True),
                             (multi_line_bad_rn_1, False),
                             (multi_line_bad_rn_2, False)]


@pytest.mark.parametrize('rn, expected_result', rn_structure_test_package)
def test_rn_structure(rn, expected_result):
    assert StructureValidator.is_valid_rn_structure(rn) == expected_result
