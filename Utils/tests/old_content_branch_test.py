
from Utils.old_content_branch import should_keep_json_file, should_keep_yml_file, edit_playbooks_directory, ryaml
import json
import shutil
TEST_VERSION = "5.1.9"
JSON_SHOULD_STAY = 'Packs/CommonReports/Reports/report-MTTRbyIncidentType2Quar.json'
YML_SHOULD_STAY = 'Packs/ThinkstCanary/Integrations/ThinkstCanary/ThinkstCanary.yml'
JSON_SHOULD_DELETE = 'Utils/tests/test_data_old_content/json_should_delete.json'
YML_SHOULD_DELETE = 'Packs/CommonPlaybooks/Playbooks/playbook-Calculate_Severity_By_Highest_DBotScore.yml'
TEST_TPB = 'Utils/tests/test_data_old_content/temp_test_playbook.yml'


def test_handle_json__should_stay():
    """
    Given
    - A path to a json file that should stay - lower fromVersion.

    When
    - Running should_keep_json_file on it.

    Then
    - function returns True (file should be updated).
    """
    with open(JSON_SHOULD_STAY, 'r') as json_file:

        json_content = json.loads(json_file.read())
    assert should_keep_json_file(json_content, TEST_VERSION) is True


def test_handle_json__should_delete():
    """
    Given
    - A path to a json file that shouldn't stay - lower toVersion.

    When
    - Running should_keep_json_file on it.

    Then
    - function returns False (file should be deleted).
    """
    with open(JSON_SHOULD_DELETE, 'r') as json_file:
        json_content = json.loads(json_file.read())
    assert should_keep_json_file(json_content, TEST_VERSION) is False


def test_handle_yml__should_stay():
    """
    Given
    - A path to a yml file that should stay - no fromversion.

    When
    - Running should_keep_yml_file on it.

    Then
    - function returns True (file should be updated)
    """
    with open(YML_SHOULD_STAY, 'r') as yml_file:

        yml_content = ryaml.load(yml_file)
    assert should_keep_yml_file(yml_content, TEST_VERSION) is True


def test_handle_yml__should_delete():
    """
    Given
    - A path to a yml file that shouldn't stay - higher fromversion.

    When
    - Running should_keep_yml_file on it.

    Then
    - function returns False (file should be deleted)
    """
    with open(YML_SHOULD_DELETE, 'r') as yml_file:

        yml_content = ryaml.load(yml_file)
    assert should_keep_yml_file(yml_content, TEST_VERSION) is True


def test_edit_playbooks_directory(tmp_path):
    """
    Given
    - A path to a tpb that should stay and its toversion field should change to 4.1.9.

    When
    - Running edit_playbooks_directory on it.

    Then
    - Tpb should be updated with a new toversion field.
    """
    tmp_tpb = shutil.copyfile(TEST_TPB, f"{tmp_path}/tpb.yml")

    edit_playbooks_directory(TEST_VERSION, tmp_path)
    with open(tmp_tpb, 'r') as yml_file:
        yml_content = ryaml.load(yml_file)
    assert yml_content['toversion'] == '5.1.9'
