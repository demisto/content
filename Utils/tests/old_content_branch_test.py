
from Utils.old_content_branch import should_keep_json_file, should_keep_yml_file, get_json, get_yaml

TEST_VERSION = "4.1.0"
JSON_SHOULD_STAY = '../../Packs/CommonReports/Reports/report-MTTRbyIncidentType2Quar.json'
YML_SHOULD_STAY = '../../Packs/ThinkstCanary/Integrations/ThinkstCanary/ThinkstCanary.yml'
JSON_SHOULD_DELETE = '../../Packs/NonSupported/Reports/report-dailyIncidentReport_3_1_0.json'
YML_SHOULD_DELETE = '../../Packs/CommonPlaybooks/Playbooks/playbook-Calculate_Severity_By_Highest_DBotScore.yml'


def test_handle_json__should_say():
    """
    Given
    - A path to a json file that should stay - lower fromVersion.

    When
    - Running should_keep_json_file on it.

    Then
    - function returns True (file should be updated).
    """
    json_content = get_json(JSON_SHOULD_STAY)
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
    json_content = get_json(JSON_SHOULD_DELETE)
    assert should_keep_json_file(json_content, TEST_VERSION, should_rewrite=False) is False


def test_handle_yml__should_stay():
    """
    Given
    - A path to a yml file that should stay - no fromversion.

    When
    - Running should_keep_yml_file on it.

    Then
    - function returns True (file should be updated)
    """
    yml_content = get_yaml(YML_SHOULD_STAY)
    assert should_keep_yml_file(yml_content, TEST_VERSION, should_rewrite=False) is True


def test_handle_yml__should_delete():
    """
    Given
    - A path to a yml file that shouldn't stay - higher fromversion.

    When
    - Running should_keep_yml_file on it.

    Then
    - function returns False (file should be deleted)
    """
    yml_content = get_yaml(YML_SHOULD_DELETE)
    assert should_keep_yml_file(yml_content, TEST_VERSION, should_rewrite=False) is False
