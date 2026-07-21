import demistomock as demisto
import pytest
from demisto_sdk.commands.common.constants import FileType
from GetIdsFromCustomContent import get_file_displayed_name, get_included_ids_command

EXAMPLE_CUSTOM_CONTENT_PATH = "test_data/content-bundle-for-test.tar.gz"
EXAMPLE_CUSTOM_CONTENT_NAME = "content-bundle-for-test.tar.gz"
IDS_IN_EXAMPLE_CONFIG = {
    "included_ids": {
        "dashboard": ["e499e9c3-0383-46ce-831d-98c3d501641d"],
        "incidentfield": ["incident_xdrfilename"],
        "incidenttype": ["TOPdesk Incident"],
        "indicatorfield": ["indicator_xdrstatus"],
        "integration": ["pff"],
        "layoutscontainer": ["Carbon Black EDR Incidents"],
        "list": ["list1"],
        "mapper": ["TOPdesk-incoming-mapper"],
        "playbook": ["UnzipFile-Test"],
        "pre-process-rule": ["1e61a15a-1c1e-481c-8d78-211c99099c23"],
        "report": ["4a62cafd-03f1-4a02-85b2-d6b58ec8184f"],
        "reputation": ["7c7f69e3-56d4-4d13-8285-8bf10d4949b4"],
        "script": ["ZipStrings"],
        "widget": ["0b674563-66ca-4c41-8eac-134722296026"],
    },
    "excluded_ids": {},
}


@pytest.mark.parametrize(
    "exclude_ids_list, expected_outputs",
    [
        pytest.param([], IDS_IN_EXAMPLE_CONFIG, id="exclude none"),
        pytest.param(
            [
                {
                    "dashboard": ["e499e9c3-0383-46ce-831d-98c3d501641d"],
                    "incidentfield": ["incident_xdrfilename"],
                    "incidenttype": ["TOPdesk Incident"],
                    "indicatorfield": ["indicator_xdrstatus"],
                    "integration": ["pff"],
                    "layoutscontainer": ["Carbon Black EDR Incidents"],
                    "list": ["list1"],
                    "mapper": ["TOPdesk-incoming-mapper"],
                    "playbook": ["UnzipFile-Test"],
                    "pre-process-rule": ["1e61a15a-1c1e-481c-8d78-211c99099c23"],
                    "report": ["4a62cafd-03f1-4a02-85b2-d6b58ec8184f"],
                    "reputation": ["7c7f69e3-56d4-4d13-8285-8bf10d4949b4"],
                    "script": ["ZipStrings"],
                    "widget": ["0b674563-66ca-4c41-8eac-134722296026"],
                }
            ],
            {"excluded_ids": {}, "included_ids": {}},
            id="exclude all",
        ),
        pytest.param(
            [{"dashboard": ["e499e9c3-0383-46ce-831d-98c3d501641d"]}],
            {
                "included_ids": {
                    "incidentfield": ["incident_xdrfilename"],
                    "incidenttype": ["TOPdesk Incident"],
                    "indicatorfield": ["indicator_xdrstatus"],
                    "integration": ["pff"],
                    "layoutscontainer": ["Carbon Black EDR Incidents"],
                    "list": ["list1"],
                    "mapper": ["TOPdesk-incoming-mapper"],
                    "playbook": ["UnzipFile-Test"],
                    "pre-process-rule": ["1e61a15a-1c1e-481c-8d78-211c99099c23"],
                    "report": ["4a62cafd-03f1-4a02-85b2-d6b58ec8184f"],
                    "reputation": ["7c7f69e3-56d4-4d13-8285-8bf10d4949b4"],
                    "script": ["ZipStrings"],
                    "widget": ["0b674563-66ca-4c41-8eac-134722296026"],
                },
                "excluded_ids": {},
            },
            id="exclude 1",
        ),
    ],
)
def test_get_included_ids_command(mocker, exclude_ids_list, expected_outputs):
    """
    Given:
        An example custom content file.

    When:
        Running GetIdsFromCustomContent.

    Then:
        Assert the right ids are returned.
    """
    mocker.patch.object(
        demisto, "getFilePath", return_value={"path": EXAMPLE_CUSTOM_CONTENT_PATH, "name": EXAMPLE_CUSTOM_CONTENT_NAME}
    )

    args = {"file_entry_id": "some_id", "exclude_ids_list": exclude_ids_list}
    response = get_included_ids_command(args)
    assert response.outputs == expected_outputs


@pytest.mark.parametrize(
    "custom_content_ids, exclude_ids_list, expected_outputs",
    [
        pytest.param(
            {
                "dashboard": [
                    {"id": "dashboard1", "name": "dashboard1"},
                    {"id": "dashboard2", "name": "dashboard2"},
                    {"id": "dashboard3", "name": "dashboard3"},
                ]
            },
            [{"dashboard": ["dashboard1"]}, {"dashboard": ["dashboard2"]}],
            {"included_ids": {"dashboard": ["dashboard3"]}, "excluded_ids": {}},
            id="exclude dashboard1, dashboard2, include dashboard3",
        ),
        pytest.param(
            {"dashboard": [{"id": "dashboard1", "name": "dashboard1"}]},
            [{"report": ["report1"]}],
            {"included_ids": {"dashboard": ["dashboard1"]}, "excluded_ids": {"report": ["report1"]}},
            id="include dashboard1, exclude report1",
        ),
        pytest.param(
            {},
            [{"report": ["report1"]}, {"report": ["report2", "report3"]}],
            {"included_ids": {}, "excluded_ids": {"report": ["report1", "report2", "report3"]}},
            id="include dashboard1, exclude report1",
        ),
    ],
)
def test_get_included_ids_with_excluded(mocker, custom_content_ids, exclude_ids_list, expected_outputs):
    """
    Given:
        An example custom content file.
        An excluded_ids_list.

    When:
        Running GetIdsFromCustomContent.

    Then:
        Assert the right ids are returned.
    """
    mocker.patch("GetIdsFromCustomContent.get_custom_content_ids", return_value=custom_content_ids)

    args = {"file_entry_id": "some_id", "exclude_ids_list": exclude_ids_list}
    response = get_included_ids_command(args)
    assert response.outputs == expected_outputs


def test_get_included_ids_with_bad_excluded_ids():
    """
    Given:
        A bad excluded_ids_list.

    When:
        Running GetIdsFromCustomContent.

    Then:
        Assert exception is raised and a relevant error message is printed.
    """
    args = {"file_entry_id": "some_id", "exclude_ids_list": "not at all a json ::"}
    with pytest.raises(ValueError) as err:
        get_included_ids_command(args)
    assert "Failed decoding excluded_ids_list as json" in str(err.value)


@pytest.mark.parametrize(
    "file_type, parse_func",
    [
        pytest.param(FileType.INTEGRATION, "get_yaml", id="integration-yaml-none"),
        pytest.param(FileType.SCRIPT, "get_yaml", id="script-yaml-none"),
        pytest.param(FileType.PLAYBOOK, "get_yaml", id="playbook-yaml-none"),
        pytest.param(FileType.MAPPER, "get_json", id="mapper-json-none"),
        pytest.param(FileType.OLD_CLASSIFIER, "get_json", id="old-classifier-json-none"),
        pytest.param(FileType.LAYOUT, "get_json", id="layout-json-none"),
        pytest.param(FileType.REPUTATION, "get_json", id="reputation-json-none"),
    ],
)
def test_get_file_displayed_name_handles_none_parse(mocker, file_type, parse_func):
    """
    Given:
        A file whose YAML/JSON parser returns None (empty/unparseable content).

    When:
        Running get_file_displayed_name.

    Then:
        An empty string is returned instead of raising AttributeError on None.
    """
    mocker.patch("GetIdsFromCustomContent.find_type", return_value=file_type)
    mocker.patch(f"GetIdsFromCustomContent.{parse_func}", return_value=None)

    assert get_file_displayed_name("some/path") == ""


def test_get_file_displayed_name_json_list_none_first_element(mocker):
    """
    Given:
        A JSON file that parses to a list whose first element is not a dict.

    When:
        Running get_file_displayed_name.

    Then:
        An empty string is returned instead of raising on res[0].get(...).
    """
    mocker.patch("GetIdsFromCustomContent.find_type", return_value=FileType.MAPPER)
    mocker.patch("GetIdsFromCustomContent.get_json", return_value=[None])

    assert get_file_displayed_name("some/path") == ""


def test_get_file_displayed_name_json_empty_list(mocker):
    """
    Given:
        A JSON file that parses to an empty list.

    When:
        Running get_file_displayed_name.

    Then:
        An empty string is returned instead of raising IndexError on res[0].
    """
    mocker.patch("GetIdsFromCustomContent.find_type", return_value=FileType.MAPPER)
    mocker.patch("GetIdsFromCustomContent.get_json", return_value=[])

    assert get_file_displayed_name("some/path") == ""


def test_get_file_displayed_name_json_list_of_dicts(mocker):
    """
    Given:
        A JSON file that parses to a list of dicts.

    When:
        Running get_file_displayed_name.

    Then:
        The name from the first element is returned (existing behavior preserved).
    """
    mocker.patch("GetIdsFromCustomContent.find_type", return_value=FileType.MAPPER)
    mocker.patch("GetIdsFromCustomContent.get_json", return_value=[{"name": "MyMapper"}])

    assert get_file_displayed_name("some/path") == "MyMapper"
