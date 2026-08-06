import demistomock as demisto
import pytest
from demisto_sdk.commands.common.constants import FileType
from GetIdsFromCustomContent import (
    filter_lists,
    get_content_details,
    get_custom_content_ids,
    get_file_displayed_name,
    get_included_ids_command,
    update_file_prefix,
)

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


@pytest.mark.parametrize(
    "file_type, parse_func, parsed_value, expected_name",
    [
        pytest.param(FileType.INTEGRATION, "get_yaml", {"display": "My Integration"}, "My Integration", id="integration-display"),
        pytest.param(FileType.SCRIPT, "get_yaml", {"name": "My Script"}, "My Script", id="script-name"),
        pytest.param(FileType.MAPPER, "get_json", {"name": "My Mapper"}, "My Mapper", id="mapper-dict-name"),
        pytest.param(FileType.OLD_CLASSIFIER, "get_json", {"brandName": "Old Brand"}, "Old Brand", id="old-classifier-brand"),
        pytest.param(FileType.LAYOUT, "get_json", {"TypeName": "My Layout"}, "My Layout", id="layout-typename"),
        pytest.param(FileType.REPUTATION, "get_json", {"id": "reputation-id"}, "reputation-id", id="reputation-id"),
    ],
)
def test_get_file_displayed_name_returns_expected_name(mocker, file_type, parse_func, parsed_value, expected_name):
    """
    Given:
        - A file of a specific content type whose parser returns a populated dict.
    When:
        - Running get_file_displayed_name.
    Then:
        - The displayed name is extracted from the type-appropriate field.
    """
    # Given: a detected file type and a mocked parser returning a populated dict
    mocker.patch("GetIdsFromCustomContent.find_type", return_value=file_type)
    mocker.patch(f"GetIdsFromCustomContent.{parse_func}", return_value=parsed_value)

    # When: resolving the displayed name
    result = get_file_displayed_name("some/path.json")

    # Then: the expected name is returned
    assert result == expected_name


def test_get_file_displayed_name_unknown_type_returns_file_name(mocker):
    """
    Given:
        - A file whose type is not recognized by find_type (returns None).
    When:
        - Running get_file_displayed_name.
    Then:
        - The file name (basename) is returned as a fallback.
    """
    # Given: find_type cannot classify the file
    mocker.patch("GetIdsFromCustomContent.find_type", return_value=None)

    # When: resolving the displayed name for a nested path
    result = get_file_displayed_name("some/nested/dir/my_file.json")

    # Then: the basename is returned
    assert result == "my_file.json"


@pytest.mark.parametrize(
    "input_name, expected_name",
    [
        pytest.param("playbook-MyPlaybook.yml", "MyPlaybook.yml", id="strip-playbook-prefix"),
        pytest.param("automation-MyScript.yml", "script-MyScript.yml", id="automation-to-script-prefix"),
        pytest.param("integration-MyIntegration.yml", "integration-MyIntegration.yml", id="no-change"),
    ],
)
def test_update_file_prefix(input_name, expected_name):
    """
    Given:
        - A custom-content file name with a specific export prefix.
    When:
        - Running update_file_prefix.
    Then:
        - The prefix is normalized to the on-disk content convention.
    """
    # Given / When: normalizing the prefix
    result = update_file_prefix(input_name)

    # Then: the expected normalized name is returned
    assert result == expected_name


def test_filter_lists_excludes_matching_ids():
    """
    Given:
        - An include list of id/name dicts and a list of ids to exclude.
    When:
        - Running filter_lists.
    Then:
        - Only items whose id is not in the exclude list remain.
    """
    # Given: an include list and ids to exclude
    include = [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}, {"id": "c", "name": "C"}]
    exclude = ["b"]

    # When: filtering
    result = filter_lists(include=include, exclude=exclude)

    # Then: the excluded id is removed, others remain
    assert result == [{"id": "a", "name": "A"}, {"id": "c", "name": "C"}]


def test_get_content_details_uses_detected_type_and_id(mocker, tmp_path):
    """
    Given:
        - A tar member whose file is detected by find_type and parsed to a dict with an id.
    When:
        - Running get_content_details.
    Then:
        - The detected entity type and the resolved id/name are returned.
    """
    # Given: a member that extracts to a small yaml file, with mocked SDK helpers
    member = mocker.Mock()
    member.name = "integration-pff.yml"

    extracted = mocker.Mock()
    extracted.read.return_value = b"id: pff\nname: pff"
    tar_handler = mocker.Mock()
    tar_handler.extractfile.return_value = extracted

    mocker.patch("GetIdsFromCustomContent.find_type", return_value=FileType.INTEGRATION)
    mocker.patch("GetIdsFromCustomContent.get_yaml", return_value={"id": "pff", "name": "pff"})
    mocker.patch("GetIdsFromCustomContent._get_file_id", return_value="pff")
    mocker.patch("GetIdsFromCustomContent.get_file_displayed_name", return_value="pff")

    # When: extracting the content details
    entity, id_name = get_content_details(tar_handler, member)

    # Then: the detected type and resolved id/name are returned
    assert entity == "integration"
    assert id_name == {"id": "pff", "name": "pff"}


def test_get_content_details_raises_when_extraction_fails(mocker):
    """
    Given:
        - A tar member whose extractfile returns None (cannot be extracted).
    When:
        - Running get_content_details.
    Then:
        - An exception is raised indicating the file could not be extracted.
    """
    # Given: a tar handler that fails to extract the member
    member = mocker.Mock()
    member.name = "integration-pff.yml"
    tar_handler = mocker.Mock()
    tar_handler.extractfile.return_value = None

    # When / Then: extraction failure raises
    with pytest.raises(Exception, match="Could not extract file"):
        get_content_details(tar_handler, member)


def test_get_custom_content_ids_raises_when_no_file_path(mocker):
    """
    Given:
        - demisto.getFilePath returns a result without a 'path'.
    When:
        - Running get_custom_content_ids.
    Then:
        - A ValueError is raised indicating the file path could not be found.
    """
    # Given: no path returned for the entry id
    mocker.patch.object(demisto, "getFilePath", return_value={"path": ""})

    # When / Then: a ValueError is raised
    with pytest.raises(ValueError, match="Could not find file path for entry id"):
        get_custom_content_ids("missing_entry_id")


def test_get_custom_content_ids_raises_when_entity_unparsable(mocker):
    """
    Given:
        - A tar with a member whose content type and id cannot be resolved.
    When:
        - Running get_custom_content_ids.
    Then:
        - An exception is raised naming the unparsable member.
    """
    # Given: a tar with a single member, and get_content_details yielding no entity/id
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "some.tar.gz"})
    member = mocker.Mock()
    member.name = "unknown-file.json"
    tar_handler = mocker.Mock()
    tar_handler.getmembers.return_value = [member]
    mocker.patch("GetIdsFromCustomContent.tarfile.open", return_value=tar_handler)
    mocker.patch("GetIdsFromCustomContent.get_content_details", return_value=("", {"id": None, "name": ""}))

    # When / Then: the unparsable member triggers an exception
    with pytest.raises(Exception, match="Could not parse content type and id from file name unknown-file.json"):
        get_custom_content_ids("some_entry_id")
