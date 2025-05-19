import pytest
from CommonServerPython import DemistoException
import demistomock as demisto  # noqa: F401
from GetAskLinks import get_ask_tasks, encode, generate_ask_link, get_ask_links_command
import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_ask_tasks(mocker):
    """Ensure get_ask_tasks returns expected output

    Given: an incident id: 1 and a mocked response object

    When:
        - sent to the get_ask_tasks

    Then:
        - assert the function returns the expected output
    """
    mocker.patch.object(demisto, "executeCommand", return_value=util_load_json("test_data/core-api-response.json"))
    result = get_ask_tasks("1")
    assert result == [{"id": "2", "options": ["Yes", "No"], "name": "Ask Question", "state": None}]

    mocker.patch.object(demisto, "executeCommand", return_value=None)
    with pytest.raises(DemistoException, match="No work plan found for the incident with id: 1"):
        get_ask_tasks("1")


@pytest.mark.parametrize("string, output", [("1@1", "4d554178")])
def test_encode(string, output):
    """Ensure encoding works as expected

    Given:
        string '1@1'

    When:
        sent to function encode

    Then:
        assert the encoded string is '4d554178'
    """
    assert encode(string) == output


@pytest.mark.parametrize(
    "server, task_id, investigation_id, email, option, output",
    [
        (
            "https://test-address:8443/",
            1,
            1,
            "ask@soar",
            "option",
            {
                "link": "https://test-address:8443/#/external/ask/4d554178/59584e7251484e765958493d/6233423061573975",
                "option": "option",
                "taskID": 1,
            },
        )
    ],
)
def test_generate_ask_link(server, task_id, investigation_id, email, option, output):
    """Test the Link generation returns the expected output

    Given:
        - server: https://test-address:8443/
        - task_id : 1
        - investigation_id: 1
        - email: ask@soar
        - option: option

    When:
        sent to generate_ask_list

    Then:
        assert the returned dict matches the expected output
    """
    assert generate_ask_link(server, task_id, investigation_id, email, option) == output


def test_get_ask_links_command(mocker):
    """Ensure get_ask_links_command returns expected output

    Given: an incident id: 1 and a mocked response object

    When:
        - sent to the get_ask_links_command

    Then:
        - assert the function returns the expected output
    """
    mocker.patch.object(demisto, "executeCommand", return_value=util_load_json("test_data/core-api-response.json"))
    mocker.patch.object(demisto, "investigation", return_value={"id": 1})
    args = {"task_name": "Ask Question"}
    result = get_ask_links_command(args)
    assert result.outputs == [
        {
            "link": "https://test-address:8443/#/external/ask/4d554179/59584e725148687a62324679/5757567a",
            "option": "Yes",
            "taskID": "2",
            "taskName": "Ask Question",
        },
        {
            "link": "https://test-address:8443/#/external/ask/4d554179/59584e725148687a62324679/546d383d",
            "option": "No",
            "taskID": "2",
            "taskName": "Ask Question",
        },
    ]
    assert (
        result.readable_output
        == (
            '### External ask links for task "Ask Question" in investigation 1\n'
            "|link|option|taskID|\n"
            "|---|---|---|\n"
            "| https://test-address:8443/#/external/ask/4d554179/59584e725148687a62324679/5757567a | Yes | 2 |\n"  # noqa: E501
            "| https://test-address:8443/#/external/ask/4d554179/59584e725148687a62324679/546d383d | No | 2 |\n"
        )
    )  # noqa: E501

    with pytest.raises(ValueError, match='no matching Ask task found for "Some Task"'):
        get_ask_links_command({"task_name": "Some Task"})
