import pytest
from json import load
from GroupIBTIA import (
    fetch_incidents_command,
    Client,
    main,
    get_available_collections_command,
)
import os
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
from cyberintegrations.utils import ParserHelper
from GroupIBTIA import TransformFieldsToMarkdown
import GroupIBTIA

# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)


BASE_URL = (
    "https://example.com"  # Replace this value before the tests. https://example.com
)
USERNAME = (
    "example@example.com"  # Replace this value before the tests. example@example.com
)
PASSWORD = "example"  # Replace this value before the tests. example

realpath = os.path.join(os.path.dirname(os.path.realpath(__file__)))
with open(f"{realpath}/test_data/example.json") as example:
    RAW_JSON = load(example)
with open(f"{realpath}/test_data/results.json") as results:
    RESULTS = load(results)


RESULTS.update(
    {
        "osi/git_repository": (
            (
                {"last_fetch": {"osi/git_repository": 1611862631144674}},
                [
                    {
                        "name": "Git Leak: https://github.com/somegit",
                        "occurred": "2021-01-28T22:32:54Z",
                        "rawJSON": '{"company": [], "companyId": [3150], "contributors": '
                        '[{"authorEmail": "some@email.com", "authorName": "somename"}, '
                        '{"authorEmail": "some@email.com", "authorName": "somename"}, '
                        '{"authorEmail": "some@email.com", "authorName": "somename"}], '
                        '"dataFound": {"password": 8, "apikey": 2, "secret": 1}, '
                        '"dateCreated": "2021-01-23T22:12:58+03:00", "dateDetected": '
                        '"2021-01-28T22:32:54+03:00", "evaluation": {"admiraltyCode": '
                        '"A1", "credibility": 50, "reliability": 50, "severity": '
                        '"orange", "tlp": "amber", "ttl": 30}, "favouriteForCompanies": '
                        '[], "files": "| URL  |   Author Email  | Author Name  | Date '
                        "Created| TimeStamp    |\\n| ---- | --------------- | "
                        "------------ | ----------- | ------------ |\\n| "
                        "https://github.com/somegit | some@email.com | TEST | "
                        '1970-01-01T03:00:00+03:00 | [1611429178] |\\n", '
                        '"hideForCompanies": [], "id": '
                        '"21aed9b86d2e6cbb15180d803a84f6d27f673db4", '
                        '"ignoreForCompanies": [], "isFavourite": false, "isHidden": '
                        'false, "isIgnore": false, "matchesTypes": [], "name": "Git '
                        'Leak: https://github.com/somegit", "numberOf": {"contributors": '
                        '3, "files": 10}, "relations": {"infobip.com": "some.com", '
                        '"Infobip": "some"}, "seqUpdate": 1611862631144674, "source": '
                        '"github", "gibType": "osi/git_repository", '
                        '"relatedIndicatorsData": [], "systemSeverity": 2}',
                    }
                ],
            )
        ),
        "osi/public_leak": (
            {"last_fetch": {"osi/public_leak": 1601909532153438}},
            [
                {
                    "name": "Public Leak: a9a5b5cb9b971a2a037e3a0a30654185ea148095",
                    "occurred": "2020-10-05T17:51:31Z",
                    "rawJSON": '{"bind": [], "created": "2020-10-05T17:51:31+03:00", "data": '
                    '"Pasted at: 05/10/2020 15:45", "displayOptions": null, '
                    '"evaluation": {"admiraltyCode": "C3", "credibility": 50, '
                    '"reliability": 50, "severity": "orange", "tlp": "amber", "ttl": '
                    '30}, "hash": "a9a5b5cb9b971a2a037e3a0a30654185ea148095", "id": '
                    '"a9a5b5cb9b971a2a037e3a0a30654185ea148095", "language": "c", '
                    '"linkList": "| Author | Date Detected | Date Published | Hash | Link | Source |\\n'
                    "| ------ | ------------- | -------------- | ---- |----- | ------ |\\n| whaaaaaat | "
                    "2020-10-05T17:51:31+03:00 | 2020-10-05T17:45:46+03:00 | "
                    "3066db9f57b7997607208fedc45d7203029d9cb3 | "
                    "[https://some.ru](https://some.ru) | some.ru "
                    '|\\n", "matches": "| Type | Sub Type | Value |\\n| ---- | -------- | ----- |\\n| email '
                    '| email | some@gmail.ru |\\n", '
                    '"oldId": null, '
                    '"portalLink": "https://bt.group-ib.com/osi/public_leak?'
                    'searchValue=id:a9a5b5cb9b971a2a037e3a0a30654186ea248094", '
                    '"seqUpdate": 1601909532153438, "size": "345 B", "updated": '
                    '"2020-10-05T17:51:31+03:00", "useful": 1, "name": '
                    '"Public Leak: a9a5b5cb9b971a2a037e3a0a30654185ea148095", "gibType": '
                    '"osi/public_leak", "relatedIndicatorsData": [], "systemSeverity": 2}',
                }
            ],
        ),
    }
)

COLLECTION_NAMES = [
    "compromised/card",
    "osi/git_repository",
    "osi/public_leak",
    "compromised/breached",
    "compromised/account_group",
]


@pytest.fixture(scope="function", params=COLLECTION_NAMES, ids=COLLECTION_NAMES)
def session_fixture(request):
    """
    Given:
      - A list of collection names from the integration

    When:
      - Using each collection name as a parameter to the session_fixture

    Then:
      - The fixture creates the expected client for each collection name
    """
    return request.param, Client(
        base_url=BASE_URL,
        auth=(USERNAME, PASSWORD),
        verify=True,
        headers={"Accept": "*/*"},
    )


def test_fetch_incidents(mocker, session_fixture):
    """
    Given:
    - Mocked API responses for fetch_incidents
    - last_run dict, first_fetch_time str, etc.

    When:
    - Calling fetch_incidents_command()

    Then:
    - next_run and incidents have expected types
    - Number of incidents matches mock response
    """
    collection_name, client = session_fixture
    mocker.patch.object(
        client, "create_poll_generator", return_value=[RAW_JSON[collection_name]]
    )
    next_run, incidents = fetch_incidents_command(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[],
        requests_count=3,
        hunting_rules=False
    )
    assert isinstance(incidents, list)


def test_main_error():
    """
    Given:
      - main() setup to raise an exception

    When:
      - Calling the error_command() via main()

    Then:
      - An exception is raised as expected
    """
    with pytest.raises(SystemExit):
        main()["error_command"]()  # type: ignore


def test_global_search_command(mocker, session_fixture):

    test_response = [
        {
            "apiPath": "suspicious_ip/open_proxy",
            "label": "Suspicious IP :: Open Proxy",
            "link": "",
            "count": 14,
            "time": 0.299055199,
            "detailedLinks": None,
        }
    ]

    collection_name, client = session_fixture
    mocker.patch.object(Client, "_http_request", return_value=test_response)
    mocker.patch.object(ParserHelper, "find_element_by_key", return_value=test_response)
    test_query = {"query": "test"}
    result = GroupIBTIA.global_search_command(client=client, args=test_query)

    assert result.outputs_prefix == "GIBTIA.search.global"
    assert result.outputs_key_field == "query"


def test_get_available_collections(mocker, session_fixture):
    """
    Given:
      - Mock client with a mocked get_available_collections method

    When:
      - Calling get_available_collections_command()

    Then:
      - Outputs prefix and key field are as expected
      - Result outputs is a list
    """
    collection_name, client = session_fixture
    mocker.patch.object(Client, "_http_request", return_value=RAW_JSON)
    mocker.patch.object(
        ParserHelper, "find_element_by_key", return_value=RAW_JSON[collection_name]
    )

    result = get_available_collections_command(client=client)

    assert result.outputs_prefix == "GIBTIA.OtherInfo"
    assert result.outputs_key_field == "collections"
    assert isinstance(result.outputs["collections"], list)


def test_find_element_by_key_nested_dict():
    """
    Given:
      - A nested input dict

    When:
      - Calling find_element_by_key() with a nested key

    Then:
      - The expected nested value is returned
    """
    test_dict = {"a": {"b": "value"}}
    result = ParserHelper.find_element_by_key(test_dict, "a.b")
    assert result == "value"


def test_find_element_by_key_list():
    """
    Given:
      - A list input

    When:
      - Calling find_element_by_key() to get all values of a key

    Then:
      - A list containing all values is returned
    """
    test_list = [{"a": "value1"}, {"a": "value2"}]
    result = ParserHelper.find_element_by_key(test_list, "a")
    assert len(result) == 2
    assert "value1" in result
    assert "value2" in result


def test_find_element_by_key_missing():
    """
    Given:
      - An input dict without the specified key

    When:
      - Calling find_element_by_key() with a missing key

    Then:
      - None is returned as expected
    """
    test_dict = {"a": 1}
    result = ParserHelper.find_element_by_key(test_dict, "b")
    assert result is None


def test_transform_some_fields_into_markdown():

    collection_name = "osi/git_repository"
    feed = {
        "revisions": [
            {
                "dataFound": [],
                "dateCreated": "1970-01-01T03:00:00+03:00",
                "dateDetected": "2021-01-28T19:37:08+00:00",
                "evaluation": {
                    "admiraltyCode": "A1",
                    "credibility": 30,
                    "reliability": 100,
                    "severity": "gray",
                    "tlp": "amber",
                    "ttl": 30
                },
                "id": "1212213123",
                "matchesType": [
                    "readme"
                ],
                "matchesTypeCount": {
                    "readme": 1
                },
                "name": "README.md",
                "revisions": [
                        {
                            "bind": [
                                {
                                    "bindBy": "",
                                    "companyId": 0,
                                    "data": "",
                                    "ruleId": 0,
                                    "type": "readme"
                                }
                            ],
                            "data": None,
                            "hash": "test",
                            "info": {
                                "authorEmail": "test@users.noreply.github.com",
                                "authorName": "ThreepreneurGlobal",
                                "timestamp": 1611429178
                            }
                        }
                ],
                "rules": None,
                "url": "https://github.com/test/README.md"
            },
        ]
    }

    expected_output = {
        "revisions": '| URL  |   Author Email  | Author Name  | Date Created  |   '
        'TimeStamp  |\n| ---- | --------------- | ------------ | ------------- | --'
        '---------- |\n| https://github.com/test/README.md | test@users.noreply.git'
        'hub.com | ThreepreneurGlobal | None | 1611429178 |\n'
    }

    result = TransformFieldsToMarkdown(
        collection_name=collection_name, feed=feed
    ).run_transform()

    assert result == expected_output


def test_transform_some_fields_into_markdown_public_leak():

    collection_name = "osi/public_leak"
    feed = {
        "linkList":
            {
                "author": ["John Doe"],
                "detected": ["2023-10-16"],
                "published": ["2023-10-15"],
                "hash": ["abcdef123456"],
                "link": ["https://example.com"],
                "source": ["Example Source"],
            },
        "matches": {
            "Type1": {"SubType1": ["Value1", "Value2"], "SubType2": ["Value3"]},
            "Type2": {"SubType3": ["Value4"]},
                },
    }

    expected_output = {
        'linkList': '| Author | Date Detected | Date Published | Hash | Link | '
        'Source |\n| ------ | ------------- | -------------- | ---- |----- | ---'
        '--- |\n| John Doe | 2023-10-16 | 2023-10-15 | abcdef123456 | '
        '[https://example.com](https://example.com) | Example Source |\n',
        'matches': '| Type | Sub Type | Value |\n| ---- | -------- | ----- |\n| Type1 '
        '| SubType1 | Value1 |\n| Type1 | SubType1 | Value2 |\n| Type1 | SubType2 | '
        'Value3 |\n| Type2 | SubType3 | Value4 |\n'}

    result = TransformFieldsToMarkdown(
        collection_name=collection_name, feed=feed
    ).run_transform()

    assert result == expected_output
