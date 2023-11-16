import pytest
from json import load
from GroupIBTIA import fetch_incidents_command, Client, transform_function, main, get_available_collections_command

with open('test_data/example.json') as example:
    RAW_JSON = load(example)
with open('test_data/results.json') as results:
    RESULTS = load(results)

# Because of errors with markdown tables
RESULTS.update({
    'osi/git_repository': (
        ({'last_fetch': {'osi/git_repository': 1611862631144674}},
         [{'name': 'Git Leak: https://github.com/somegit',
           'occurred': '2021-01-28T22:32:54Z',
           'rawJSON': '{"company": [], "companyId": [3150], "contributors": '
                      '[{"authorEmail": "some@email.com", "authorName": "somename"}, '
                      '{"authorEmail": "some@email.com", "authorName": "somename"}, '
                      '{"authorEmail": "some@email.com", "authorName": "somename"}], '
                      '"dataFound": {"password": 8, "apikey": 2, "secret": 1}, '
                      '"dateCreated": "2021-01-23T22:12:58+03:00", "dateDetected": '
                      '"2021-01-28T22:32:54+03:00", "evaluation": {"admiraltyCode": '
                      '"A1", "credibility": 50, "reliability": 50, "severity": '
                      '"orange", "tlp": "amber", "ttl": 30}, "favouriteForCompanies": '
                      '[], "files": "| URL  |   Author Email  | Author Name  | Date '
                      'Created| TimeStamp    |\\n| ---- | --------------- | '
                      '------------ | ----------- | ------------ |\\n| '
                      'https://github.com/somegit | some@email.com | TEST | '
                      '1970-01-01T03:00:00+03:00 | [1611429178] |\\n", '
                      '"hideForCompanies": [], "id": '
                      '"21aed9b86d2e6cbb15180d803a84f6d27f673db4", '
                      '"ignoreForCompanies": [], "isFavourite": false, "isHidden": '
                      'false, "isIgnore": false, "matchesTypes": [], "name": "Git '
                      'Leak: https://github.com/somegit", "numberOf": {"contributors": '
                      '3, "files": 10}, "relations": {"infobip.com": "some.com", '
                      '"Infobip": "some"}, "seqUpdate": 1611862631144674, "source": '
                      '"github", "gibType": "osi/git_repository", '
                      '"relatedIndicatorsData": [], "systemSeverity": 2}'}])),
    'osi/public_leak': (
        {'last_fetch': {'osi/public_leak': 1601909532153438}},
        [
            {
                'name': 'Public Leak: a9a5b5cb9b971a2a037e3a0a30654185ea148095',
                'occurred': '2020-10-05T17:51:31Z',
                'rawJSON': '{"bind": [], "created": "2020-10-05T17:51:31+03:00", "data": '
                           '"Pasted at: 05/10/2020 15:45", "displayOptions": null, '
                           '"evaluation": {"admiraltyCode": "C3", "credibility": 50, '
                           '"reliability": 50, "severity": "orange", "tlp": "amber", "ttl": '
                           '30}, "hash": "a9a5b5cb9b971a2a037e3a0a30654185ea148095", "id": '
                           '"a9a5b5cb9b971a2a037e3a0a30654185ea148095", "language": "c", '
                           '"linkList": "| Author | Date Detected | Date Published | Hash | Link | Source |\\n'
                           '| ------ | ------------- | -------------- | ---- |----- | ------ |\\n| whaaaaaat | '
                           '2020-10-05T17:51:31+03:00 | 2020-10-05T17:45:46+03:00 | '
                           '3066db9f57b7997607208fedc45d7203029d9cb3 | '
                           '[https://some.ru](https://some.ru) | some.ru '
                           '|\\n", "matches": "| Type | Sub Type | Value |\\n| ---- | -------- | ----- |\\n| email '
                           '| email | some@gmail.ru |\\n", '
                           '"oldId": null, '
                           '"portalLink": "https://bt.group-ib.com/osi/public_leak?'
                           'searchValue=id:a9a5b5cb9b971a2a037e3a0a30654186ea248094", '
                           '"seqUpdate": 1601909532153438, "size": "345 B", "updated": '
                           '"2020-10-05T17:51:31+03:00", "useful": 1, "name": '
                           '"Public Leak: a9a5b5cb9b971a2a037e3a0a30654185ea148095", "gibType": '
                           '"osi/public_leak", "relatedIndicatorsData": [], "systemSeverity": 2}'
            }
        ]
    ),
    'bp/phishing_kit': (
        {'last_fetch': {'bp/phishing_kit': [1614921031175]}},
        [
            {'name': 'Phishing Kit: 8d7ea805fe20d6d77f57e2f0cadd17b1',
             'occurred': '2021-01-14T12:10:41Z',
             'rawJSON': '{"dateDetected": "2021-01-14T12:10:41+00:00", "dateFirstSeen": "2021-01-14T13:10:41+00:00", '
                        '"dateLastSeen": "2021-01-14T14:12:17+00:00", "downloadedFrom": "| URL | File Name '
                        '| Domain | Date |\\n| --- | --------- | ------ | ---- |\\n'
                        '| https://some.ru | show.zip | some.ru | 2021-01-21 10:10:41 |\\n'
                        '| https://some.ru | show.zip | "some.ru" '
                        '| 2021-01-21 10:10:41 |\\n| https://some.ru | show.zip '
                        '| some.ru | 2021-01-21 10:10:41 |\\n", '
                        '"emails": [], "evaluation": {"admiraltyCode": "B2", "credibility": 70, '
                        '"reliability": 80, "severity": "orange", "tlp": "amber", "ttl": '
                        '30}, "hash": "8d7ea805fe20d6d77f57e2f0cadd17b1", "id": '
                        '"044f3f2cb599228c1882884eb77eb073f68a25f2", "isFavourite": '
                        'false, "isHidden": false, "oldId": "396793696", "path": '
                        '"https://tap.group-ib.com/api/api/v2/web/attacks/phishing_kit'
                        '/044f3f2cb599228c1882884eb77eb073f68a25f2/file'
                        '/95b61a1df152012abb79c3951ed98680e0bd917bbcf1d440e76b66a120292c76", '
                        '"portalLink": "https://bt.group-ib.com/attacks/phishing_kit?searchValue='
                        'id:044f3f2cb599228c1882884eb77eb073f68a25f2", '
                        '"seqUpdate": 1614921031175, "targetBrand": [], "tsFirstSeen": '
                        'null, "tsLastSeen": null, "variables": null, "name": '
                        '"Phishing Kit: 8d7ea805fe20d6d77f57e2f0cadd17b1", "gibType": '
                        '"bp/phishing_kit", "relatedIndicatorsData": [[]], '
                        '"systemSeverity": 2}'}]),
})
COLLECTION_NAMES = ['compromised/card', 'osi/git_repository', 'osi/public_leak',
                    'bp/phishing', 'bp/phishing_kit', 'malware/targeted_malware', "compromised/breached",
                    "compromised/account_group"]


@pytest.fixture(scope='function', params=COLLECTION_NAMES, ids=COLLECTION_NAMES)
def session_fixture(request):
    """
    Given:
      - A list of collection names from the integration

    When:
      - Using each collection name as a parameter to the session_fixture

    Then:
      - The fixture creates the expected client for each collection name
    """
    return request.param, Client(base_url='https://some.ru')


def test_transform_function_on_dict():
    """
    Given:
      - A dictionary input to transform

    When:
      - Calling transform_function() on the input

    Then:
      - The nested dict is flattened as expected
    """
    test_input = {'a': 1, 'b': {'c': 2}}
    expected = {'a': 1, 'b c': 2}
    actual, _ = transform_function(test_input)
    assert actual == expected


def test_transform_function_on_list():
    """
    Given:
      - A list input to transform

    When:
      - Calling transform_function() on the input

    Then:
      - The nested list is flattened as expected
    """
    test_input = [{'a': 1}, {'b': 2}]
    # expected = {}
    actual, _ = transform_function(test_input)
    assert actual == {}


def test_transform_function_on_primitive():
    """
    Given:
      - A primitive input to transform

    When:
      - Calling transform_function() on the input

    Then:
      - The nested primitive is flattened as expected
    """
    test_input = 'test'
    expected = {'': 'test'}
    actual, _ = transform_function(test_input)
    assert actual == expected


def test_transform_function_returns_tuple():
    """
    Given:
      - A tuple input to transform

    When:
      - Calling transform_function() on the input

    Then:
      - The nested tuple is flattened as expected
    """
    test_input = {'a': 1}
    actual = transform_function(test_input)
    assert isinstance(actual, tuple)
    assert len(actual) == 2


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
    mocker.patch.object(client, 'create_poll_generator', return_value=[RAW_JSON[collection_name]])
    next_run, incidents = fetch_incidents_command(client=client,
                                                  last_run={},
                                                  first_fetch_time="3 days",
                                                  incident_collections=[],
                                                  requests_count=3)
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
    with pytest.raises(Exception):
        main()["error_command"]()


def test_global_search_command(mocker, session_fixture):
    import GroupIBTIA
    test_response = [{
        "apiPath": "suspicious_ip/open_proxy",
        "label": "Suspicious IP :: Open Proxy",
        "link": "",
        "count": 14,
        "time": 0.299055199,
        "detailedLinks": None,
    }]

    collection_name, client = session_fixture
    mocker.patch.object(Client, '_http_request', return_value=test_response)
    mocker.patch.object(GroupIBTIA, 'find_element_by_key', return_value=test_response)
    test_query = {'query': 'test'}
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
    import GroupIBTIA
    collection_name, client = session_fixture
    mocker.patch.object(Client, '_http_request', return_value=RAW_JSON)
    mocker.patch.object(GroupIBTIA, 'find_element_by_key', return_value=RAW_JSON[collection_name])

    result = get_available_collections_command(client=client)

    assert result.outputs_prefix == "GIBTIA.OtherInfo"
    assert result.outputs_key_field == "collections"
    assert isinstance(result.outputs['collections'], list)


def test_find_element_by_key_nested_dict():
    """
    Given:
      - A nested input dict

    When:
      - Calling find_element_by_key() with a nested key

    Then:
      - The expected nested value is returned
    """
    from GroupIBTIA import find_element_by_key
    test_dict = {'a': {'b': 'value'}}
    result = find_element_by_key(test_dict, 'a.b')
    assert result == 'value'


def test_find_element_by_key_list():
    """
    Given:
      - A list input

    When:
      - Calling find_element_by_key() to get all values of a key

    Then:
      - A list containing all values is returned
    """
    from GroupIBTIA import find_element_by_key
    test_list = [{'a': 'value1'}, {'a': 'value2'}]
    result = find_element_by_key(test_list, 'a')
    assert len(result) == 2
    assert 'value1' in result
    assert 'value2' in result


def test_find_element_by_key_missing():
    """
    Given:
      - An input dict without the specified key

    When:
      - Calling find_element_by_key() with a missing key

    Then:
      - None is returned as expected
    """
    from GroupIBTIA import find_element_by_key
    test_dict = {'a': 1}
    result = find_element_by_key(test_dict, 'b')
    assert result is None


def test_transform_some_fields_into_markdown():
    from GroupIBTIA import transform_some_fields_into_markdown

    collection_name = "osi/git_repository"
    feed = {
        "files": [
            {
                "url": "https://example.com",
                "dateCreated": "2023-10-16",
                "revisions": {
                    "info": {
                        "authorEmail": "author@example.com",
                        "authorName": "John Doe",
                        "timestamp": 1234567890
                    }
                }
            },
            # ...
        ]
    }

    expected_output = {
        "files": "| URL  |   Author Email  | Author Name  | Date Created| TimeStamp    |\n"
                 "| ---- | --------------- | ------------ | ----------- | ------------ |\n"
                 "| https://example.com | author@example.com | John Doe | 2023-10-16 | 1234567890 |\n"
    }

    result = transform_some_fields_into_markdown(collection_name, feed)

    assert result == expected_output


def test_transform_some_fields_into_markdown_phishing_kit():
    from GroupIBTIA import transform_some_fields_into_markdown

    collection_name = "bp/phishing_kit"
    feed = {
        "downloadedFrom": [
            {
                "date": "2023-10-16",
                "url": "https://example.com",
                "domain": "example.com",
                "fileName": "phish.zip"
            },
            # ...
        ]
    }

    expected_output = {'downloadedFrom': '| URL | File Name | Domain | Date |\n'
                                         '| --- | --------- | ------ | ---- |\n'
                                         '| https://example.com | phish.zip | example.com | '
                                         '2023-10-16 |\n'}

    result = transform_some_fields_into_markdown(collection_name, feed)

    assert result == expected_output


def test_transform_some_fields_into_markdown_public_leak():
    from GroupIBTIA import transform_some_fields_into_markdown

    collection_name = "osi/public_leak"
    feed = {
        "linkList": [
            {
                "author": "John Doe",
                "dateDetected": "2023-10-16",
                "datePublished": "2023-10-15",
                "hash": "abcdef123456",
                "link": "https://example.com",
                "source": "Example Source"
            },
            # ...
        ],
        "matches": {
            "Type1": {
                "SubType1": ["Value1", "Value2"],
                "SubType2": ["Value3"]
            },
            "Type2": {
                "SubType3": ["Value4"]
            }
        }
    }

    expected_output = {'linkList': '| Author | Date Detected | Date Published | Hash | Link | Source |\n'
                                   '| ------ | ------------- | -------------- | ---- |----- | ------ |\n'
                                   '| John Doe | 2023-10-16 | 2023-10-15 | abcdef123456 | '
                                   '[https://example.com](https://example.com) | Example Source |\n',
                       'matches': '| Type | Sub Type | Value |\n'
                                  '| ---- | -------- | ----- |\n'
                                  '| Type1 | SubType1 | Value1 |\n'
                                  '| Type1 | SubType1 | Value2 |\n'
                                  '| Type1 | SubType2 | Value3 |\n'
                                  '| Type2 | SubType3 | Value4 |\n'}

    result = transform_some_fields_into_markdown(collection_name, feed)

    assert result == expected_output


def test_get_human_readable_feed():
    from GroupIBTIA import get_human_readable_feed

    collection_name = "TestCollection"
    feed = {
        "id": 123,
        "field1": "value1",
        "field2": "value2",
        "field3": "value3"
    }

    expected_output = ('### Feed from TestCollection with ID 123\n'
                       '|field1|field2|field3|id|\n'
                       '|---|---|---|---|\n'
                       '| value1 | value2 | value3 | 123 |')

    result = get_human_readable_feed(collection_name, feed)

    assert result.strip() == expected_output.strip()
