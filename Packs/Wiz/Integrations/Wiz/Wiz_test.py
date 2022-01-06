import pytest
from freezegun import freeze_time

import demistomock as demisto

integration_params = {
    'url': 'http://test.io',
    'credentials': {'identifier': 'test', 'password': 'pass'},
    'fetch_time': '7 days',
}


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


@freeze_time("2022-01-02T12:11:10.746Z")
def test_fetch_incidents(mocker):
    """
        Given
            - fetch incidents command
            - command args
        When
            - mock the integration parameters
        Then
            - Validate that the last_time is as the now time(not changed, not of the incident)
    """
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    from Wiz import fetch_issues
    result_response = {
        "data": {
            "issues": {
                "nodes": [
                    {
                        "id": "12345678-1234-1234-1234-d25e16359c19",
                        "control": {
                            "id": "12345678-4321-4321-4321-3792e8a03318",
                            "name": "test delete",
                        },
                        "createdAt": "2022-01-02T15:46:34Z",
                        "updatedAt": "2022-01-04T10:40:57Z",
                        "status": "OPEN",
                        "severity": "CRITICAL",
                        "entity": {
                            "bla": "lot more blah was here",
                            "name": "bucket",
                            "type": "BUCKET"
                        }
                    }
                ],
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": "eyJQcmltYXJ5Ijp7IkZpZWxkIjoiU2V2ZXJpdHkiLCJWYWx1"
                }
            }
        }
    }
    mocker.patch('Wiz.checkAPIerrors', return_value=result_response)

    _, next_run = fetch_issues(500)
    assert next_run == 1641283870


def test_get_filtered_issues(mocker):
    from Wiz import get_filtered_issues
    result_response = {
        "data": {
            "issues": {
                "nodes": [
                    {
                        "id": "12345678-1234-1234-1234-d25e16359c19",
                        "control": {
                            "id": "12345678-4321-4321-4321-3792e8a03318",
                            "name": "test delete",
                        },
                        "createdAt": "2022-01-02T15:46:34Z",
                        "updatedAt": "2022-01-04T10:40:57Z",
                        "status": "OPEN",
                        "severity": "CRITICAL",
                        "entity": {
                            "bla": "lot more blah was here",
                            "name": "bucket",
                            "type": "BUCKET"
                        }
                    }
                ],
                "pageInfo": {
                    "hasNextPage": True,
                    "endCursor": "eyJQcmltYXJ5Ijp7IkZpZWxkIjoiU2V2ZXJpdHkiLCJWYWx1"
                }
            }
        }
    }
    mocker.patch('Wiz.checkAPIerrors', return_value=result_response)
    mocker.patch.object(demisto, 'results')
    get_filtered_issues('', 'i_am_an_id', 'CRITICAL', 500)
    assert demisto.results.call_args[0][0].get('EntryContext') == result_response
    get_filtered_issues('virtualMachine', '', 'CRITICAL', 500)
    assert demisto.results.call_args[0][0].get('EntryContext') == result_response


def test_get_resource(mocker):
    from Wiz import get_resource
    result_response = {
        "data": {
            "graphSearch": {
                "totalCount": 1,
                "maxCountReached": False,
                "pageInfo": {
                    "endCursor": "1",
                    "hasNextPage": False,
                    "__typename": "PageInfo"
                },
                "nodes": [
                    {
                        "entities": [
                            {
                                "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
                                "name": "my-cluster-2",
                                "type": "VIRTUAL_MACHINE",
                                "properties": {
                                    "blah": "lots_of_blah_here"
                                }
                            }
                        ]
                    }
                ]
            }
        }
    }
    mocker.patch('Wiz.checkAPIerrors', return_value=result_response)
    mocker.patch.object(demisto, 'results')
    get_resource('i_am_an_id')
    assert demisto.results.call_args[0][0].get('EntryContext') == result_response
