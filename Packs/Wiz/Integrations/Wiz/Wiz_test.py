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
    use_values = {
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
    mocker.patch('Wiz.checkAPIerrors', return_value=use_values)

    _, next_run = fetch_issues(500)
    assert next_run == 1641283870
