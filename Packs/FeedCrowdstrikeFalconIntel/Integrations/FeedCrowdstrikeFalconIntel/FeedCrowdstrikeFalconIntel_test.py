import pytest
import json

from FeedCrowdstrikeFalconIntel import Client


def get_fetch_data():
    with open('./test_data/test_data.json', 'r') as f:
        return json.loads(f.read())


indicators = get_fetch_data()


@pytest.mark.parametrize(
    "params, actors_filter, expected",
    [
        ({}, '', '/intel/combined/actors/v1'),
        ({}, 'blabla', '/intel/combined/actors/v1blabla'),
        ('last_modified_date%3A%3E{relevant_time}', 'blabla',
         '/intel/combined/actors/v1blabla%2Blast_modified_date%3A%3E{relevant_time}'),
        ('last_modified_date%3A%3E{relevant_time}', '',
         '/intel/combined/actors/v1?filter=last_modified_date%3A%3E{relevant_time}')
    ]
)
def test_build_url_suffix(params, actors_filter, expected):
    res = Client.build_url_suffix(Client, params, actors_filter)
    assert res == expected


def test_create_indicators_from_response():
    res = Client.create_indicators_from_response(Client, indicators["list_data_cs"], {}, 'AMBER')
    assert res == indicators["expected_list"]


@pytest.mark.parametrize(
    argnames='server_ge_620, expected_actor_type',
    argvalues=[
        (False, 'STIX Threat Actor'),
        (True, 'Threat Actor')
    ])
def test_actor_type(mocker, server_ge_620, expected_actor_type):
    """
    Given:
        - Server version above end bellow 6.2.0

    When:
        - Creating indicators

    Then:
        -
        Validate 'STIX Threat Actor' are the type in server version < 6.2.0
        and 'Threat Actor' for server >= 6.2.0
    """

    # prepare
    mocker.patch('CommonServerPython.is_demisto_version_ge', return_value=server_ge_620)

    # run
    res = Client.create_indicators_from_response(Client, indicators["list_data_cs"], {}, 'AMBER')

    # validate
    assert all(indicator['type'] == expected_actor_type for indicator in res)


def test_fetch_indicators_with_limit(mocker, requests_mock):
    """
    Given:
        - Limit param are 2

    When:
        - fetch_indicators

    Then:
        -
        Validate there is offset in the last_run for the next run
    """
    import re
    import demistomock as demisto
    from FeedCrowdstrikeFalconIntel import main
    mocker.patch.object(Client, '_get_access_token', return_value='test_token')
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'params', return_value={'limit': '2', 'credentials_client': {
                        'identifier': 'test_identifier', 'password': 'test_password'}})
    mocker.patch.object(demisto, 'setLastRun')
    requests_mock.get(re.compile('.*api.crowdstrike.com.*'),
                      json=indicators['list_data_cs'])

    main()

    last_run_call_args = demisto.setLastRun.call_args[0][0]
    assert 'last_modified_time' in last_run_call_args
    assert last_run_call_args['offset'] == 2
