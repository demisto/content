import json
import io
import demistomock as demisto
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_crowdstrike_indicators_list_command(requests_mock):
    """Tests crowdstrike_indicators_list_command function
        Given
            - The following indicator type: 'domain' that was chosen by the user.
            - include_deleted: False
        When
            - Calling `crowdstrike_indicators_list_command`
        Then
            - convert the result to indicators list
            - validate the length of the indicators list
            - validate the Feed tags is as expected
        """

    from CrowdStrikeIndicatorFeed import Client, crowdstrike_indicators_list_command

    mock_response = util_load_json('test_data/crowdstrike_indicators_list_command.json')
    requests_mock.post('https://api.crowdstrike.com/oauth2/token', json={'access_token': '12345'})
    requests_mock.get(url='https://api.crowdstrike.com/intel/combined/indicators/v1', json=mock_response)

    feed_tags = ['Tag1', 'Tag2']
    client = Client(base_url='https://api.crowdstrike.com/', credentials={'identifier': '123', 'password': '123'},
                    type='Domain', include_deleted='false', limit=2, feed_tags=feed_tags)
    args = {
        'limit': '2'
    }
    response = crowdstrike_indicators_list_command(client, args)

    assert len(response.outputs) == 3
    assert len(response.raw_response) == 3
    assert "Indicators from CrowdStrike Falcon Intel" in response.readable_output
    assert "domain_abc" in response.readable_output
    assert feed_tags[0] and feed_tags[1] in response.raw_response[0]['fields']['tags']


@pytest.mark.parametrize(
    "types_list, expected",
    [
        (['ALL'], "type:'username',type:'domain',type:'email_address',type:'hash_md5',type:'hash_sha1',"
                  "type:'hash_sha256',type:'registry',type:'url',type:'ip_address',type:'reports',type:'actors',"
                  "type:'malware_families',type:'vulnerabilities'"),
        (['Domain', 'Email', 'Registry Key'], "type:'domain',type:'email_address',type:'registry'")
    ]
)
def test_build_type_fql(types_list, expected):
    """Tests build_type_fql function
        Given
            - Indicator types that were chosen by the user.
        When
            - Calling `build_type_fql` in order to build filter for `get_indicators`
        Then
            - validate result as expected
        """
    from CrowdStrikeIndicatorFeed import Client

    res = Client.build_type_fql(types_list=types_list)
    assert res == expected


def test_create_indicators_from_response():
    """Tests build_type_fql function
        Given
            - Indicator types that were chosen by the user.
        When
            - Calling `create_indicators_from_response` in order to build indicators from response
        Then
            - validate result as expected
    """
    from CrowdStrikeIndicatorFeed import Client

    raw_response = util_load_json('test_data/crowdstrike_indicators_list_command.json')
    expected_result = util_load_json('test_data/create_indicators_from_response.json')
    res = Client.create_indicators_from_response(raw_response)
    assert res == expected_result


def test_empty_first_fetch(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={'first_fetch': ''})
    mocker.patch.object(demisto, 'command', return_value='')
    requests_mock.post('https://api.crowdstrike.com/oauth2/token', json={'access_token': '12345'})
    from CrowdStrikeIndicatorFeed import main
    main()
    assert True


@pytest.mark.parametrize(
    'field, indicator, resource, expected_results',
    [
        (
            'relations',
            {"type": "hash_md5", "value": "1234567890"},
            {"relations": [{"type": "password"}, {"type": 'username', 'indicator': 'abc'}]},
            [{'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': '1234567890',
              'entityAFamily': 'Indicator', 'entityAType': 'hash_md5', 'entityB': 'abc', 'entityBFamily': 'Indicator',
              'entityBType': 'Account', 'fields': {}}]
        ),
        (
            'malware_families',
            {"type": "type non support", "value": "1234567890"},
            {"malware_families": {"relations": "Test indicator"}},
            [{'name': 'type non support', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator',
              'entityA': '1234567890', 'entityAFamily': 'Indicator', 'entityAType': 'type non support',
              'entityB': 'relations', 'entityBFamily': 'Indicator',
              'entityBType': 'Malware', 'fields': {}}]
        )
    ]
)
def test_create_relationships_unknown_key(field, indicator, resource, expected_results):
    """
        Given
            - Field type, indicator and a resource with an unknown relation type.
        When
            - Calling `create_relationships` command.
        Then
            - validate that no Key Error exception was thrown, and that only 1 relationship was created.
    """
    from CrowdStrikeIndicatorFeed import create_relationships
    rs_ls = create_relationships(field, indicator, resource)
    assert rs_ls == expected_results
    assert len(rs_ls) == 1


def test_reset_last_run(mocker):
    """
        Given
            - No inputs.
        When
            - Calling `reset_last_run` command.
        Then
            - Ensure that the integration context dict was cleared.
    """
    from CrowdStrikeIndicatorFeed import reset_last_run
    demisto_set_context_mocker = mocker.patch.object(demisto, 'setIntegrationContext')
    reset_last_run()
    assert demisto_set_context_mocker.call_args.args == ({},)


def test_fetch_no_indicators(mocker, requests_mock):
    """
    Given
        - no indicators api response
    When
        - fetching indicators
    Then
        - Ensure empty list is returned and no exception is raised.
    """
    from CrowdStrikeIndicatorFeed import Client

    mock_response = util_load_json('test_data/crowdstrike_indicators_list_command.json')
    requests_mock.post('https://api.crowdstrike.com/oauth2/token', json={'access_token': '12345'})
    requests_mock.get(url='https://api.crowdstrike.com/intel/combined/indicators/v1', json=mock_response)

    feed_tags = ['Tag1', 'Tag2']
    client = Client(base_url='https://api.crowdstrike.com/', credentials={'identifier': '123', 'password': '123'},
                    type='Domain', include_deleted='false', limit=2, feed_tags=feed_tags)

    mocker.patch.object(client, 'get_indicators', return_value={'resources': []})

    assert client.fetch_indicators(limit=10, offset=5, fetch_command=True) == []


def test_crowdstrike_to_xsoar_types():

    from CrowdStrikeIndicatorFeed import CROWDSTRIKE_TO_XSOAR_TYPES

    assert None not in CROWDSTRIKE_TO_XSOAR_TYPES


@pytest.mark.parametrize(
    'first_fetch, filter, integration_context, get_indicators_response, filter_arg_call, expected_results',
    [
        (
            '1662650320',
            '',
            {'last_updated': '1662650343'},
            {},
            '(last_updated:>=1662650343)',
            ('', 0)
        ),
        (
            '1662650320',
            '',
            {'last_updated': '1662650343'},
            {'resources': [
                {
                    "id": "dummy",
                    "indicator": "dummy",
                    "type": "hash_md5",
                    "deleted": "False",
                    "published_date": 1622198010,
                    "last_updated": 1662650343,
                    "reports": [],
                    "actors": [
                        "DOPPELSPIDER"
                    ],
                    "malware_families": [
                        "DoppelDridex"
                    ],
                    "kill_chains": [],
                    "ip_address_types": [],
                    "domain_types": [],
                    "malicious_confidence": "high",
                    "_marker": "test_marker_test",
                    "labels": []
                }
            ]},
            '(last_updated:>=1662650343)',
            ("(_marker:>'test_marker_test')", 1)
        ),
        (
            '1662650320',
            '',
            {},
            {'resources': [
                {
                    "id": "dummy",
                    "indicator": "dummy",
                    "type": "hash_md5",
                    "deleted": "False",
                    "published_date": 1622198010,
                    "last_updated": 1662650343,
                    "reports": [],
                    "actors": [
                        "DOPPELSPIDER"
                    ],
                    "malware_families": [
                        "DoppelDridex"
                    ],
                    "kill_chains": [],
                    "ip_address_types": [],
                    "domain_types": [],
                    "malicious_confidence": "high",
                    "_marker": "test_marker_test",
                    "labels": []
                }
            ]},
            '(last_updated:>=1662650320)',
            ("(_marker:>'test_marker_test')", 1)
        ),
        (
            '',
            '',
            {},
            {'resources': [
                {
                    "id": "dummy",
                    "indicator": "dummy",
                    "type": "hash_md5",
                    "deleted": "False",
                    "published_date": 1622198010,
                    "last_updated": 1662650343,
                    "reports": [],
                    "actors": [
                        "DOPPELSPIDER"
                    ],
                    "malware_families": [
                        "DoppelDridex"
                    ],
                    "kill_chains": [],
                    "ip_address_types": [],
                    "domain_types": [],
                    "malicious_confidence": "high",
                    "_marker": "test_marker_test",
                    "labels": []
                }
            ]},
            None,
            ("(_marker:>'test_marker_test')", 1)
        )
    ]
)
def test_handling_first_fetch_and_old_integration_context(mocker,
                                                          requests_mock,
                                                          first_fetch,
                                                          filter,
                                                          integration_context,
                                                          get_indicators_response,
                                                          filter_arg_call,
                                                          expected_results):

    from CrowdStrikeIndicatorFeed import Client

    requests_mock.post('https://api.crowdstrike.com/oauth2/token', json={'access_token': '12345'})
    client = Client(base_url='https://api.crowdstrike.com/', credentials={'identifier': '123', 'password': '123'},
                    type='ALL', include_deleted='false', limit=2, first_fetch=first_fetch)
    mocker.patch('CrowdStrikeIndicatorFeed.demisto.getIntegrationContext', return_value=integration_context)
    get_indicator_call = mocker.patch.object(client, 'get_indicators', return_value=get_indicators_response)

    results = client.handle_first_fetch_context_or_pre_2_1_0(filter)

    assert get_indicator_call.call_args.kwargs['params'].get('filter') == filter_arg_call
    assert results[0] == expected_results[0]
    assert len(results[1]) == expected_results[1]


@pytest.mark.parametrize(
    'indicator, expected_results',
    [
        (
            {'indicator': '1.1.1.1', 'type': 'ip_address'},
            'IP'
        ),
        (
            {'indicator': 'fe80:0000:0000:0000:91ba:7558:26d3:acde', 'type': 'ip_address'},
            'IPv6'
        ),
        (
            {'indicator': 'test_test', 'type': 'username'},
            'Account'
        ),
        (
            {'indicator': 'test_test', 'type': 'password'},
            None
        )
    ]
)
def test_auto_detect_indicator_type_from_cs(indicator: dict, expected_results: str | None):
    from CrowdStrikeIndicatorFeed import auto_detect_indicator_type_from_cs

    assert auto_detect_indicator_type_from_cs(indicator['indicator'], indicator['type']) == expected_results
