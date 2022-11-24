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


def test_create_relationships_unknown_key():
    """
        Given
            - Field type, indicator and a resource with an unknown relation type.
        When
            - Calling `create_relationships` command.
        Then
            - validate that no Key Error exception was thrown, and that only 1 relationship was created.
    """
    from CrowdStrikeIndicatorFeed import create_relationships
    rs_ls = create_relationships('relations', {"type": "hash_md5", "value": "1234567890"},
                                 {"relations": [{"type": "password"}, {"type": 'username', 'indicator': 'abc'}]})
    assert rs_ls == [{'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': '1234567890',
                      'entityAFamily': 'Indicator', 'entityAType': 'hash_md5', 'entityB': 'abc', 'entityBFamily': 'Indicator',
                      'entityBType': 'Account', 'fields': {}}]
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
