import json
import io

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
        """

    from CrowdStrikeIndicatorFeed import Client, crowdstrike_indicators_list_command

    mock_response = util_load_json('test_data/crowdstrike_indicators_list_command.json')
    requests_mock.post('https://api.crowdstrike.com/oauth2/token', json={'access_token': '12345'})
    requests_mock.get(url='https://api.crowdstrike.com/intel/combined/indicators/v1', json=mock_response)

    client = Client(base_url='https://api.crowdstrike.com/', credentials={'identifier': '123', 'password': '123'},
                    type='Domain', include_deleted='false', limit=2)
    args = {
        'limit': '2'
    }
    response = crowdstrike_indicators_list_command(client, args)

    assert len(response.outputs) == 2
    assert len(response.raw_response) == 2
    assert "Indicators from CrowdStrike Falcon Intel" in response.readable_output
    assert "domain_abc" in response.readable_output


@pytest.mark.parametrize(
    "types_list, expected",
    [
        (['ALL'], "type:'username',type:'domain',type:'email_address',type:'hash_md5',type:'hash_sha256',"
                  "type:'registry',type:'url',type:'ip_address'"),
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
