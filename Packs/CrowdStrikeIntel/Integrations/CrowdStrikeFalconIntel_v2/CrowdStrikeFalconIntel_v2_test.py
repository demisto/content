import pytest
import json
import os
import demistomock as demisto
from CrowdStrikeFalconIntel_v2 import *
from CommonServerPython import DBotScoreType, Common, DemistoException

with open(os.path.normpath(os.path.join(__file__, '..', './test_data/indicator_resource.json'))) as f:
    INDICATOR_RESOURCE = json.load(f)

with open(os.path.normpath(os.path.join(__file__, '..', './test_data/indicator_output.json'))) as f:
    INDICATOR_OUTPUT = json.load(f)


class TestClientHelperFunctions:
    QUERY_PARAMS = ['offset', 'limit', 'sort', 'q']
    DATE_PARAMS = {
        'created_date': {'operator': '', 'raw_name': 'created_date'},
        'max_last_modified_date': {'operator': '<=', 'api_key': 'last_modified_date'},
        'min_last_activity_date': {'operator': '>=', 'api_key': 'first_activity_date'},
        'max_last_activity_date': {'operator': '<=', 'api_key': 'last_activity_date'}
    }

    @pytest.mark.parametrize('args, output', [
        ({'query': 1}, {'filter': 1}),
        ({'wow': 1}, {'filter': "wow:'1'"})
    ])
    def test_build_request_params(self, args, output, mocker):
        """Unit test
        Given
        - demisto args
        When
        - A query arg is provided and when not
        Then
        - If query arg is present it is the filter value, else build the params dict
        """
        mocker.patch.object(CrowdStrikeClient, "_generate_token")
        client = Client({})
        assert client.build_request_params(args) == output

    def test_build_filter_query(self, mocker):
        """Unit test
        Given
        - demisto args
        When
        - Both date and regular field is provided
        Then
        - Build the filter query according to FQL
        """
        mocker.patch.object(CrowdStrikeClient, "_generate_token")
        client = Client({})
        args = {'offset': 1, 'max_last_modified_date': '2020-09-16T22:28:42.143302', 'wow': 2}
        output = "last_modified_date:<=1600295322+wow:'2'"
        assert client.build_filter_query(args) == output


class TestHelperFunctions:

    def test_get_score_from_resource(self):
        """Unit test
        Given
        - A falcon intel resource, can be actor, report, indicator...
        When
        - We need to calculate the dbot score of the resource
        Then
        - The dbot score is calculated
        """
        assert get_score_from_resource(INDICATOR_RESOURCE) == 3

    @pytest.mark.parametrize('hash_value, hash_type, exception', [
        ('88302dbc829636b6ef926f0f055bdebd', 'hash_md5', False),
        ('D2C4535AD4CBCCF3C8E3FF580669958766DDE1CE', 'hash_sha1', False),
        ('9BA81ADE4C162975230BDADCD9D60F00A37907FC10782B76B287B057470F0760', 'hash_sha256', False),
        ('wow', '', True)
    ])
    def test_get_indicator_hash_type(self, hash_value, hash_type, exception):
        """Unit test
        Given
        - The hash value
        When
        - The type is unknown
        Then
        - Return the correct type
        """
        if not exception:
            assert get_indicator_hash_type(hash_value) == hash_type
        else:
            with pytest.raises(DemistoException):
                get_indicator_hash_type(hash_value)

    @pytest.mark.parametrize('ind_val, ind_type, dbot_score, output', [
        ('8.8.8.8', 'ip', Common.DBotScore(indicator='8.8.8.8', indicator_type=DBotScoreType.IP,
                                           integration_name='FalconIntel', score=0, malicious_description=''),
         Common.IP(ip='8.8.8.8', dbot_score=Common.DBotScore(indicator='8.8.8.8', indicator_type=DBotScoreType.IP,
                                                             integration_name='FalconIntel', score=0,
                                                             malicious_description=''))),
        ('wow', 'wow', Common.DBotScore(indicator='CVE-1999-0067', indicator_type=DBotScoreType.CVE,
                                        integration_name='FalconIntel', score=0, malicious_description=''), None)
    ])
    def test_get_indicator_object(self, ind_val, ind_type, dbot_score, output):
        """Unit test
        Given
        - The indicator value and type and its corresponding dbot score
        When
        - The indicator object doesn't exist
        Then
        - Create the indicator object
        """
        if not output:
            assert get_indicator_object(ind_val, ind_type, dbot_score) == output
        else:
            assert get_indicator_object(ind_val, ind_type, dbot_score).to_context() == \
                   output.to_context()

    @pytest.mark.parametrize('items_list, ret_type, keys, output', [
        ([{'value': 1, 'name': 2}], 'str', 'value', '1'),
        ([{'value': 1, 'name': 2}], 'list', 'value', [1]),
        ([{'value': 1, 'name': 2, 'wow': 3}], 'list', ['value', 'name'], [{'Value': 1, 'Name': 2}]),
        ([{'value': 1, 'name': 2, 'wow': 3}], 'str', ['value', 'name'], "{'Value': 1, 'Name': 2}")

    ])
    def test_get_values(self, items_list, ret_type, keys, output):
        """Unit test
        Given
        - A list of objects
        When
        - We need one or more fields of these object as a list
        Then
        - Depending on the return type and the number of keys, return the needed list
        """
        assert get_values(items_list, ret_type, keys) == output

    def test_get_indicator_data(self):
        """Unit test
        Given
        - Indicator resource from falcon intel
        When
        - We need the indicator outputs to show in war-room
        Then
        - Create the correct output
        """
        output = get_indicator_outputs(INDICATOR_RESOURCE)
        assert output == INDICATOR_OUTPUT

    @pytest.mark.parametrize('_type, output, exception', [
        ('ip', DBotScoreType.IP, False),
        ('domain', DBotScoreType.DOMAIN, False),
        ('file', DBotScoreType.FILE, False),
        ('hash', DBotScoreType.FILE, False),
        ('url', DBotScoreType.URL, False),
        ('wow', None, True)
    ])
    def test_get_dbot_score_type(self, _type, output, exception):
        """Unit test
        Given
        - The indicator type
        When
        - We need the DBotScoreType object corresponding to the indicator type
        Then
        - Return the correct DBotScoreType
        """
        if exception:
            with pytest.raises(DemistoException, match='Indicator type is not supported.'):
                get_dbot_score_type(_type)
        else:
            assert get_dbot_score_type(_type) == output


BANG_COMMANDS_PACK = [
    ('ip', '2.2.2.2'),
    ('ip', '2.2.2.2,3.3.3.3'),
    ('url', 'www.demisto.com'),
    ('url', 'www.demisto.com,www.xsoar.pan.dev'),
    ('file', '123456789012345'),
    ('file', '123456789012345,123456789012345123456789012345123456789012345'),
    ('domain', 'demisto.com'),
    ('domain', 'demisto.com,paloaltonetworks.com'),
]


@pytest.mark.parametrize('indicators_type,values', BANG_COMMANDS_PACK)
def test_bang_commands(mocker, indicators_type, values):
    mocker.patch.object(demisto, 'args', return_value={indicators_type: values})
    mocker.patch.object(demisto, 'command', return_value=indicators_type)
    mocker.patch.object(demisto, 'results')

    import CrowdStrikeFalconIntel_v2 as csfi2
    mocker.patch.object(csfi2, 'build_indicator', return_value=['item'])
    mocker.patch.object(Client, '__init__', return_value=None)

    main()

    results = demisto.results.call_args[0][0]
    assert len(results) == len(values.split(','))
