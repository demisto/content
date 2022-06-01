import json
import io
import pytest
from CommonServerPython import DBotScoreReliability
from ThreatCrowd_v2 import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def get_key_from_test_data(key):
    path = './test_data/response_mocks.json'
    test_data = util_load_json(path)
    return test_data[key]


CLIENT = Client(
    base_url='test_url',
    verify=False,
    proxy=False,
    reliability=DBotScoreReliability.C,
    entry_limit=50
)
LIMIT_CASES = [
    (5, -1, None),  # case where command requires all results while instance is limited
    (-1, 5, 5),  # case where command requires limit amount of result while instance is limitless
    (-1, -1, None),  # case where unlimited results are required
    (5, None, 5),  # case where command does not specified a limit,
]


@pytest.mark.parametrize("instance_limit,command_limit, expected", LIMIT_CASES)
def test_get_limit_for_command(instance_limit, command_limit, expected):
    """
        Given:
            - a limit of the instance and a limit of a command

        When:
            - running _get_limit_for_command function

        Then:
            - validates that if limit was given in a function, it override the instance limit.
    """
    CLIENT.entry_limit = instance_limit
    res = CLIENT._get_limit_for_command(command_limit)
    assert res == expected


RESOLUTION_CASES = [
    (True,
     [{'last_resolved': '2015-08-15', 'domain': 'test11.com'}, {'last_resolved': '2015-05-28', 'domain': 'test2.com'},
      {'last_resolved': '2015-05-05', 'domain': 'test3.com'}, {'last_resolved': '2015-05-05', 'domain': 'test5.com'},
      {'last_resolved': '2015-01-20', 'domain': 'test6.com'}, {'last_resolved': '2015-01-19', 'domain': 'test12.com'},
      {'last_resolved': '2014-07-01', 'domain': 'test8.com'}, {'last_resolved': '2014-06-14', 'domain': 'test4.com'},
      {'last_resolved': '2014-05-16', 'domain': 'test9.com'}, {'last_resolved': '2014-03-14', 'domain': 'test10.com'},
      {'last_resolved': '2014-03-10', 'domain': 'test7.com'}, {'last_resolved': '2013-11-03', 'domain': 'test1.com'}]
     ),
    (False,
     [{'last_resolved': '2015-05-28', 'domain': 'test2.com'}, {'last_resolved': '2015-05-05', 'domain': 'test3.com'},
      {'last_resolved': '2015-05-05', 'domain': 'test5.com'}, {'last_resolved': '2014-06-14', 'domain': 'test4.com'},
      {'last_resolved': '2013-11-03', 'domain': 'test1.com'}]
     )
]


@pytest.mark.parametrize("extended,expected", RESOLUTION_CASES)
def test_handle_resolutions(mocker, extended, expected):
    """
        Given:
            - a list of dictionaries representing resolution section of api response

        When:
            - running handle_resolution function

        Then:
            - validates that the function correctly cuts the list and sort it by date.
    """
    from ThreatCrowd_v2 import handle_resolutions
    mock_response = get_key_from_test_data('resulotion_respone')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    limit = None
    if not extended:
        limit = 5
    assert handle_resolutions(mock_response, limit) == expected


IP_CASES = [
    ('ip_response_1',  # case where all data is found in the server response.
     {'value': '0.0.0.0', 'resolutions_len': 2, 'references_len': 2, 'hashes_len': 3}  # expected
     ),
    ('ip_response_2',  # case where 'reference', 'hashes' and 'resolutions' are missing from the server response.
     {'value': '0.0.0.0', 'resolutions_len': 0, 'references_len': 0, 'hashes_len': 0}
     )
]


@pytest.mark.parametrize("field_in_mock,expected", IP_CASES)
def test_ip_command(mocker, field_in_mock, expected):
    """
        Given:
            - a list of ips

        When:
            - running ip command was required

        Then:
            - validates that indicator objects were created as expected
    """
    # from Packs.Threat_Crowd.Integrations.ThreatCrowdV2.ThreatCrowd_v2 import get_ip
    from ThreatCrowd_v2 import ip_command

    mock_response = get_key_from_test_data(field_in_mock)
    mock_request = mocker.patch.object(Client, '_http_request', return_value=mock_response)

    res = ip_command(CLIENT, {'ip': '0.0.0.0, 1.1.1.1'})
    assert mock_request.call_args_list[0][1] == {'method': 'GET', 'params': {'ip': '0.0.0.0'},
                                                 'url_suffix': 'ip/report/'}
    assert res[0].outputs['value'] == expected['value']
    assert res[0].indicator.dbot_score.reliability == DBotScoreReliability.C
    assert res[0].indicator.dbot_score.score == 3
    assert res[0].indicator.dbot_score.indicator == "0.0.0.0"
    assert len(res[0].outputs['resolutions']) == expected['resolutions_len']
    assert len(res[0].outputs['references']) == expected['references_len']
    assert len(res[0].outputs['hashes']) == expected['hashes_len']
    assert len(res) == 2


def test_ip_command_empty_response(mocker):
    """
    Given:
        - List of IPs.
    When:
        - ThreatCrowd service returns returns empty data regarding the requested IP.

    Then:
        - validates that indicator objects were created as expected

    """
    from ThreatCrowd_v2 import ip_command

    mock_response = get_key_from_test_data('empty_ip_response')
    mock_request = mocker.patch.object(Client, '_http_request', return_value=mock_response)

    res = ip_command(CLIENT, {'ip': '0.0.0.0'})
    assert mock_request.call_args_list[0][1] == {'method': 'GET', 'params': {'ip': '0.0.0.0'},
                                                 'url_suffix': 'ip/report/'}
    assert res[0].outputs['value'] == "0.0.0.0"
    assert res[0].outputs['value'] == "0.0.0.0"
    assert res[0].indicator.dbot_score.reliability == DBotScoreReliability.C
    assert res[0].indicator.dbot_score.score == 0
    assert res[0].indicator.dbot_score.indicator == "0.0.0.0"
    assert not res[0].outputs['hashes']
    assert len(res) == 1


def test_domain_command(mocker):
    """
        Given:
            - a list of domains

        When:
            - running domain command was required

        Then:
            - validates that indicator objects were created as expected
    """
    # from Packs.Threat_Crowd.Integrations.ThreatCrowdV2.ThreatCrowd_v2 import get_domain
    from ThreatCrowd_v2 import domain_command

    mock_response = get_key_from_test_data('domain_response')
    mock_request = mocker.patch.object(Client, '_http_request', return_value=mock_response)

    res = domain_command(CLIENT, {'domain': 'test1.com, test2.com'})
    assert mock_request.call_args_list[0][1] == {'method': 'GET',
                                                 'params': {'domain': 'test1.com'},
                                                 'url_suffix': 'domain/report/'}
    assert res[0].outputs['value'] == "test1.com"
    assert res[0].indicator.dbot_score.reliability == DBotScoreReliability.C
    assert res[0].indicator.dbot_score.score == 2
    assert res[0].indicator.dbot_score.indicator == 'test1.com'
    assert len(res) == 2


def test_email_command(mocker):
    """
        Given:
            - a list of emails

        When:
            - running email command was required

        Then:
            - validates that indicator objects were created as expected
    """
    # from Packs.Threat_Crowd.Integrations.ThreatCrowdV2.ThreatCrowd_v2 import get_ip
    from ThreatCrowd_v2 import email_command

    mock_response = get_key_from_test_data('email_response')
    mock_request = mocker.patch.object(Client, '_http_request', return_value=mock_response)

    res = email_command(CLIENT, {'email': 'test@test1.com, test@test2.com'})
    assert mock_request.call_args_list[0][1] == {'method': 'GET',
                                                 'params': {'email': 'test@test1.com'},
                                                 'url_suffix': 'email/report/'}
    assert res[0].outputs['value'] == "test@test1.com"
    assert res[0].indicator.dbot_score.reliability == DBotScoreReliability.C
    assert res[0].indicator.dbot_score.score == 0
    assert res[0].indicator.dbot_score.indicator == "test@test1.com"
    assert len(res) == 2


def test_antivirus_command(mocker):
    """
        Given:
            - a list of antiviruses

        When:
            - running antivirus command was required

        Then:
            - validates that Response object were created as expected
    """
    # from Packs.Threat_Crowd.Integrations.ThreatCrowdV2.ThreatCrowd_v2 import get_ip
    from ThreatCrowd_v2 import antivirus_command

    mock_response = get_key_from_test_data('antivirus_response')
    mock_request = mocker.patch.object(Client, '_http_request', return_value=mock_response)

    res = antivirus_command(CLIENT, {'antivirus': 'test, test2'})
    assert mock_request.call_args_list[0][1] == {'method': 'GET', 'url_suffix': 'antivirus/report/',
                                                 'params': {'antivirus': 'test'}}
    assert res[0].outputs['value'] == "test"
    assert len(res[0].outputs['hashes']) > 0
    assert len(res) == 2


def test_file_command(mocker):
    """
        Given:
            - a list of file's hashes

        When:
            - running file command was required

        Then:
            - validates that indicator objects were created as expected
    """
    # from Packs.Threat_Crowd.Integrations.ThreatCrowdV2.ThreatCrowd_v2 import get_domain
    from ThreatCrowd_v2 import file_command

    mock_response = get_key_from_test_data('file_response')
    mock_request = mocker.patch.object(Client, '_http_request', return_value=mock_response)

    res = file_command(CLIENT, {'file': 'test_md5, test_md5_2.com'})
    assert mock_request.call_args_list[0][1] == {'method': 'GET', 'url_suffix': 'file/report/',
                                                 'params': {'resource': 'test_md5'}}

    assert mock_request.call_args_list[1][1] == {'method': 'GET', 'url_suffix': 'file/report/',
                                                 'params': {'resource': 'test_md5_2.com'}}

    assert res[0].outputs['value'] == "test_md5"
    assert res[0].indicator.md5 == 'test_md5'
    assert res[0].indicator.sha1 == 'test_sha1'
    assert res[0].indicator.dbot_score.reliability == DBotScoreReliability.C
    assert res[0].indicator.dbot_score.score == 0
    assert res[0].indicator.dbot_score.indicator == 'test_md5'
    assert len(res) == 2
