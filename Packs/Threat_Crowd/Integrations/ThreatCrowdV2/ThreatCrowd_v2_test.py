import json
import io
# from Packs.Base.Scripts.CommonServerPython.CommonServerPython import DBotScoreReliability
# from Packs.Threat_Crowd.Integrations.ThreatCrowdV2.ThreatCrowd_v2 import Client
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
    base_url='https://www.threatcrowd.org/searchApi/v2/',
    verify=False,
    proxy=False,
    reliability=DBotScoreReliability.C
)


def test_ip_command(mocker):
    """
        Given:
            - a list of ips

        When:
            - running ip command was required

        Then:
            - validates that indicator objects were created as expected
    """
    # from Packs.Threat_Crowd.Integrations.ThreatCrowdV2.ThreatCrowd_v2 import get_ip
    from ThreatCrowd_v2 import get_ip

    mock_response = get_key_from_test_data('ip_response')
    mocker.patch.object(Client, 'http_request', return_value=mock_response)

    res = get_ip(CLIENT, {'ip': '0.0.0.0, 1.1.1.1'})
    assert res[0].outputs['value'] == "0.0.0.0"
    assert res[0].indicator.dbot_score.reliability == DBotScoreReliability.C
    assert res[0].indicator.dbot_score.score == 3
    assert res[0].indicator.dbot_score.indicator == "0.0.0.0"
    assert len(res) == 2


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
    from ThreatCrowd_v2 import get_domain

    mock_response = get_key_from_test_data('domain_response')
    mocker.patch.object(Client, 'http_request', return_value=mock_response)

    res = get_domain(CLIENT, {'domain': 'test1.com, test2.com'})
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
    from ThreatCrowd_v2 import get_email

    mock_response = get_key_from_test_data('email_response')
    mocker.patch.object(Client, 'http_request', return_value=mock_response)

    res = get_email(CLIENT, {'email': 'test@test1.com, test@test2.com'})
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
    from ThreatCrowd_v2 import get_antivirus

    mock_response = get_key_from_test_data('antivirus_response')
    mocker.patch.object(Client, 'http_request', return_value=mock_response)

    res = get_antivirus(CLIENT, {'antivirus': 'test, test2'})

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
    from ThreatCrowd_v2 import get_file

    mock_response = get_key_from_test_data('file_response')
    mocker.patch.object(Client, 'http_request', return_value=mock_response)

    res = get_file(CLIENT, {'file': 'test_md5, test2.com'})
    assert res[0].outputs['value'] == "test_md5"
    assert res[0].indicator.md5 == 'test_md5'
    assert res[0].indicator.sha1 == 'test_sha1'
    assert res[0].indicator.dbot_score.reliability == DBotScoreReliability.C
    assert res[0].indicator.dbot_score.score == 0
    assert res[0].indicator.dbot_score.indicator == 'test_md5'
    assert len(res) == 2
