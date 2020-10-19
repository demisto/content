"""EmailRep Integration for Cortex XSOAR - Unit Tests file"""
from CommonServerPython import Common, DBotScoreType

import pytest
import json
import io

TEST_EMAIL_ADDRESS = 'test@example.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_email_reputation_get(requests_mock):
    """Test emailrep-email-reputation-get command"""
    from EmailRep import INTEGRATION_NAME, Client, email_reputation_command

    mock_response = util_load_json('test_data/reputation_get_results.json')
    requests_mock.get(f'https://emailrep.io/{TEST_EMAIL_ADDRESS}', json=mock_response)

    client = Client(
        base_url='https://emailrep.io',
        verify=False,
        headers={
            'Key': 'testkey',
            'User-Agent': f'{INTEGRATION_NAME}-unittest'
        }
    )

    args = {
        'email_address': 'test@example.com'
    }

    response = email_reputation_command(client, args)

    assert response.outputs_prefix == f'{INTEGRATION_NAME}.Email'
    assert response.outputs_key_field == 'email'
    assert response.outputs == [{
        "details": {
            "blacklisted": True,
            "malicious_activity": True,
            "malicious_activity_recent": True,
            "credentials_leaked": True,
            "credentials_leaked_recent": False,
            "data_breach": True,
            "first_seen": "07/01/2008",
            "last_seen": "10/18/2020",
            "domain_exists": True,
            "domain_reputation": "n/a",
            "new_domain": False,
            "days_since_domain_creation": 9197,
            "suspicious_tld": False,
            "spam": True,
            "free_provider": True,
            "disposable": False,
            "deliverable": False,
            "accept_all": False,
            "valid_mx": True,
            "primary_mx": "",
            "spoofable": True,
            "spf_strict": True,
            "dmarc_enforced": False,
            "profiles": [
                "twitter"
            ]
        },
        "email": f"{TEST_EMAIL_ADDRESS}",
        "reputation": "none",
        "suspicious": True,
        "references": 143
    }]

    # Assert mandatory fields check
    with pytest.raises(ValueError) as error_info:
        email_reputation_command(client, {})
    assert 'Email(s) not specified' in str(error_info.value)


def test_report_email_address(requests_mock):
    """Test emailrep-email-address-report command"""
    from EmailRep import INTEGRATION_NAME, Client, report_email_address_command

    mock_response = {
        "status": "success"
    }

    requests_mock.post(f'https://emailrep.io/report', json=mock_response)

    client = Client(
        base_url='https://emailrep.io',
        verify=False,
        headers={
            'Key': 'testkey',
            'User-Agent': f'{INTEGRATION_NAME}-unittest'
        }
    )

    args = {
        'email_address': 'test@example.com',
        'tags': ['scam']
    }

    response = report_email_address_command(client, args)

    assert response.outputs_prefix == f'{INTEGRATION_NAME}.Report'
    assert response.outputs_key_field == 'status'
    assert response.outputs == {
        "status": "success"
    }

    # Assert tag checking.
    args = {
        'email_address': 'test@example.com',
        'tags': ['invalid-tag', 'scam']
    }
    with pytest.raises(ValueError) as error_info:
        report_email_address_command(client, args)
    assert 'not in accepted tag list' in str(error_info.value)

    # Assert mandatory field checking.
    args = {
        'email_address': 'test@example.com'
    }
    with pytest.raises(ValueError) as error_info:
        report_email_address_command(client, args)
    assert 'Tag(s) not specified' in str(error_info.value)

    args = {
        'tags': ['invalid-tag', 'scam']
    }
    with pytest.raises(ValueError) as error_info:
        report_email_address_command(client, args)
    assert 'Email(s) not specified' in str(error_info.value)


def test_email(requests_mock):
    """Test email command"""
    from EmailRep import INTEGRATION_NAME, Client, email_command

    mock_response = util_load_json('test_data/reputation_get_results.json')
    requests_mock.get(f'https://emailrep.io/{TEST_EMAIL_ADDRESS}', json=mock_response)

    client = Client(
        base_url='https://emailrep.io',
        verify=False,
        headers={
            'Key': 'testkey',
            'User-Agent': f'{INTEGRATION_NAME}-unittest'
        }
    )

    args = {
        'email_address': f'{TEST_EMAIL_ADDRESS}'
    }

    response = email_command(client, args)

    # Assert mocked response
    assert response.outputs_prefix == f'{INTEGRATION_NAME}.EmailScore'
    assert response.outputs_key_field == 'email'
    assert response.outputs == [{
        "details": {
            "blacklisted": True,
            "malicious_activity": True,
            "malicious_activity_recent": True,
            "credentials_leaked": True,
            "credentials_leaked_recent": False,
            "data_breach": True,
            "first_seen": "07/01/2008",
            "last_seen": "10/18/2020",
            "domain_exists": True,
            "domain_reputation": "n/a",
            "new_domain": False,
            "days_since_domain_creation": 9197,
            "suspicious_tld": False,
            "spam": True,
            "free_provider": True,
            "disposable": False,
            "deliverable": False,
            "accept_all": False,
            "valid_mx": True,
            "primary_mx": "",
            "spoofable": True,
            "spf_strict": True,
            "dmarc_enforced": False,
            "profiles": [
                "twitter"
            ]
        },
        "email": "test@example.com",
        "reputation": "none",
        "suspicious": True,
        "references": 143
    }]

    # Assert SUSPICIOUS dbot score
    assert response.indicators[0].email_address == TEST_EMAIL_ADDRESS
    assert response.indicators[0].dbot_score.indicator == TEST_EMAIL_ADDRESS
    assert response.indicators[0].dbot_score.indicator_type == DBotScoreType.EMAIL_ADDRESS
    assert response.indicators[0].dbot_score.integration_name == INTEGRATION_NAME
    assert response.indicators[0].dbot_score.score == Common.DBotScore.SUSPICIOUS

    # Assert GOOD dbot score
    mock_response["suspicious"] = False
    requests_mock.get(f'https://emailrep.io/{TEST_EMAIL_ADDRESS}', json=mock_response)
    response = email_command(client, args)
    assert response.indicators[0].dbot_score.score == Common.DBotScore.GOOD

    # Assert BAD dbot score due to malicious_activity_recent
    mock_response["suspicious"] = True
    mock_response["details.malicious_activity_recent"] = True
    mock_response["details.credentials_leaked_recent"] = False

    requests_mock.get(f'https://emailrep.io/{TEST_EMAIL_ADDRESS}', json=mock_response)
    response = email_command(client, args)
    assert response.indicators[0].dbot_score.score == Common.DBotScore.BAD
    assert response.indicators[0].dbot_score.malicious_description == 'EmailRep returned malicious_activity_recent'

    # Assert BAD dbot score due to malicious_activity_recent
    mock_response["suspicious"] = True
    mock_response["details.malicious_activity_recent"] = False
    mock_response["details.credentials_leaked_recent"] = True

    requests_mock.get(f'https://emailrep.io/{TEST_EMAIL_ADDRESS}', json=mock_response)
    response = email_command(client, args)
    assert response.indicators[0].dbot_score.score == Common.DBotScore.BAD
    assert response.indicators[0].dbot_score.malicious_description == 'EmailRep returned credentials_leaked_recent'

    # Assert BAD dbot score due to malicious_activity_recent and credentials_leaked_recent
    mock_response["suspicious"] = True
    mock_response["details.malicious_activity_recent"] = True
    mock_response["details.credentials_leaked_recent"] = True

    requests_mock.get(f'https://emailrep.io/{TEST_EMAIL_ADDRESS}', json=mock_response)
    response = email_command(client, args)
    assert response.indicators[0].dbot_score.score == Common.DBotScore.BAD
    assert response.indicators[0].dbot_score.malicious_description == \
        'EmailRep returned malicious_activity_recent credentials_leaked_recent'

    # Assert mandatory fields check
    with pytest.raises(ValueError) as error_info:
        email_command(client, {})
    assert 'Email(s) not specified' in str(error_info.value)
