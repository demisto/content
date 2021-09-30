import json
import io
import pytest

from CommonServerPython import DemistoException, FeedIndicatorType, CommandResults


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


SOCRADAR_API_ENDPOINT = 'https://platform.socradar.com/api'

CALCULATE_DBOT_SCORE_INPUTS = [
    (900, 3),
    (800, 2),
    (450, 2),
    (300, 1),
    (100, 1),
    (0, 0),
]


def test_test_module(requests_mock):
    """Tests the test_module validation command.
    """
    from SOCRadarThreatFusion import Client, test_module

    mock_socradar_api_key = "APIKey"
    suffix = f'threat/analysis/check/auth?key={mock_socradar_api_key}'
    mock_response = util_load_json('test_data/check_auth_response.json')
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    response = test_module(client)

    assert response == 'ok'


def test_test_module_handles_authorization_error(requests_mock):
    """Tests the test_module validation command authorization error.
    """
    from SOCRadarThreatFusion import Client, test_module, MESSAGES

    mock_socradar_api_key = "WrongAPIKey"
    suffix = f'threat/analysis/check/auth?key={mock_socradar_api_key}'
    mock_response = util_load_json('test_data/check_auth_response_auth_error.json')
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response, status_code=401)
    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )
    with pytest.raises(DemistoException, match=MESSAGES['AUTHORIZATION_ERROR']):
        test_module(client)


def test_ip_command(requests_mock):
    """Tests the ip_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar ThreatFusion API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarThreatFusion import Client, ip_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/score_ip_response.json')
    suffix = 'threat/analysis'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'ip': '1.1.1.1'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    result = ip_command(
        client=client,
        args=mock_args,
    )

    expected_output = util_load_json('test_data/score_ip_expected_output.json')
    expected_context = util_load_json('test_data/score_ip_expected_context_generic_command.json')

    assert isinstance(result, list)
    assert result != []
    assert '### SOCRadar - Analysis results for IP: 1.1.1.1' in result[0].readable_output
    assert result[0].outputs == expected_context
    assert result[0].raw_response == expected_output


def test_ip_command_handles_incorrect_entity_type():
    """Tests the ip_command function incorrect entity type error.
    """
    from SOCRadarThreatFusion import Client, ip_command

    mock_socradar_api_key = "APIKey"
    mock_args = {'ip': 'INCORRECT IP ADDRESS'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    with pytest.raises(ValueError):
        ip_command(
            client=client,
            args=mock_args,
        )


def test_domain_command(requests_mock):
    """Tests the domain_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar ThreatFusion API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarThreatFusion import Client, domain_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/score_domain_response.json')
    suffix = 'threat/analysis'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'domain': 'paloaltonetworks.com'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    result = domain_command(
        client=client,
        args=mock_args,
    )

    expected_output = util_load_json('test_data/score_domain_expected_output.json')
    expected_context = util_load_json('test_data/score_domain_expected_context_generic_command.json')
    assert isinstance(result, list)
    assert result != []
    assert '### SOCRadar - Analysis results for domain: paloaltonetworks.com' in result[0].readable_output
    assert result[0].outputs == expected_context
    assert result[0].raw_response == expected_output


def test_domain_command_handles_incorrect_entity_type():
    """Tests the domain_command function incorrect entity type error.
    """
    from SOCRadarThreatFusion import Client, domain_command

    mock_socradar_api_key = "APIKey"
    mock_args = {'domain': 'INCORRECT DOMAIN'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    with pytest.raises(ValueError):
        domain_command(
            client=client,
            args=mock_args,
        )


def test_file_command(requests_mock):
    """Tests the file_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar ThreatFusion API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarThreatFusion import Client, file_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/score_hash_response.json')
    suffix = 'threat/analysis'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'file': '3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    result = file_command(
        client=client,
        args=mock_args,
    )

    expected_output = util_load_json('test_data/score_hash_expected_output.json')
    expected_context = util_load_json('test_data/score_hash_expected_context_generic_command.json')

    assert isinstance(result, list)
    assert result != []
    assert '### SOCRadar - Analysis results for hash: 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792' \
           in result[0].readable_output
    assert result[0].outputs == expected_context
    assert result[0].raw_response == expected_output


def test_file_command_handles_incorrect_entity_type():
    """Tests the file_command function incorrect entity type error.
    """
    from SOCRadarThreatFusion import Client, file_command

    mock_socradar_api_key = "APIKey"
    mock_args = {'file': 'INCORRECT HASH'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    with pytest.raises(ValueError):
        file_command(
            client=client,
            args=mock_args,
        )


def test_score_ip(requests_mock):
    """Tests the score_ip_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar ThreatFusion API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarThreatFusion import Client, score_ip_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/score_ip_response.json')
    suffix = 'threat/analysis'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'ip': '1.1.1.1'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    result = score_ip_command(
        client=client,
        args=mock_args,
    )

    expected_output = util_load_json('test_data/score_ip_expected_output.json')
    expected_context = util_load_json('test_data/score_ip_expected_context.json')

    assert isinstance(result, CommandResults)
    assert '### SOCRadar - Analysis results for IP: 1.1.1.1' in result.readable_output
    assert result.outputs == expected_context
    assert result.raw_response == expected_output


def test_score_ip_handles_incorrect_entity_type():
    """Tests the score_ip_command function incorrect entity type error.
    """
    from SOCRadarThreatFusion import Client, score_ip_command

    mock_socradar_api_key = "APIKey"
    mock_args = {'ip': 'INCORRECT IP ADDRESS'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    with pytest.raises(ValueError):
        score_ip_command(
            client=client,
            args=mock_args,
        )


def test_score_domain(requests_mock):
    """Tests the score_domain_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar ThreatFusion API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarThreatFusion import Client, score_domain_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/score_domain_response.json')
    suffix = 'threat/analysis'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'domain': 'paloaltonetworks.com'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    result = score_domain_command(
        client=client,
        args=mock_args,
    )

    expected_output = util_load_json('test_data/score_domain_expected_output.json')
    expected_context = util_load_json('test_data/score_domain_expected_context.json')
    assert isinstance(result, CommandResults)
    assert '### SOCRadar - Analysis results for domain: paloaltonetworks.com' in result.readable_output
    assert result.outputs == expected_context
    assert result.raw_response == expected_output


def test_score_domain_handles_incorrect_entity_type():
    """Tests the score_domain_command function incorrect entity type error.
    """
    from SOCRadarThreatFusion import Client, score_domain_command

    mock_socradar_api_key = "APIKey"
    mock_args = {'domain': 'INCORRECT DOMAIN'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    with pytest.raises(ValueError):
        score_domain_command(
            client=client,
            args=mock_args,
        )


def test_score_hash(requests_mock):
    """Tests the score_hash_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar ThreatFusion API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarThreatFusion import Client, score_hash_command

    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/score_hash_response.json')
    suffix = 'threat/analysis'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'hash': '3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    result = score_hash_command(
        client=client,
        args=mock_args
    )

    expected_output = util_load_json('test_data/score_hash_expected_output.json')
    expected_context = util_load_json('test_data/score_hash_expected_context.json')

    assert isinstance(result, CommandResults)
    assert '### SOCRadar - Analysis results for hash: 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792' \
           in result.readable_output
    assert result.outputs == expected_context
    assert result.raw_response == expected_output


def test_score_hash_handles_incorrect_entity_type():
    """Tests the score_hash_command function incorrect entity type error.
    """
    from SOCRadarThreatFusion import Client, score_hash_command

    mock_socradar_api_key = "APIKey"
    mock_args = {'hash': 'INCORRECT HASH'}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        verify=False,
        proxy=False
    )

    with pytest.raises(ValueError):
        score_hash_command(
            client=client,
            args=mock_args,
        )


@pytest.mark.parametrize('socradar_score, dbot_score', CALCULATE_DBOT_SCORE_INPUTS)
def test_calculate_dbot_score(socradar_score, dbot_score):
    from SOCRadarThreatFusion import calculate_dbot_score
    assert calculate_dbot_score(socradar_score) == dbot_score


def test_map_indicator_type():
    from SOCRadarThreatFusion import map_indicator_type

    assert FeedIndicatorType.IP == map_indicator_type('ipv4')
    assert FeedIndicatorType.IPv6 == map_indicator_type('ipv6')
    assert FeedIndicatorType.Domain == map_indicator_type('hostname')
    assert FeedIndicatorType.File == map_indicator_type('hash')
    assert None is map_indicator_type('IP')
    assert None is map_indicator_type('invalid')
