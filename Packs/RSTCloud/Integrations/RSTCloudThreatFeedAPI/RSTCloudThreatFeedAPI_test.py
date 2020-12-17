"""RST Cloud Threat Feed API Integration for Cortex XSOAR - Unit Tests file
Test Execution
--------------
Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/RSTCloud/Integrations/RSTCloudThreatFeedAPI

"""
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_ip_command(requests_mock):
    """Tests the ip reputation command function.

    Configures requests_mock instance to generate the appropriate
    ip reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from RSTCloudThreatFeedAPI import Client, ip_command

    value_to_check = '118.243.83.70'
    mock_response = util_load_json('test_data/ip_reputation.json')
    requests_mock.get(f'https://api.rstcloud.net/v1/ioc?value={value_to_check}', json=mock_response)

    client = Client(verify=False, apikey='test')
    args = {'ip': value_to_check}
    markdown, raw_results, indicators = ip_command(client, args)

    assert isinstance(markdown, list)
    assert isinstance(raw_results, list)
    assert isinstance(indicators, list)
    assert isinstance(markdown[0], str)
    assert indicators[0].ip == value_to_check


def test_domain_command(requests_mock):
    """Tests the domain reputation command function.

    Configures requests_mock instance to generate the appropriate
    domain reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from RSTCloudThreatFeedAPI import Client, domain_command

    value_to_check = 'thec0de-22249.portmap.io'
    mock_response = util_load_json('test_data/domain_reputation.json')
    requests_mock.get(f'https://api.rstcloud.net/v1/ioc?value={value_to_check}', json=mock_response)

    client = Client(verify=False, apikey='test')
    args = {'domain': value_to_check}
    markdown, raw_results, indicators = domain_command(client, args)

    assert isinstance(markdown, list)
    assert isinstance(raw_results, list)
    assert isinstance(indicators, list)
    assert isinstance(markdown[0], str)
    assert indicators[0].domain == value_to_check


def test_url_command(requests_mock):
    """Tests the url reputation command function.

    Configures requests_mock instance to generate the appropriate
    url reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from RSTCloudThreatFeedAPI import Client, url_command

    value_to_check = 'http://zpmagura.com/wp-content/nux5wem-08'
    mock_response = util_load_json('test_data/url_reputation.json')
    requests_mock.get(f'https://api.rstcloud.net/v1/ioc?value={value_to_check}', json=mock_response)

    client = Client(verify=False, apikey='test')
    args = {'url': value_to_check}
    markdown, raw_results, indicators = url_command(client, args)

    assert isinstance(markdown, list)
    assert isinstance(raw_results, list)
    assert isinstance(indicators, list)
    assert isinstance(markdown[0], str)
    assert indicators[0].url == value_to_check


def test_submit_command(requests_mock):
    """Tests the submission command function.

    Configures requests_mock instance to generate the appropriate
    submission API response. Checks
    the output of the command function with the expected output.
    """

    from RSTCloudThreatFeedAPI import Client, submit_command

    value_to_check = '1.1.1.1'
    mock_response = {"ioc_value": value_to_check, "status": "submitted"}
    requests_mock.post("https://api.rstcloud.net/v1/ioc", json=mock_response)

    client = Client(verify=False, apikey='test')
    args = {'ioc': value_to_check}
    markdown = submit_command(client, args)

    assert isinstance(markdown, list)
    assert markdown[0] == f'Indicator: {value_to_check} was submitted as a potential threat indicator to RST Cloud\n'


def test_submitfp_command(requests_mock):
    """Tests the False Positive submission command function.

    Configures requests_mock instance to generate the appropriate
    False Positive submission API response. Checks
    the output of the command function with the expected output.
    """

    from RSTCloudThreatFeedAPI import Client, submitfp_command

    value_to_check = '1.1.1.1'
    mock_response = {"ioc_value": value_to_check, "status": "submitted"}
    requests_mock.put("https://api.rstcloud.net/v1/ioc", json=mock_response)

    client = Client(verify=False, apikey='test')
    args = {'ioc': value_to_check}
    markdown = submitfp_command(client, args)

    assert isinstance(markdown, list)
    assert markdown[0] == f'Indicator: {value_to_check} was submitted as False Positive to RST Cloud\n'
