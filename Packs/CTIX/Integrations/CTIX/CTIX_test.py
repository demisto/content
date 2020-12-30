import io
import json

'''CONSTANTS'''

BASE_URL = "http://test.com/"
ACCESS_ID = "access_id"
SECRET_KEY = "secret_key"


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_ip(requests_mock):
    from CTIX import Client, ip_details_command
    from CommonServerPython import Common

    ip_to_check = '6.7.8.9'
    mock_response = util_load_json('test_data/ip_details.json')
    requests_mock.get(f'http://test.com/objects/indicator/?q={ip_to_check}',
                      json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={}
    )

    args = {
        'ip': ip_to_check,
        'enhanced': False
    }

    response = ip_details_command(client, args)

    assert response.outputs[0] == mock_response["results"][0]
    assert response.outputs_prefix == 'CTIX.IP'
    assert response.outputs_key_field == 'name2'

    assert isinstance(response.indicators, list)
    assert len(response.indicators) == 1
    assert isinstance(response.indicators[0], Common.IP)
    assert response.indicators[0].ip == ip_to_check


def test_domain(requests_mock):
    from CTIX import Client, domain_details_command
    from CommonServerPython import Common

    domain_to_check = 'testing.com'
    mock_response = util_load_json('test_data/domain_details.json')
    requests_mock.get(f'http://test.com/objects/indicator/?q={domain_to_check}',
                      json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={}
    )

    args = {
        'domain': domain_to_check,
        'enhanced': False
    }

    response = domain_details_command(client, args)

    assert response.outputs[0] == mock_response["results"][0]
    assert response.outputs_prefix == 'CTIX.Domain'
    assert response.outputs_key_field == 'name2'

    assert isinstance(response.indicators, list)
    assert len(response.indicators) == 1
    assert isinstance(response.indicators[0], Common.Domain)
    assert response.indicators[0].domain == domain_to_check


def test_url(requests_mock):
    from CTIX import Client, url_details_command
    from CommonServerPython import Common

    url_to_check = 'https://www.ibm.com/support/mynotifications/'
    mock_response = util_load_json('test_data/url_details.json')
    requests_mock.get(f'http://test.com/objects/indicator/?q={url_to_check}',
                      json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={}
    )

    args = {
        'url': url_to_check,
        'enhanced': False
    }

    response = url_details_command(client, args)

    assert response.outputs[0] == mock_response["results"][0]
    assert response.outputs_prefix == 'CTIX.URL'
    assert response.outputs_key_field == 'name2'

    assert isinstance(response.indicators, list)
    assert len(response.indicators) == 1
    assert isinstance(response.indicators[0], Common.URL)
    assert response.indicators[0].url == url_to_check


def test_file(requests_mock):
    from CTIX import Client, file_details_command
    from CommonServerPython import Common

    file_to_check = '4d552241543b8176a3189864a16b6052f9d163a124291ec9552e1b77'
    mock_response = util_load_json('test_data/file_details.json')
    requests_mock.get(f'http://test.com/objects/indicator/?q={file_to_check}',
                      json=mock_response)

    client = Client(
        base_url=BASE_URL,
        access_id=ACCESS_ID,
        secret_key=SECRET_KEY,
        verify=False,
        proxies={}
    )

    args = {
        'file': file_to_check,
        'enhanced': False
    }

    response = file_details_command(client, args)

    assert response.outputs[0] == mock_response["results"][0]
    assert response.outputs_prefix == 'CTIX.File'
    assert response.outputs_key_field == 'name2'

    assert isinstance(response.indicators, list)
    assert len(response.indicators) == 1
    assert isinstance(response.indicators[0], Common.File)
    assert response.indicators[0].name == file_to_check
