import json
import io
import base64
from wsgiref import headers
from Cryptosim import Client, correlation_alerts_command, correlations_command


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_correlations_command(requests_mock):
    mock_response = {'StatusCode': 200,
                     'Data': [
                                {'Name': "Correlation1", 'CorrelationId': 1},
                                {'Name': "Correlation2", 'CorrelationId': 2},
                            ],
                     'OutParameters': None
                     }
    requests_mock.get("https://test.com/api/service/correlations",
                        json=mock_response)


    authorization = "admin:admin"
    auth_byte= authorization.encode('utf-8')
    base64_byte = base64.b64encode(auth_byte)
    base64_auth = base64_byte.decode('utf-8')
    authValue = "Basic " + base64_auth 

    headers = {
        "Content-Type": "application/json",
        'Authorization': authValue
    }
    client = Client(
        base_url="https://test.com",
        verify=False,
        headers=headers
        proxy=False)

    results = correlations_command(client)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'Correlations'



def test_correlation_alerts_command(requests_mock):
    mock_response = {'StatusCode': 200,
                     'Data': [
                         {'Name': "Correlation1", 'CorrelationId': 1},
                         {'Name': "Correlation2", 'CorrelationId': 2},
                     ],
                     'OutParameters': None
                     }

    requests_mock.get("https://test.com/api/service/correlationalerts",
                        json=mock_response)
    client = Client(
        base_url="https://test.com",
        verify=False,
        auth=("test", "test"),
        proxy=False)

    args = {
        'startDate': '2022-01-20T12:00:00',
        'endDate': '2022-01-20T24:00:00'
    }
    results = correlation_alerts_command(client, args)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'Correlations'
