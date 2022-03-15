import base64
import Cryptosim
from Cryptosim import Client, correlation_alerts_command, correlations_command


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
    client = Client(base_url="https://test.com", verify=False, headers=headers, proxy=False)

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
    client = Client(base_url="https://test.com", verify=False, auth=("test", "test"), proxy=False)


    results = correlation_alerts_command(client)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'Correlations'
