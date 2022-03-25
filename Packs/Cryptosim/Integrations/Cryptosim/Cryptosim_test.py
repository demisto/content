import base64
import json
import Cryptosim
from Cryptosim import Client, correlation_alerts_command, correlations_command, fetch_incidents


authorization = "admin:admin"
auth_byte = authorization.encode('utf-8')
base64_byte = base64.b64encode(auth_byte)
base64_auth = base64_byte.decode('utf-8')
authValue = "Basic " + base64_auth

test_client = Client(
    base_url='https://127.0.0.1',
    verify=False,
    proxy=False,
    headers={
        "Content-Type": "application/json",
        'Authorization': authValue
    }
)


def test_correlations_command(request_mock):
    mock_response = {'StatusCode': 200,
                     'Data': [
                         {'Name': "Correlation1", 'CorrelationId': 1},
                         {'Name': "Correlation2", 'CorrelationId': 2},
                     ],
                     'OutParameters': None
                     }

    requests_mock.post("https://test.com/api/service/correlations",
                        json=mock_response)


    results = correlations_command(test_client)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'Correlations'


def test_correlation_alerts_command(request_mock):
    mock_response = {'StatusCode': 200,
                     'Data': [
                         {'CorrelationAlert': {"NAME": "name1", "changedKey1": "changedVal1"},
                          'Log': {"differentLog1": "differentValue1"}
                          },
                         {'CorrelationAlert': {"NAME": "name2", "changedKey2": "changedVal2"},
                          'Log': {"differentLog1": "differentValue1"}
                          }
                     ],
                     'OutParameters': None
                     }

    requests_mock.post("https://test.com/api/service/correlationalerts",
                        json=mock_response)


    results = correlation_alerts_command(test_client)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'CorrelationAlerts'


def test_fetch_incidents(request_mock, params):
    mock_response = ({"lastRun": "2022-03-25T14:13:20"},
                     [{
                         'name': "test_name",
                         'occurred': "2018-10-24T14:13:20:00",
                         'rawJSON': json.dumps({"NAME": "test1", "id": "123"}),
                         "severity": 2,
                         'type': 'Crpyotsim CorrelationAlert'
                     }])


    requests_mock.post("https://test.com/api/service/correlationalerts",
                        json=mock_response)
    max_fetch = 3
    next_run, incidents = fetch_incidents(test_client, {"max_fetch":max_fetch,"first_fetch":"2022-03-25T00:00:00"})
    assert next_run["lastRun"] == mock_response[0]["lastRun"]
    assert len(incidents) == max_fetch
    assert isinstance(incidents, list)
