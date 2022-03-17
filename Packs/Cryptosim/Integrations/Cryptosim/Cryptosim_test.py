import base64
import json
import Cryptosim
from Cryptosim import Client, correlation_alerts_command, correlations_command, fetch_incidents


authorization = "admin:admin"
auth_byte= authorization.encode('utf-8')
base64_byte = base64.b64encode(auth_byte)
base64_auth = base64_byte.decode('utf-8')
authValue = "Basic " + base64_auth 

test_client = Client(
    base_url='https://127.0.0.1',
    verify=False,
    proxy=False,
    headers = {
        "Content-Type": "application/json",
        'Authorization': authValue
    }
)

def test_correlations_command():
    mock_response = {'StatusCode': 200,
                     'Data': [
                                {'Name': "Correlation1", 'CorrelationId': 1},
                                {'Name': "Correlation2", 'CorrelationId': 2},
                            ],
                     'OutParameters': None
                     }
    requests_mock.get("https://test.com/api/service/correlations",
                        json=mock_response)

    results = correlations_command(test_client)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'Correlations'



def test_correlation_alerts_command():
    mock_response = {'StatusCode': 200,
                     'Data': [
                         {'CorrelationAlert': {"NAME":"name1","changedKey1":"changedVal1"},
                          'Log': {"differentLog1":"differentValue1"}
                          },
                         {'CorrelationAlert': {"NAME":"name2","changedKey2":"changedVal2"},
                          'Log': {"differentLog1":"differentValue1"}
                         }
                     ],
                     'OutParameters': None
                     }

    requests_mock.get("https://test.com/api/service/correlationalerts",
                        json=mock_response)

    results = correlation_alerts_command(test_client)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'Correlations'

def test_fetch_incidents(client):
    mock_response = ( {"lastRun": "2018-10-24T14:13:20+00:00"},
                      [{
                        'name': "test_name",
                        'occurred': "2018-10-24T14:13:20+00:00",
                        'rawJSON': json.dumps({"NAME":"test1","id":"123"}),
                        "severity": 2,
                        'type': 'Crpyotsim CorrelationAlert'
                    }])

    requests_mock.get("https://test.com/api/service/correlationalerts",
                        json=mock_response)
    next_run, incidents = fetch_incidents(test_client)
    assert next_run == {"lastRun": "2018-10-24T14:13:20+00:00"}
    assert isinstance(incidents, list)
