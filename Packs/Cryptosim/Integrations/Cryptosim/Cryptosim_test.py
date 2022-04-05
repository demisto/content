import base64
from Cryptosim import Client, correlation_alerts_command, correlations_command, fetch_incidents

authorization = "admin:admin"
auth_byte = authorization.encode('utf-8')
base64_byte = base64.b64encode(auth_byte)
base64_auth = base64_byte.decode('utf-8')
authValue = "Basic " + base64_auth

test_client = Client(
    base_url='https://test.com',
    verify=False,
    proxy=False,
    headers={
        "Content-Type": "application/json",
        'Authorization': authValue
    }
)


def test_correlations_command(requests_mock):
    mock_response = {'StatusCode': 200,
                     'Data': [
                         {'Name': "Correlation1", 'CorrelationId': 1},
                         {'Name': "Correlation2", 'CorrelationId': 2},
                     ],
                     'OutParameters': None
                     }

    requests_mock.get("https://test.com/correlations?limit=100&sortType=asc", json=mock_response)

    results = correlations_command(test_client)
    assert {'StatusCode', 'Data', 'OutParameters'} <= {*results.outputs}
    assert results.outputs_prefix == 'Correlations'


def test_correlation_alerts_command(requests_mock):
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

    requests_mock.post("https://test.com/correlationalertswithlogs",
                       json=mock_response)

    results = correlation_alerts_command(test_client)
    assert {'StatusCode', 'Data', 'OutParameters'} <= {*results.outputs}
    assert results.outputs_prefix == 'CorrelationAlerts'


def test_fetch_incidents(requests_mock):
    mock_response = ({'StatusCode': 200,
                      'Data': [
                          {'CorrelationAlert': {"NAME": "name1", "changedKey1": "changedVal1",
                                                'CREATEDATE': "2022-03-28T14:30:20", },
                           'Log': {"differentLog1": "differentValue1"},
                           },
                          {'CorrelationAlert': {"NAME": "name2", "changedKey2": "changedVal2",
                                                'CREATEDATE': "2022-03-28T14:30:20", },
                           'Log': {"differentLog1": "differentValue1"},
                           }
                      ],
                      'OutParameters': None
                      })

    requests_mock.post("https://test.com/correlationalertswithlogs",
                       json=mock_response)
    max_fetch = 3
    next_run, incidents = fetch_incidents(test_client, {"max_fetch": max_fetch, "first_fetch": "1 hour"})
    assert len(incidents) <= max_fetch
    assert isinstance(incidents, list)
    if len(incidents) > 0:
        assert isinstance(incidents[0], dict)
        assert incidents[0]['type'] == 'Crpyotsim Correlation Alerts'


def test_fetct_incident_max(requests_mock):
    mock_response = ({'StatusCode': 200,
                      'Data': [
                          {'CorrelationAlert': {"NAME": "name1", "changedKey1": "changedVal1",
                                                'CREATEDATE': "2022-03-28T14:30:20", },
                           'Log': {"differentLog1": "differentValue1"},
                           },
                          {'CorrelationAlert': {"NAME": "name2", "changedKey2": "changedVal2",
                                                'CREATEDATE': "2022-03-28T14:30:20", },
                           'Log': {"differentLog1": "differentValue1"},
                           }
                      ],
                      'OutParameters': None
                      })

    requests_mock.post("https://test.com/correlationalertswithlogs",
                       json=mock_response)
    max_fetch = 1
    next_run, incidents = fetch_incidents(test_client, {"max_fetch": max_fetch, "first_fetch": "3 days"})
    assert len(incidents) <= max_fetch
