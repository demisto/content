import pytest
import demistomock as demisto

from CommonServerPython import *
from SplitCampaignContext import filter_by_threshold

CONTEXT_EXAMPLE = [
    {
        "emailfrom": "example@example.com",
        "emailfromdomain": "example.com",
        "id": "1",
        "name": "example1",
        "occurred": "2021-07-15T11:24:46.869394623Z",
        "recipients": [
            "victim-test2@demistodev.onmicrosoft.com"
        ],
        "recipientsdomain": [
            "example.com"
        ],
        "severity": 3,
        "similarity": 1,
        "status": 1
    },
    {
        "emailfrom": "example@example.com",
        "emailfromdomain": "example.com",
        "id": "2",
        "name": "example2",
        "occurred": "2021-07-13T08:42:32.344058566Z",
        "recipients": [
            "victim-test2@demistodev.onmicrosoft.com"
        ],
        "recipientsdomain": [
            "example.com"
        ],
        "severity": 3,
        "similarity": 0.9,
        "status": 1
    },
    {
        "emailfrom": "example@example.com",
        "emailfromdomain": "example.com",
        "id": "398",
        "name": "example3",
        "occurred": "2021-07-13T08:47:28.067532466Z",
        "recipients": [
            "victim-test2@demistodev.onmicrosoft.com"
        ],
        "recipientsdomain": [
            "example.com"
        ],
        "severity": 3,
        "similarity": 0.85,
        "status": 1
    },
    {
        "emailfrom": "example@example.com",
        "emailfromdomain": "example.com",
        "id": "4",
        "name": "example4",
        "occurred": "2021-07-13T11:20:43.144384137Z",
        "recipients": [
            "victim-test2@demistodev.onmicrosoft.com"
        ],
        "recipientsdomain": [
            "example.com"
        ],
        "severity": 1,
        "similarity": 0.82,
        "status": 1
    }
]

CONTEXT_EXAMPLE_EMPTY = []
CASES = [
    (CONTEXT_EXAMPLE, 0.84,
     [{'emailfrom': 'example@example.com', 'emailfromdomain': 'example.com', 'id': '4', 'name': 'example4',
       'occurred': '2021-07-13T11:20:43.144384137Z', 'recipients': ['victim-test2@demistodev.onmicrosoft.com'],
       'recipientsdomain': ['example.com'], 'severity': 1, 'similarity': 0.82, 'status': 1}],
     [{'emailfrom': 'example@example.com', 'emailfromdomain': 'example.com', 'id': '1', 'name': 'example1',
       'occurred': '2021-07-15T11:24:46.869394623Z', 'recipients': ['victim-test2@demistodev.onmicrosoft.com'],
       'recipientsdomain': ['example.com'], 'severity': 3, 'similarity': 1, 'status': 1},
      {'emailfrom': 'example@example.com', 'emailfromdomain': 'example.com', 'id': '2', 'name': 'example2',
       'occurred': '2021-07-13T08:42:32.344058566Z', 'recipients': ['victim-test2@demistodev.onmicrosoft.com'],
       'recipientsdomain': ['example.com'], 'severity': 3, 'similarity': 0.9, 'status': 1},
      {'emailfrom': 'example@example.com', 'emailfromdomain': 'example.com', 'id': '398', 'name': 'example3',
       'occurred': '2021-07-13T08:47:28.067532466Z', 'recipients': ['victim-test2@demistodev.onmicrosoft.com'],
       'recipientsdomain': ['example.com'], 'severity': 3, 'similarity': 0.85, 'status': 1}]),

    (CONTEXT_EXAMPLE_EMPTY, 0.84, [], [])
]



@pytest.mark.parametrize('context, threshold, expected_low, expected_high', CASES)
def test_filter_by_threshold(context, threshold, expected_low, expected_high):
    low, high = filter_by_threshold(context, threshold)
    assert low == expected_low, high == expected_high
