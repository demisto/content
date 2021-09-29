import pytest
import SplitCampaignContext

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
       'recipientsdomain': ['example.com'], 'severity': 3, 'similarity': 0.85, 'status': 1}], False),
    (CONTEXT_EXAMPLE, 0.84, [],
     [{'emailfrom': 'example@example.com', 'emailfromdomain': 'example.com', 'id': '4', 'name': 'example4',
       'occurred': '2021-07-13T11:20:43.144384137Z', 'recipients': ['victim-test2@demistodev.onmicrosoft.com'],
       'recipientsdomain': ['example.com'], 'severity': 1, 'similarity': 0.82, 'status': 1},
      {'emailfrom': 'example@example.com', 'emailfromdomain': 'example.com', 'id': '4', 'name': 'example4',
       'occurred': '2021-07-13T11:20:43.144384137Z', 'recipients': ['victim-test2@demistodev.onmicrosoft.com'],
       'recipientsdomain': ['example.com'], 'severity': 1, 'similarity': 0.85, 'status': 1}], True
     ),
    (CONTEXT_EXAMPLE_EMPTY, 0.84, [], [], False)
]


@pytest.mark.parametrize('context, threshold, expected_low, expected_high, part_of_campaign', CASES)
def test_filter_by_threshold(mocker, context, threshold, expected_low, expected_high, part_of_campaign):
    """
    Given:
        Context with incidents with different similarities and a threshold for low similarity
    When:
        Splitting context to low/ high similarity incidents
    Then:
        Makes sure the incidents with low similarities goes to 'low' similarity and the rest to 'high'
    """
    mocker.patch.object(SplitCampaignContext, '_get_incident_campaign', return_value=part_of_campaign)
    low, high = SplitCampaignContext.filter_by_threshold(context, threshold)
    assert low == expected_low, high == expected_high


CAMPAIGN_CASES = [(CONTEXT_EXAMPLE, 0.84)]


@pytest.mark.parametrize('context, threshold', CAMPAIGN_CASES)
def test_filter_by_threshold_with_campaign(mocker, context, threshold):
    """
    Given:
        Context with incidents with campaign id and a threshold for low similarity
    When:
        Splitting context to low/ high similarity incidents
    Then:
        Makes sure the incidents with campaign goes to 'high' similarity.
    """
    mocker.patch.object(SplitCampaignContext, '_get_incident_campaign', return_value=2)
    low, high = SplitCampaignContext.filter_by_threshold(context[-1:], threshold)
    assert low == [], high == [
        {'emailfrom': 'example@example.com', 'emailfromdomain': 'example.com', 'id': '4', 'name': 'example4',
         'occurred': '2021-07-13T11:20:43.144384137Z', 'recipients': ['victim-test2@demistodev.onmicrosoft.com'],
         'recipientsdomain': ['example.com'], 'severity': 1, 'similarity': 0.82, 'status': 1}]
