import pytest

import demistomock as demisto
from IsIncidentPartOfCampaign import check_incidents_ids_in_campaigns_list, get_incidents_ids_by_type, main

PHISHING_CAMPAIGN_INCIDENTS = [
    {'id': '1',
     'type': 'Phishing Campaign',
     'EmailCampaign': {'incidents': [{'id': '11'}, {'id': '12'}]}
     },
    {'id': '2',
     'type': 'Phishing Campaign',
     'EmailCampaign': {'incidents': [{'id': '21'}, {'id': '22'}]}
     },
]
OTHER_INCIDENTS = [
    {'id': '3',
     'type': 'Phishing',
     },
]


def _wrap_mocked_get_context(raw_incident):
    return [{'Contents': {'context': raw_incident}}]


def _wrap_mocked_get_incident(raw_incidents):
    return [{'Contents': {'data': raw_incidents}}]


@pytest.mark.parametrize('incidents_ids_set, result',
                         [({'11'}, '1'), ({'11', '21'}, '1'), ({'21', '22'}, '2'), ({'31'}, None)])
def test_check_incidents_ids_in_campaigns_list(mocker, incidents_ids_set, result):
    mocker.patch.object(demisto, 'executeCommand',
                        side_effect=[_wrap_mocked_get_context(incident) for incident in PHISHING_CAMPAIGN_INCIDENTS])
    assert result == check_incidents_ids_in_campaigns_list(['1', '2'], incidents_ids_set)


def test_check_incidents_ids_in_campaigns_list_no_incidents():
    assert check_incidents_ids_in_campaigns_list([], {'11', '12'}) is None


def test_get_incidents_ids_by_type(mocker):
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=_wrap_mocked_get_incident(PHISHING_CAMPAIGN_INCIDENTS + OTHER_INCIDENTS))
    assert get_incidents_ids_by_type('Phishing Campaign') == ['1', '2']


def test_get_incidents_ids_by_type_empty(mocker):
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=_wrap_mocked_get_incident(None))
    assert get_incidents_ids_by_type('Phishing Campaign') == []


def test_main(mocker):
    mocker.patch.object(demisto, 'args',
                        return_value={'CampaignIncidentType': 'Phishing Campaign', 'IncidentIDs': '11,21'})
    mocker.patch.object(demisto, 'executeCommand',
                        side_effect=[_wrap_mocked_get_incident(PHISHING_CAMPAIGN_INCIDENTS + OTHER_INCIDENTS)] + [
                            _wrap_mocked_get_context(incident) for incident in PHISHING_CAMPAIGN_INCIDENTS])
    results = main()
    assert results.readable_output == "Found campaign with ID - 1"
    assert results.outputs['ExistingCampaignID'] == '1'
    mocker.patch.object(demisto, 'executeCommand',
                        side_effect=[_wrap_mocked_get_incident(None)])
    results = main()
    assert results.readable_output == "No campaign has found"
    assert results.outputs['ExistingCampaignID'] is None
