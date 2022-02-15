import pytest

import demistomock as demisto
from IsIncidentPartOfCampaign import check_incidents_ids_in_campaign, get_incidents_ids_by_type, main

PHISHING_CAMPAIGN_INCIDENTS = [
    {'id': '1',
     'type': 'Phishing Campaign',
     'EmailCampaign': {'incidents': [{'id': '11'}, {'id': '12'}]},
     },
    {'id': '2',
     'type': 'Phishing Campaign',
     'EmailCampaign': {'incidents': [{'id': '21'}, {'id': '22'}]},
     },
]
OTHER_INCIDENTS = [
    {'id': '3',
     'type': 'Phishing',
     },
]


def _wrap_mocked_get_context(raw_incident):
    return [{'Type': 'note', 'Contents': {'context': raw_incident}}]


def _wrap_mocked_get_incident(raw_incidents):
    return [{'Type': 'note', 'Contents': {'data': raw_incidents}}]


@pytest.mark.parametrize('incidents_ids_set, result',
                         [({'11'}, True), ({'11', '21'}, True), ({'31'}, False)])
def test_check_incidents_ids_in_campaign(mocker, incidents_ids_set, result):
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=_wrap_mocked_get_context(PHISHING_CAMPAIGN_INCIDENTS[0]))
    assert result == check_incidents_ids_in_campaign('1', incidents_ids_set)


def test_check_incidents_ids_in_campaign_no_incidents():
    assert check_incidents_ids_in_campaign([], {'11', '12'}) is False


class TestGetIncidentsIDsByType:
    @staticmethod
    def test_sanity(mocker):
        """
        Given:
            Incident type
        When:
            Calling get_incident_ids_by_type
        Then:
            Only incidents with the given type are returned.
        """
        mocker.patch.object(demisto, 'executeCommand',
                            side_effect=[
                                _wrap_mocked_get_incident(PHISHING_CAMPAIGN_INCIDENTS + OTHER_INCIDENTS),
                                _wrap_mocked_get_incident([])])
        assert list(get_incidents_ids_by_type('Phishing Campaign')) == ['1', '2']

    @staticmethod
    def test_get_incidents_ids_by_type_empty(mocker):
        """
        Given:
            non existing Incident type
        When:
            Calling get_incident_ids_by_type
        Then:
            Only incident with the given type are returned.
        """
        mocker.patch.object(demisto, 'executeCommand',
                            return_value=_wrap_mocked_get_incident(None))
        assert list(get_incidents_ids_by_type('Phishing Campaign')) == []


class TestMain:
    @staticmethod
    def test_sanity(mocker):
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

    @staticmethod
    def test_main_pagination(mocker):
        """
        Given
            a campaign incident type
            incident ID part of a campaign
        When
            calling the script
        Then
            return the correct campaign ID which appears in the second incidents page
        """
        mocker.patch.object(demisto, 'args', return_value={
            'CampaignIncidentType': 'Phishing Campaign',
            'IncidentIDs': '123'
        })
        mocker.patch.object(demisto, 'executeCommand', side_effect=[
            _wrap_mocked_get_incident(OTHER_INCIDENTS * 2),
            _wrap_mocked_get_incident(PHISHING_CAMPAIGN_INCIDENTS),
            _wrap_mocked_get_context({'EmailCampaign': {'incidents': [{'id': '11'}, {'id': '12'}]}}),
            _wrap_mocked_get_context({'EmailCampaign': {'incidents': [{'id': '11'}, {'id': '123'}]}}),
        ])

        results = main()
        assert results.readable_output == 'Found campaign with ID - 2'
        assert results.outputs['ExistingCampaignID'] == '2'


def test_where_no_campaign_ids(mocker):
    """
    Given
        Incidents to check if they are part of campaign.
    When
        Getting some incidents campaign ids which are not related to the given incident ids.
    Then
        Ensure the results returned nothing.
    """
    import IsIncidentPartOfCampaign

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(IsIncidentPartOfCampaign, 'get_incidents_ids_by_type', return_value=[1, 2, 3])
    mocker.patch.object(IsIncidentPartOfCampaign, 'check_incidents_ids_in_campaign', return_value=False)

    command_results = main()

    assert command_results.readable_output == "No campaign has found"
    assert command_results.outputs['ExistingCampaignID'] is None
