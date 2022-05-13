import demistomock as demisto

import ShowCampaignIncidentsOwners


def demisto_execute_command(command, args):
    return [{'Contents': '[{"owner": "owner_1"}, {"owner": "owner_2"}]', 'Type': 3}]


def test_show_incident_owners(mocker):
    """
    Given:
        - Incident IDs.
    When:
        - Running the show owners script main function.
    Then:
        - Ensure all the owners appear in the html result.
    """
    mocker.patch.object(ShowCampaignIncidentsOwners, 'get_incident_ids', return_value=['1', '2'])
    mocker.patch.object(demisto, 'incident', return_value={'owner': 'admin'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=demisto_execute_command)
    mocker.patch.object(demisto, 'results')

    ShowCampaignIncidentsOwners.main()
    res = demisto.results.call_args[0][0]['Contents']

    assert 'admin' in res and 'owner_1' in res and 'owner_2' in res
