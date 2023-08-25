import MITREIndicatorsByOpenIncidentsv2
from CommonServerPython import *


def test_mitre_indicators_by_open_incidents_v2(mocker):
    """
    Given:
        - A search_indicators_by_version result with iocs.
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure that the iocs values appear in the Human Readable result.
    """

    mocker.patch.object(IndicatorsSearcher,
                        'search_indicators_by_version',
                        return_value={'total': 0, 'iocs': [{'value': '1'}, {'value': '2'}, {'value': '3'}],
                                      'searchAfter': None, 'accountErrors': None, 'totalAccounts': 0})
    mocker.patch.object(demisto, 'args', return_value={'from': '2023-07-25', 'to': '2023-07-26'})
    mocker.patch.object(demisto, 'results')
    MITREIndicatorsByOpenIncidentsv2.main()

    assert "\n| 1 |  |  |  |\n| 2 |  |  |  |\n| 3 |  |  |  |\n" in demisto.results.call_args_list[0].args[0]["HumanReadable"]


def test_mitre_indicators_by_open_incidents_v2_empty_iocs(mocker):
    """
    Given:
        - A search_indicators_by_version result with empty iocs (iocs: None which is a valid response from the server).
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure that the scripts completed the run with no errors.
    """
    mocker.patch.object(IndicatorsSearcher,
                        'search_indicators_by_version',
                        return_value={'total': 0, 'iocs': None, 'searchAfter': None, 'accountErrors': None, 'totalAccounts': 0})
    mocker.patch.object(demisto, 'args', return_value={'from': '2023-07-25', 'to': '2023-07-26'})
    mocker.patch.object(demisto, 'results')
    MITREIndicatorsByOpenIncidentsv2.main()

    assert "### MITRE ATT&CK techniques by related Incidents\n**No entries.**\n" in \
           demisto.results.call_args_list[0].args[0]["HumanReadable"]
