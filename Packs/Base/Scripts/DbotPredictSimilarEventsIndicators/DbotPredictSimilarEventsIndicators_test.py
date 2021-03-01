from DbotPredictSimilarEventsIndicators import get_prediction_for_incident

from CommonServerPython import *


def executeCommand(command, args):
    indicator = [{'id': 'a', 'investigationIDs': ['1', '2', '10'], 'value': 'value_a', 'indicator_type': 'URL'},
                 {'id': 'b', 'investigationIDs': ['2', '10'], 'value': 'value_b', 'indicator_type': 'File'}]

    indicators_list = [{'id': 'a', 'investigationIDs': ['1', '2', '10'], 'value': 'value_a', 'indicator_type': 'File'},
                       {'id': 'b', 'investigationIDs': ['2', '10'], 'value': 'value_b', 'indicator_type': 'Domain'},
                       {'id': 'c', 'investigationIDs': ['3', '45'], 'value': 'value_c', 'indicator_type': 'Email'},
                       {'id': 'd', 'investigationIDs': ['1', '45'], 'value': 'value_d', 'indicator_type': 'File'},
                       {'id': 'c', 'investigationIDs': ['2', '45'], 'value': 'value_c', 'indicator_type': 'File'}
                       ]

    if command == 'findIndicators' and 'OR' in args['query']:
        return [{'Contents': indicators_list, 'Type': 'note'}]
    else:
        return [{'Contents': indicator, 'Type': 'note'}]


# samples Koch: 100(10710), 1000(14943),5000(explorer difficult), 6000, 10000
# Nil use 214 (similar incident to show 4703, 5293)


def test_get_prediction_for_incident(mocker):
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'maxIncidentsInIndicatorsForWhiteList': '150',
                            'aggreagateIncidents': 'True',
                            'minNumberOfIndicators': '0',
                            'threshold': '0.1',
                            'indicatorsTypes': 'File,  URL, IP, Domain, IPv6',
                            'showActualIncident': "True",
                            'maxIncidentsToDisplay': '150',
                            'fieldsIncidentToDisplay': 'type'
                        })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res = get_prediction_for_incident()
    # res.to_csv('view.csv')
    print(res)
