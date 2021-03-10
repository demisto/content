from DBotPredictSimilarEvents import get_prediction_for_incident

from CommonServerPython import *


def executeCommand(command, args):
    with open(
            '',
            'rb') as f:
        incidents = json.load(f)
    if command == 'GetIncidentsByQuery' and '-id' in args['query']:
        return [{'Contents': json.dumps(incidents), 'Type': 'note'}]
    else:
        return [{'Contents': json.dumps([incidents[10]]), 'Type': 'note'}]


# samples Koch: 100(10710), 1000(14943),5000(explorer difficult), 6000, 10000
# Nil use 214 (similar incident to show 4703, 5293)


def test_get_prediction_for_incident(mocker):
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': 'xdralert.destinationhostname, filename, command',
                            'similarCategoricalField': 'signature, filehash',
                            'similarJsonField': 'xdralerts',
                            'limit': 10000,
                            'fieldExactMatch': '',
                            'fieldsToDisplay': 'filehash, destinationip, closeNotes, sourceip, alertdescription',
                            'showDistance': True,
                            'confidence': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'Fals',
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res = get_prediction_for_incident()
    # res.to_csv('view.csv')
    print(res)
