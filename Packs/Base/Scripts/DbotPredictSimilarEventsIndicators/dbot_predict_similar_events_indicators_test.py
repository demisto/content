from collections import defaultdict

import pytest

from CommonServerPython import *
from DbotPredictSimilarEventsIndicators import identity_score, match_indicators_incident, get_indicators_map, Tfidf, \
    Transformer, Model, get_number_of_invs_for_indicators, get_prediction_for_incident

indicator = [{'id': 'a', 'investigationIDs': ['1', '2', '10'], 'value': 'value_a', 'indicator_type': 'URL'},
             {'id': 'b', 'investigationIDs': ['2', '10'], 'value': 'value_b', 'indicator_type': 'File'}]

indicators_list = [{'id': 'a', 'investigationIDs': ['1', '2', '10'], 'value': 'value_a', 'indicator_type': 'File'},
                   {'id': 'b', 'investigationIDs': ['2', '10'], 'value': 'value_b', 'indicator_type': 'Domain'},
                   {'id': 'c', 'investigationIDs': ['3', '45'], 'value': 'value_c', 'indicator_type': 'Email'},
                   {'id': 'd', 'investigationIDs': ['1', '45'], 'value': 'value_d', 'indicator_type': 'File'},
                   {'id': 'c', 'investigationIDs': ['2', '45'], 'value': 'value_c', 'indicator_type': 'File'}
                   ]


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


TRANSFORMATION = {
    'indicators': {'transformer': Tfidf,
                   'normalize': None,
                   'params': {'analyzer': 'word', 'max_features': 200, 'token_pattern': '.'},  # [\d\D]*
                   'scoring': {'scoring_function': identity_score, 'min': 0.5}
                   }
}


def test_get_number_of_invs_for_indicators(mocker):
    assert get_number_of_invs_for_indicators(indicator[0]) == 3


def test_get_indicators_map(mocker):
    res = {
        'a': indicator[0],
        'b': indicator[1]
    }
    assert get_indicators_map(indicator) == res


def test_match_indicators_incident(mocker):
    res = {'1': ['a', 'd'], '2': ['a', 'b', 'c']}
    assert match_indicators_incident(indicators_list, ['1', '2']) == res


def test_get_prediction_for_incident(mocker):
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'maxIncidentsInIndicatorsForWhiteList': '150',
                            'aggreagateIncidents': 'True',
                            'minNumberOfIndicators': '0',
                            'threshold': '0.1',
                            'indicatorsTypes': 'File,  URL, IP, Domain, IPv6'
                        })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    get_prediction_for_incident()
