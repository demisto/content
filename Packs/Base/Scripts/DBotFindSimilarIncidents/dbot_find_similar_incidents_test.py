import pandas as pd
# from CommonServerPython import *
# import pytest
from DBotFindSimilarIncidents import *

TRANSFORMATION = {
    'commandline': {'transformer': Tfidf,
                    'normalize': normalize_command_line,
                    'params': {'analyzer': 'char', 'max_features': 2000, 'ngram_range': (1, 5)},
                    'scoring': {'scoring_function': cdist_new, 'min': 0.5}
                    },

    'url': {'transformer': Tfidf,
            'normalize': normalize_identity,
            'params': {'analyzer': 'char', 'max_features': 100, 'ngram_range': (1, 5)},
            'scoring': {'scoring_function': cdist_new, 'min': 0.5}
            },
    'potentialMatch': {'transformer': Identity,
                       'normalize': None,
                       'params': {},
                       'scoring': {'scoring_function': identity, 'min': 0.5}
                       },
    'json': {'transformer': Tfidf,
             'normalize': normalize_json,
             'params': {'analyzer': 'word', 'max_features': 5000, 'ngram_range': (1, 5)},  # , 'max_df': 0.2
             'scoring': {'scoring_function': cdist_new, 'min': 0.5}
             }

}

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


def test_score(mocker):
    normalize_function = TRANSFORMATION['indicators']['normalize']
    incident = pd.DataFrame({'indicators': ['1 2 3 4 5 6']})
    # Check if incident is rare then the score is higher
    incidents_1 = pd.DataFrame({'indicators': ['1 2', '1 3', '1 3']})
    tfidf = FrequencyIndicators('indicators', normalize_function, incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))
    # Check if same rarity then same scores
    incidents_1 = pd.DataFrame({'indicators': ['1 2', '3 4']})
    tfidf = FrequencyIndicators('indicators', normalize_function, incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] == scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))
    # Check if more indicators in commun them better score
    incidents_1 = pd.DataFrame({'indicators': ['1 2 3', '4 5', '6']})
    tfidf = FrequencyIndicators('indicators', normalize_function, incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))
