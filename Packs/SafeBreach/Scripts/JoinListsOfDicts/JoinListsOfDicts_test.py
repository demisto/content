import demistomock as demisto
from JoinListsOfDicts import main as JoinListsOfDicts

LEFT_DICTS = [{
    "insightIds": ['1', '2', '3'],
    "value": "value123"
}, {
    "insightIds": ['1'],
    "value": "value1"
}, {
    "insightIds": ['3'],
    "value": "value3"
}]

RIGHT_DICTS = [{
    "id": 1,
    "name": "someInsight 1"
}, {
    "id": 3,
    "name": "someInsight 3"
}]

LEFT_DICT = {
    "insightIds": ['1', '2', '3'],
    "value": "value123"
}

RIGHT_DICT = {
    "id": 2,
    "name": "someInsight 2"
}


def test_JoinListsOfDicts(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'rightkey': 'id',
        'key': 'insightIds',
        'right': RIGHT_DICTS,
        'value': LEFT_DICTS,  # left
    })
    mocker.patch.object(demisto, 'results')
    JoinListsOfDicts(demisto.args())
    list_join_indicators = demisto.results.call_args[0][0]
    assert len(list_join_indicators) == 4
    assert list_join_indicators[0]['insightIds'] == ['1', '2', '3']
    # verify that also single dict will work.
    mocker.patch.object(demisto, 'args', return_value={
        'rightkey': 'id',
        'key': 'insightIds',
        'right': RIGHT_DICT,
        'value': LEFT_DICT,  # left
    })
    mocker.patch.object(demisto, 'results')
    JoinListsOfDicts(demisto.args())
    single_join_indicator = demisto.results.call_args[0][0]
    assert len(single_join_indicator) == 1
    assert single_join_indicator[0]['insightIds'] == ['1', '2', '3']
