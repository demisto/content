import demistomock as demisto
from ListGroupBy import main as ListGroupBy

LIST_JOIN_INDICATORS = [{'insightIds': ['1', '2', '3'], 'value': 'value123', 'id': 1, 'name': 'someInsight 1'},
                        {'insightIds': ['1', '2', '3'], 'value': 'value123', 'id': 3, 'name': 'someInsight 3'},
                        {'insightIds': ['1'], 'value': 'value1', 'id': 1, 'name': 'someInsight 1'},
                        {'insightIds': ['3'], 'value': 'value3', 'id': 3, 'name': 'someInsight 3'}]


def test_list_group_by(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'keys': 'id,name',
        'outputkey': 'value',
        'separator': ',',
        'value': LIST_JOIN_INDICATORS
    })
    mocker.patch.object(demisto, 'results')
    ListGroupBy(demisto.args())
    res = demisto.results.call_args[0][0]
    assert len(res) == 2
    assert res[0]['value'] == 'value123,value1'
