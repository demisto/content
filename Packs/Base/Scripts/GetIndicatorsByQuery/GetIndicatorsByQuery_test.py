from CommonServerPython import *

from GetIndicatorsByQuery import main

ioc1 = {
    'id': 1,
    'value': 'abc@demisto.com',
    'indicator_type': 'Email',
    'score': 2,
    'CustomFields': {
        'testField': "testValue",
        'test2Fields': "testValue2"
    },
}

ioc2 = {
    'id': 2,
    'value': 'abc2@demisto.com',
    'indicator_type': 'Email',
    'score': 2,
    'CustomFields': {
        'testField': "testValue",
        'test2Fields': "testValue2"
    },
}

search_indicators_side_effect = [{'iocs': [ioc1, ioc2]}, StopIteration]


def get_args():
    args = {}
    args['limit'] = 500
    args['offset'] = 0
    return args


def get_args_with_hashing():
    args = {}
    args['limit'] = 500
    args['offset'] = 0
    args['fieldsToHash'] = 'test2*'
    return args


def get_args_with_populate():
    args = {}
    args['limit'] = 500
    args['offset'] = 0
    args['populateFields'] = 'testField,indicator_type'
    return args


def get_args_with_unpopulate():
    args = {}
    args['limit'] = 500
    args['offset'] = 0
    args['dontPopulateFields'] = 'testField,indicator_type'
    return args


def test_main(mocker):
    mocker.patch.object(demisto, 'args', side_effect=get_args)
    mocker.patch('CommonServerPython.IndicatorsSearcher.__next__', side_effect=search_indicators_side_effect)

    entry = main()
    indicators = entry['Contents']
    assert len(indicators) == 2
    assert indicators[0]['indicator_type'] == 'Email'
    assert indicators[0]['test2Fields'] == 'testValue2'


def test_main_with_hashing(mocker):
    mocker.patch.object(demisto, 'args', side_effect=get_args_with_hashing)
    mocker.patch('CommonServerPython.IndicatorsSearcher.__next__', side_effect=search_indicators_side_effect)

    entry = main()
    indicators = entry['Contents']
    assert len(indicators) == 2
    assert indicators[0]['indicator_type'] == 'Email'
    assert indicators[0]['test2Fields'] == '19a5feec8b080d4865be5c7f69c320db'


def test_main_populate(mocker):
    mocker.patch.object(demisto, 'args', side_effect=get_args_with_populate)
    mocker.patch('CommonServerPython.IndicatorsSearcher.__next__', side_effect=search_indicators_side_effect)

    entry = main()
    indicators = entry['Contents']
    assert len(indicators) == 2
    assert set(indicators[0].keys()) == set(['indicator_type', 'testField'])


def test_main_unpopulate(mocker):
    mocker.patch.object(demisto, 'args', side_effect=get_args_with_unpopulate)
    mocker.patch('CommonServerPython.IndicatorsSearcher.__next__', side_effect=search_indicators_side_effect)
    entry = main()
    indicators = entry['Contents']
    assert len(indicators) == 2
    assert 'testField' not in indicators[0].keys()
    assert 'indicator_type' not in indicators[0].keys()
