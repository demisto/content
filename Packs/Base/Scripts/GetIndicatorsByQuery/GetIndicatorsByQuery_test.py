from CommonServerPython import *
import pytest
from GetIndicatorsByQuery import main, get_parsed_populated_fields

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


def search_indicators_side_effect(**kwargs):
    def parse_ioc(ioc: dict[str, Any]) -> dict:
        if not (fields_to_populate := argToList(kwargs.get('populateFields'))):
            return ioc
        custom_fields = {k: v for k, v in ioc['CustomFields'].items() if k in fields_to_populate}
        ioc = {k: v for k, v in ioc.items() if k in fields_to_populate}
        return ioc | {"CustomFields": custom_fields}

    return {'iocs': [parse_ioc(ioc1.copy()), parse_ioc(ioc2.copy())], 'total': 2}


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
    mocker.patch.object(demisto, 'searchIndicators', side_effect=search_indicators_side_effect)

    entry = main()
    indicators = entry['Contents']
    assert len(indicators) == 2
    assert indicators[0]['indicator_type'] == 'Email'
    assert indicators[0]['test2Fields'] == 'testValue2'


def test_main_with_hashing(mocker):
    mocker.patch.object(demisto, 'args', side_effect=get_args_with_hashing)
    mocker.patch.object(demisto, 'searchIndicators', side_effect=search_indicators_side_effect)

    entry = main()
    indicators = entry['Contents']
    assert len(indicators) == 2
    assert indicators[0]['indicator_type'] == 'Email'
    assert indicators[0]['test2Fields'] == '19a5feec8b080d4865be5c7f69c320db'


def test_main_populate(mocker):
    """
    Given:
    - Command arguments: populateFields="testField,indicator_type", dontPopulateFields is not provided
    When:
    - Running GetIndicatorsByQuery
    Then:
    - Ensure the expected fields are returned
    - Ensure `populateFields` kwarg was passed to `searchIndicators` call
    """
    mocker.patch.object(demisto, 'args', side_effect=get_args_with_populate)
    search_indicators = mocker.patch.object(demisto, 'searchIndicators', side_effect=search_indicators_side_effect)

    entry = main()
    indicators = entry['Contents']
    assert len(indicators) == 2
    assert set(indicators[0].keys()) == {'indicator_type', 'testField'}
    assert "populateFields" in search_indicators.call_args.kwargs


def test_main_unpopulate(mocker):
    """
    Given:
    - Command arguments: dontPopulateFields="testField,indicator_type", populateFields is not provided
    When:
    - Running GetIndicatorsByQuery
    Then:
    - Ensure the expected fields are not returned
    - Ensure `populateFields` kwarg wasn't passed to `searchIndicators` call
    """
    mocker.patch.object(demisto, 'args', side_effect=get_args_with_unpopulate)
    search_indicators = mocker.patch.object(demisto, 'searchIndicators', side_effect=search_indicators_side_effect)
    entry = main()
    indicators = entry['Contents']
    assert len(indicators) == 2
    assert 'testField' not in indicators[0].keys()
    assert 'indicator_type' not in indicators[0].keys()
    assert "populateFields" not in search_indicators.call_args.kwargs


@pytest.mark.parametrize("fields_to_parse, expected_result", [
    pytest.param("ALL", None, id="Overriding non possible empty parameter."),
    pytest.param([], frozenset(), id="Case impossible due to yml default values"),
    pytest.param(["field1", "field2", "field3"], frozenset(["field1", "field2", "field3"]), id="Normal fields populating"),
    pytest.param(["field1", "field1", "field2"], frozenset(["field1", "field2"]), id="Normal fields populating with duplicates"),
    pytest.param(["field1", "RelatedIncCount"], frozenset(
        ["field1", "RelatedIncCount", "investigationsCount"]), id="populating `RelatedIncCount` field"),
    pytest.param(["field1", "investigationsCount"], frozenset(
        ["field1", "investigationsCount"]), id="populating `investigationsCount` field"),
    pytest.param(["ALL", "field1", "field2"], None, id="Using both `ALL` and other fields."),
])
def test_get_parsed_populated_fields(fields_to_parse, expected_result):
    """
    Given: A list of fields to parse for an indicator
    When: The function is called with these fields
    Then: returns a frozenset containing the parsed fields (according to API need), or None if all fields are requested.
    """

    result = get_parsed_populated_fields(fields_to_parse)
    assert result == expected_result
