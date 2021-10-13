def mock_misp(mocker):
    from pymisp import ExpandedPyMISP
    mocker.patch.object(ExpandedPyMISP, '__init__', return_value=None)


def test_get_misp_threat_level(mocker):
    mock_misp(mocker)
    from MISP_V2 import get_misp_threat_level
    assert get_misp_threat_level('1') == 'HIGH'
    assert get_misp_threat_level('2') == 'MEDIUM'
    assert get_misp_threat_level('3') == 'LOW'
    assert get_misp_threat_level('4') == 'UNDEFINED'


def test_get_dbot_level(mocker):
    mock_misp(mocker)
    from MISP_V2 import get_dbot_level
    assert get_dbot_level('1') == 3
    assert get_dbot_level('2') == 3
    assert get_dbot_level('3') == 2
    assert get_dbot_level('4') == 0
    assert get_dbot_level('random') == 0


def test_convert_timestamp(mocker):
    mock_misp(mocker)
    from MISP_V2 import convert_timestamp
    assert convert_timestamp(1546713469) == "2019-01-05 18:37:49"


def test_build_list_from_dict(mocker):
    mock_misp(mocker)
    from MISP_V2 import build_list_from_dict
    lst = build_list_from_dict({'ip': '8.8.8.8', 'domain': 'google.com'})
    assert lst == [{'ip': '8.8.8.8'}, {'domain': 'google.com'}]


def test_extract_error(mocker):
    mock_misp(mocker)
    from MISP_V2 import extract_error
    error_response = [
        (
            403,
            {
                'name': 'Could not add object',
                'message': 'Could not add object',
                'url': '/objects/add/156/',
                'errors': 'Could not save object as at least one attribute has failed validation (ip). \
                        {"value":["IP address has an invalid format."]}'
            }
        )
    ]
    expected_response = [
        {
            'code': 403,
            'message': 'Could not add object',
            'errors': 'Could not save object as at least one attribute has failed validation (ip).      '
                      '                   {"value":["IP address has an invalid format."]}'
        }
    ]
    err = extract_error(error_response)
    assert err == expected_response

    error_response = [(404, {'name': 'Invalid event.', 'message': 'Invalid event.', 'url': '/objects/add/1546'})]
    expected_response = [{'code': 404, 'message': 'Invalid event.', 'errors': None}]
    err = extract_error(error_response)
    assert err == expected_response

    # Empty error
    err = extract_error([])
    assert err == []

    # TODO check errors


def test_build_misp_complex_filter(mocker):
    mock_misp(mocker)
    from MISP_V2 import build_misp_complex_filter

    old_query = "tag1"
    old_query_with_ampersand = "tag1&&tag2"
    old_query_with_not = "!tag1"

    actual = build_misp_complex_filter(old_query)
    assert actual == old_query

    actual = build_misp_complex_filter(old_query_with_ampersand)
    assert actual == old_query_with_ampersand

    actual = build_misp_complex_filter(old_query_with_not)
    assert actual == old_query_with_not

    complex_query_AND_single = "AND:tag1"
    expected = {'AND': ['tag1']}
    actual = build_misp_complex_filter(complex_query_AND_single)
    assert actual == expected

    complex_query_OR_single = "OR:tag1"
    expected = {'OR': ['tag1']}
    actual = build_misp_complex_filter(complex_query_OR_single)
    assert actual == expected

    complex_query_NOT_single = "NOT:tag1"
    expected = {'NOT': ['tag1']}
    actual = build_misp_complex_filter(complex_query_NOT_single)
    assert actual == expected

    complex_query_AND = "AND:tag1,tag2"
    expected = {'AND': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_AND)
    assert actual == expected

    complex_query_OR = "OR:tag1,tag2"
    expected = {'OR': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_OR)
    assert actual == expected

    complex_query_NOT = "NOT:tag1,tag2"
    expected = {'NOT': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_NOT)
    assert actual == expected

    complex_query_AND_OR = "AND:tag1,tag2;OR:tag3,tag4"
    expected = {'AND': ['tag1', 'tag2'], 'OR': ['tag3', 'tag4']}
    actual = build_misp_complex_filter(complex_query_AND_OR)
    assert actual == expected

    complex_query_OR_AND = "OR:tag3,tag4;AND:tag1,tag2"
    expected = {'OR': ['tag3', 'tag4'], 'AND': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_OR_AND)
    assert actual == expected

    complex_query_AND_NOT = "AND:tag1,tag2;NOT:tag3,tag4"
    expected = {'AND': ['tag1', 'tag2'], 'NOT': ['tag3', 'tag4']}
    actual = build_misp_complex_filter(complex_query_AND_NOT)
    assert actual == expected

    complex_query_NOT_AND = "NOT:tag3,tag4;AND:tag1,tag2"
    expected = {'NOT': ['tag3', 'tag4'], 'AND': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_NOT_AND)
    assert actual == expected

    complex_query_OR_NOT = "OR:tag1,tag2;NOT:tag3,tag4"
    expected = {'OR': ['tag1', 'tag2'], 'NOT': ['tag3', 'tag4']}
    actual = build_misp_complex_filter(complex_query_OR_NOT)
    assert actual == expected

    complex_query_NOT_OR = "NOT:tag3,tag4;OR:tag1,tag2"
    expected = {'NOT': ['tag3', 'tag4'], 'OR': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_NOT_OR)
    assert actual == expected

    complex_query_AND_OR_NOT = "AND:tag1,tag2;OR:tag3,tag4;NOT:tag5"
    expected = {'AND': ['tag1', 'tag2'], 'OR': ['tag3', 'tag4'], 'NOT': ['tag5']}
    actual = build_misp_complex_filter(complex_query_AND_OR_NOT)
    assert actual == expected


def test_data_filtering(mocker):
    mock_misp(mocker)
    mocker.patch('MISP_V2.DATA_KEYS_TO_SAVE', ['Category', 'EventID', 'UUID'])
    mocker.patch('MISP_V2.MAX_ATTRIBUTES', 1000)

    from test_data import test_constants
    from MISP_V2 import build_context

    full_response = test_constants.full_response_before_filtering
    filtered_response = test_constants.response_after_filtering_category_eventid_uuid
    assert build_context(full_response) == filtered_response


def test_attributes_data_filtering(mocker):
    mock_misp(mocker)

    from test_data import test_constants
    from MISP_V2 import build_attribute_context

    full_response = test_constants.full_attributes_response
    filtered_response = test_constants.filtered_attributes_response
    assert build_attribute_context(full_response) == filtered_response


def test_limit_data(mocker):
    """
   Scenario: Create context for misp event with limiting the amount of attributes

   Given:
   - event with 10 attributes
   - configuration to limit attributes to 3
   - attribute fields filter to 'EventID', 'Timestamp'.

   When:
   - Creating context for event

   Then:
   - only 3 of the most recent attributes are created for context
   """
    mock_misp(mocker)
    mocker.patch('MISP_V2.DATA_KEYS_TO_SAVE', ['EventID', 'Timestamp'])
    mocker.patch('MISP_V2.MAX_ATTRIBUTES', 3)

    from test_data import test_constants
    from MISP_V2 import build_context

    full_response = test_constants.full_response_before_filtering
    assert build_context(full_response)[0]['Attribute'] == test_constants.filtered_recent_attributes
