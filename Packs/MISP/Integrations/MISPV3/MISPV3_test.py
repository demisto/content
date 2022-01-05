import pytest
import io
from CommonServerPython import *
from CommonServerPython import DemistoException, Common

TAG_IDS_LISTS = [([1, 2, 3], [2, 3, 4, 5], [1, 2, 3], [4, 5]),
                 ([1, 2, 3], [4, 5], [1, 2, 3], [4, 5])]

ATTRIBUTE_TAG_LIMIT = [{'ID': '1', 'Name': 'Tag1'}, {'ID': '2', 'Name': 'misp-galaxy:tag2'},
                       {'ID': '3', 'Name': 'misp-galaxy:tag3'}]
INVALID_HASH_ERROR = "Invalid hash length, enter file hash of format MD5, SHA-1 or SHA-256'"
REPUTATION_COMMANDS_ERROR_LIST = [
    ("FILE", "invalid_hash", INVALID_HASH_ERROR),  # invalid HASH,
    ("IP", "1.2.3", "Error: The given IP address: 1.2.3 is not valid"),  # invalid IP,
    ("DOMAIN", "invalid_domain", "Error: The given domain: invalid_domain is not valid"),  # invalid DOMAIN,
    ("URL", "invalid_url", "Error: The given url: invalid_url is not valid"),  # invalid URL,
    ("EMAIL", "invalid_email", "Error: The given invalid_email address: example is not valid"),  # invalid EMAIL,
]

CASE_OF_MALICIOUS_ATTRIBUTE = (['1'], ['2'], ['1'], ['4'], Common.DBotScore.BAD, '1', False)
CASE_OF_SUSPICIOUS_ATTRIBUTE = (['1'], ['2'], ['2'], ['1'], Common.DBotScore.SUSPICIOUS, '1', False)
CASE_OF_MALICIOUS_EVENT = (['8'], ['2'], ['2'], ['1'], Common.DBotScore.BAD, '2', False)
CASE_OF_SUSPICIOUS_EVENT = (['8'], ['2'], ['3'], ['2'], Common.DBotScore.SUSPICIOUS, '2', False)
CASE_OF_UNKNOWN = (['1'], ['2'], ['3'], ['4'], Common.DBotScore.NONE, None, False)
CASE_OF_BAD_THREAT_LEVEL_ID = (['1'], ['2'], ['3'], ['4'], Common.DBotScore.BAD, None, True)
TEST_TAG_SCORES = [CASE_OF_MALICIOUS_ATTRIBUTE, CASE_OF_SUSPICIOUS_ATTRIBUTE, CASE_OF_MALICIOUS_EVENT,
                   CASE_OF_SUSPICIOUS_EVENT, CASE_OF_UNKNOWN, CASE_OF_BAD_THREAT_LEVEL_ID]

VALID_DISTRIBUTION_LIST = [(0, 0), ("1", 1), ("Your_organization_only", 0)]
INVALID_DISTRIBUTION_LIST = ["invalid_distribution", 1.5, "53.5"]

TEST_PREPARE_ARGS = [({'type': '1', 'to_ids': 0, 'from': '2', 'to': '3', 'event_id': '4', 'last': '5',
                       'include_decay_score': 0, 'include_sightings': 0, 'include_correlations': 0,
                       'enforceWarninglist': 0, 'tags': 'NOT:param3', 'value': 6, 'category': '7', 'limit': 10,
                       'org': 7}, {'type_attribute': '1', 'to_ids': 0, 'date_from': '2', 'date_to': '3',
                                   'eventid': ['4'], 'publish_timestamp': '5', 'include_decay_score': 0,
                                   'include_sightings': 0, 'include_correlations': 0, 'enforceWarninglist': 0,
                                   'limit': 10, 'tags': {'NOT': ['param3']}, 'org': 7, 'value': 6, 'category': '7',
                                   'controller': 'attributes'}),
                     ({}, {'limit': '50', 'controller': 'attributes'})  # default value
                     ]

TEST_EVENTS_INCLUDE_DETECTED_TAG = [("2", ['149', '145', '144']),  # 3 events include the detected tag
                                    ("278", ['145']),  # 1 event includes the detected attribute's tag
                                    (None, []),  # no tag was detected, no event returns
                                    ("104", ['149'])]  # 1 event includes the detected event's tag


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def mock_misp(mocker):
    from pymisp import ExpandedPyMISP
    mocker.patch.object(ExpandedPyMISP, '__init__', return_value=None)
    mocker.patch.object(demisto, 'params', return_value={'credentials': {'password': "123"}})


def test_misp_convert_timestamp_to_date_string(mocker):
    """

    Given:
    - MISP response includes timestamp.

    When:
    - Getting Timestamp of a misp event ot attribute.

    Then:
    - Ensure timestamp converted successfully to human readable format.
    """
    mock_misp(mocker)
    from MISPV3 import misp_convert_timestamp_to_date_string
    assert misp_convert_timestamp_to_date_string(1546713469) == "2019-01-05T18:37:49Z"


def test_build_list_from_dict(mocker):
    """

    Given:
    - Dictionary describes MISP object

    When:
    - Trying to use MISP's GenericObjectGenerator.

    Then:
    - The dict was parsed to a list.
    """
    mock_misp(mocker)
    from MISPV3 import dict_to_generic_object_format
    lst = dict_to_generic_object_format({'ip': '8.8.8.8', 'domain': 'google.com'})
    assert lst == [{'ip': '8.8.8.8'}, {'domain': 'google.com'}]


def test_extract_error(mocker):
    """

    Given:
    - list of responses from error section.

    When:
    - Getting response with errors from MISP.

    Then:
    - Ensures that the error was extracted correctly.

    Examples:
        extract_error([
            (403,
                {
                    'name': 'Could not add object',
                    'message': 'Could not add object',
                    'url': '/objects/add/156/',
                    'errors': 'Could not save object as at least one attribute has failed validation (ip). \
                    {"value":["IP address has an invalid format."]}'
                }
            )
        ])

        Response:
        [{
            'code': 403,
            'message': 'Could not add object',
            'errors': 'Could not save object as at least one attribute has failed validation (ip). \
            {"value":["IP address has an invalid format."]}'
        }]
    """
    mock_misp(mocker)
    from MISPV3 import extract_error
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


def test_build_misp_complex_filter(mocker):
    """

    Given:
    - A complex query contains saved words: 'AND:', 'OR:' and 'NOT:'.

    When:
    - Calling a command that uses 'tags' as input.

    Then:
    - Ensure the input query converted to ש dictionary created for misp to perform complex query.

    Example:
    demisto_query should look like:
        example 1: "AND:param1,param2;OR:param3;NOT:param4,param5"
        example 2: "NOT:param3,param5"
        example 3 (simple syntax): "param1,param2"
    """
    mock_misp(mocker)
    from MISPV3 import build_misp_complex_filter

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


def test_is_tag_list_valid(mocker):
    """

    Given:
    - a tag list ids

    When:
    - configuring a MISP instance.

    Then:
    - Ensure the all the ids are valid.
    """
    mock_misp(mocker)
    from MISPV3 import is_tag_list_valid
    is_tag_list_valid(["200", 100])
    assert True


def test_is_tag_list_invalid(mocker):
    """

    Given:
    - a tag list ids

    When:
    - configuring a MISP instance.

    Then:
    - Ensure that an error is returned when an id is invalid.
    """
    mock_misp(mocker)
    from MISPV3 import is_tag_list_valid
    with pytest.raises(DemistoException) as e:
        is_tag_list_valid(["abc", 100, "200", -1, '0'])
        if not e:
            assert False


@pytest.mark.parametrize('malicious_tag_ids, suspicious_tag_ids, return_malicious_tag_ids, return_suspicious_tag_ids',
                         TAG_IDS_LISTS)
def test_handle_tag_duplication_ids(mocker, malicious_tag_ids, suspicious_tag_ids, return_malicious_tag_ids,
                                    return_suspicious_tag_ids):
    """

    Given:
    - 2 lists of tag ids: one for malicious and the other one is for suspicious.

    When:
    - configuring a MISP instance.

    Then:
    - Ensure that in case an id exists in both lists, it will be removed from the suspicious one.
    """
    mock_misp(mocker)
    from MISPV3 import handle_tag_duplication_ids
    assert return_malicious_tag_ids, return_suspicious_tag_ids == handle_tag_duplication_ids(malicious_tag_ids,
                                                                                             suspicious_tag_ids)


def test_convert_arg_to_misp_args(mocker):
    """
    Given:
    - demisto args includes '_'.

    When:
    - Using the integrations' commands.

    Then:
    - Ensure args with '_' converted to be with '-'.
    """
    mock_misp(mocker)
    from MISPV3 import convert_arg_to_misp_args
    args = {'dst_port': 8001, 'src_port': 8002, 'name': 'test'}
    args_names = ['dst_port', 'src_port', 'name']
    assert convert_arg_to_misp_args(args, args_names) == [{'dst-port': 8001}, {'src-port': 8002}, {'name': 'test'}]


@pytest.mark.parametrize('dbot_type, value, error_expected', REPUTATION_COMMANDS_ERROR_LIST)
def test_reputation_value_validation(mocker, dbot_type, value, error_expected):
    """

    Given:
    - an indicator type and value

    When:
    - Running a reputation command (ip, domain, email, url, file).

    Then:
    - Ensure that the value is valid (depends on the type).
    """
    mock_misp(mocker)
    from MISPV3 import reputation_value_validation
    with pytest.raises(DemistoException) as e:
        reputation_value_validation(value, dbot_type)
        assert error_expected in str(e.value)


@pytest.mark.parametrize('is_event_level, expected_output, expected_tag_list_ids', [
    (False, ATTRIBUTE_TAG_LIMIT, {'1', '3'}),
    (True, ATTRIBUTE_TAG_LIMIT, {'1', '3', '2'})])
def test_limit_tag_output(mocker, is_event_level, expected_output, expected_tag_list_ids):
    """
    Given:
    -   is_event_level (bool): whether this is a dict of event. False is for attribute level.
        ATTRIBUTE_TAG_LIMIT: list includes a dict of MISP tags.

    When:
    -   parsing a reputation response from MISP.

    Then:
    - Ensure that the Tag section is limited to include only name and id.
    """
    mock_misp(mocker)
    from MISPV3 import limit_tag_output_to_id_and_name
    mock_tag_json = util_load_json("test_data/Attribute_Tags.json")
    outputs, tag_list_id = limit_tag_output_to_id_and_name(mock_tag_json, is_event_level)
    assert outputs == expected_output
    assert tag_list_id == expected_tag_list_ids


@pytest.mark.parametrize('attribute_tags_ids, event_tags_ids, malicious_tag_ids, suspicious_tag_ids, '
                         'expected_score, found_tag, is_attribute_in_event_with_bad_threat_level', TEST_TAG_SCORES)
def test_get_score(mocker, attribute_tags_ids, event_tags_ids, malicious_tag_ids, suspicious_tag_ids,
                   expected_score, found_tag, is_attribute_in_event_with_bad_threat_level):
    """

    Given:
    - 4 lists that include tag ids.
        attribute_tags_ids : all tag ids of an attribute.
        event_tags_ids: all tag ids of an event.
        malicious_tag_ids: tag ids that defined to be recognized as malicious.
        suspicious_tag_ids: tag ids that defined to be recognized as  suspicious.

    When:
    - Running a reputation command and want to get the dbot score.

    Then:
    - Check that the returned score matches the expected one, depends on the given lists.
    - Check that the tag id matched the expected one to be identified, depends on the given lists.
    """
    mock_misp(mocker)
    from MISPV3 import get_score
    score, tag = get_score(attribute_tags_ids, event_tags_ids, malicious_tag_ids, suspicious_tag_ids,
                           is_attribute_in_event_with_bad_threat_level)
    assert score == expected_score
    assert tag == found_tag


def test_event_response_to_markdown_table(mocker):
    """

    Given:
    - A MISP event search response (json).

    When:
    - Running misp-search-events command.

    Then:
    - Ensure that the output to human readable is valid and was parsed correctly.
    """
    mock_misp(mocker)
    from MISPV3 import event_to_human_readable
    event_response = util_load_json("test_data/event_response_to_md.json")
    md = event_to_human_readable(event_response)[0]
    assert md['Event ID'] == '1'
    assert md['Event Tags'] == ["Tag1", "misp-galaxy:tag2", "misp-galaxy:tag3"]
    assert md['Event Galaxies'] == ["galaxy1", "galaxy2"]
    assert md['Event Objects'] == ["obj1", "obj2"]
    assert md['Publish Timestamp'] == '2021-06-16 08:35:01'
    assert md['Event Info'] == 'Test'
    assert md['Event Org ID'] == '1'
    assert md['Event Orgc ID'] == '8'
    assert md['Event Distribution'] == '0'
    assert md['Event UUID'] == '5e6b322a-9f80-4e2f-9f2a-3cab0a123456'


def test_attribute_response_to_markdown_table(mocker):
    """

    Given:
    - A MISP attribute search response (json).

    When:
    - Running misp-search-attributes command.

    Then:
    - Ensure that the output to human readable is valid and was parsed correctly.
    """
    mock_misp(mocker)
    from MISPV3 import attribute_response_to_markdown_table
    attribute_response = util_load_json("test_data/attribute_response_to_md.json")
    md = attribute_response_to_markdown_table(attribute_response)[0]
    assert md['Attribute ID'] == "1"
    assert md['Event ID'] == "2"
    assert md['Attribute Category'] == "Payload delivery"
    assert md['Attribute Type'] == "md5"
    assert md['Attribute Value'] == "6c73d338ec64e0e44bd54ea123456789"
    assert md['Attribute Tags'] == ["Tag1", "misp-galaxy:tag2", "misp-galaxy:tag3"]
    assert md['To IDs'] is True
    assert md['Event Info'] == 'Test'
    assert md['Event Organization ID'] == '1'
    assert md['Event Distribution'] == '0'
    assert md['Event UUID'] == '5e6b322a-9f80-4e2f-9f2a-3cab0a123456'


@pytest.mark.parametrize('detected_tag, expected_related_events', TEST_EVENTS_INCLUDE_DETECTED_TAG)
def test_get_events_related_to_scored_tag(mocker, detected_tag, expected_related_events):
    """

    Given:
    - detected_tag - a tag id that was detected as malicious or suspicious.
    - expected_related_events - All events that include detected_tag.

    When:
    - After running a reputation command

    Then:
    - Ensure that the returned list includes only the events that has detected_tag.
    """
    mock_misp(mocker)
    from MISPV3 import get_events_related_to_scored_tag
    reputation_command_outputs = util_load_json("test_data/reputation_command_outputs.json")
    events_to_human_readable = get_events_related_to_scored_tag(reputation_command_outputs.get('Attribute'),
                                                                detected_tag)
    all_event_ids_found = [event.get('Event_ID') for event in events_to_human_readable]
    assert all_event_ids_found == expected_related_events


def test_parse_response_reputation_command(mocker):
    """

    Given:
    - a response of reputation command.

    When:
    - searching for an attribute by a given value.

    Then:
    -  Ensure that the output is valid and was parsed correctly.
    """
    mock_misp(mocker)
    from MISPV3 import parse_response_reputation_command
    reputation_response = util_load_json("test_data/reputation_command_response.json")
    reputation_expected = util_load_json("test_data/reputation_command_outputs.json")
    malicious_tag_ids = ['279', '131']
    suspicious_tag_ids = ['104']
    attribute_limit = 3
    outputs, _, _, _ = parse_response_reputation_command(reputation_response, malicious_tag_ids, suspicious_tag_ids,
                                                         attribute_limit)
    assert outputs == reputation_expected


@pytest.mark.parametrize('demisto_args, expected_args', TEST_PREPARE_ARGS)
def test_prepare_args_to_search(mocker, demisto_args, expected_args):
    """

    Given:
    - demisto args.

    When:
    - running every integration command, when switching the given args to MISP's args format.

    Then:
    - Ensure that the conversion to MISP args format is valid.
    """
    mock_misp(mocker)
    from MISPV3 import prepare_args_to_search
    import demistomock
    mocker.patch.object(demistomock, 'args', return_value=demisto_args)
    assert prepare_args_to_search('attributes') == expected_args


def test_build_events_search_response(mocker):
    """

    Given:
    - A MISP event search response (json).

    When:
    - Running misp-search-events command.

    Then:
    - Ensure that the output to context data is valid and was parsed correctly.
    """
    mock_misp(mocker)
    from MISPV3 import build_events_search_response, EVENT_FIELDS
    search_response = util_load_json("test_data/search_event_by_tag.json")
    search_expected_output = util_load_json("test_data/search_event_by_tag_outputs.json")
    search_outputs = build_events_search_response(search_response, {'include_feed_correlations': True})
    for actual_event, expected_event in zip(search_outputs, search_expected_output):
        for event_field in EVENT_FIELDS:
            if actual_event.get(event_field):
                assert actual_event.get(event_field) == expected_event.get(event_field)


def test_build_events_search_response_without_feed_correlations(mocker):
    """

    Given:
    - A MISP event search response (json).

    When:
    - Running misp-search-events command.

    Then:
    - Ensure that the output to context data is valid and was parsed correctly.
    """
    mock_misp(mocker)
    from MISPV3 import build_events_search_response, EVENT_FIELDS
    search_response = util_load_json("test_data/search_event_by_tag.json")
    search_expected_output = util_load_json("test_data/search_event_by_tag_no_feed_outputs.json")
    search_outputs = build_events_search_response(search_response, {'include_feed_correlations': False})
    for actual_event, expected_event in zip(search_outputs, search_expected_output):
        for event_field in EVENT_FIELDS:
            if actual_event.get(event_field):
                assert actual_event.get(event_field) == expected_event.get(event_field)


def test_build_attributes_search_response(mocker):
    """

    Given:
    - A MISP attribute search response (json).

    When:
    - Running misp-search-attributes command.

    Then:
    - Ensure that the output to context data is valid and was parsed correctly.
    """
    mock_misp(mocker)
    from MISPV3 import build_attributes_search_response, ATTRIBUTE_FIELDS
    search_response = util_load_json("test_data/search_attribute_by_type.json")
    search_expected_output = util_load_json("test_data/search_attribute_by_type_outputs.json")
    search_outputs = build_attributes_search_response(search_response)
    for actual_attribute, expected_attribute in zip(search_outputs, search_expected_output):
        for event_field in ATTRIBUTE_FIELDS:
            if actual_attribute.get(event_field):
                assert actual_attribute.get(event_field) == expected_attribute.get(event_field)
