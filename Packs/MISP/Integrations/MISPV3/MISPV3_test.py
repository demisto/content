import pytest
from CommonServerPython import *
from CommonServerPython import DemistoException, Common
from requests.models import Response

TAG_IDS_LISTS = [([1, 2, 3], [2, 3, 4, 5], [4, 6, 7], [1, 2, 3], [4, 5], [6, 7]),
                 ([1, 2, 3], [4, 5], [6, 7], [1, 2, 3], [4, 5], [6, 7])]

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

CASE_OF_MALICIOUS_ATTRIBUTE = (['1'], ['2'], ['1'], ['4'], ['5'], Common.DBotScore.BAD, '1', False)
CASE_OF_SUSPICIOUS_ATTRIBUTE = (['1'], ['2'], ['2'], ['1'], ['5'], Common.DBotScore.SUSPICIOUS, '1', False)
CASE_OF_BENIGN_ATTRIBUTE = (['5'], ['2'], ['2'], ['1'], ['5'], Common.DBotScore.GOOD, '5', False)
CASE_OF_MALICIOUS_EVENT = (['8'], ['2'], ['2'], ['1'], ['5'], Common.DBotScore.BAD, '2', False)
CASE_OF_SUSPICIOUS_EVENT = (['8'], ['2'], ['3'], ['2'], ['5'], Common.DBotScore.SUSPICIOUS, '2', False)
CASE_OF_BENIGN_EVENT = (['8'], ['5'], ['3'], ['3'], ['5'], Common.DBotScore.GOOD, '5', False)
CASE_OF_UNKNOWN = (['1'], ['2'], ['3'], ['4'], ['5'], Common.DBotScore.NONE, None, False)
CASE_OF_BAD_THREAT_LEVEL_ID = (['1'], ['2'], ['3'], ['4'], ['5'], Common.DBotScore.BAD, None, True)
TEST_TAG_SCORES = [CASE_OF_MALICIOUS_ATTRIBUTE, CASE_OF_SUSPICIOUS_ATTRIBUTE, CASE_OF_BENIGN_ATTRIBUTE, CASE_OF_MALICIOUS_EVENT,
                   CASE_OF_SUSPICIOUS_EVENT, CASE_OF_BENIGN_EVENT, CASE_OF_UNKNOWN, CASE_OF_BAD_THREAT_LEVEL_ID]

VALID_DISTRIBUTION_LIST = [(0, 0), ("1", 1), ("Your_organization_only", 0)]
INVALID_DISTRIBUTION_LIST = ["invalid_distribution", 1.5, "53.5"]

TEST_PREPARE_ARGS = [({'type': '1', 'to_ids': 0, 'from': '2', 'to': '3', 'event_id': '4', 'last': '5',
                       'include_decay_score': 0, 'include_sightings': 0, 'include_correlations': 0,
                       'enforceWarninglist': 0, 'tags': 'NOT:param3', 'value': 6, 'category': '7', 'limit': 10,
                       'org': 7, 'with_attachments': 'true'},
                      {'type_attribute': ['1'], 'to_ids': 0, 'date_from': '2', 'date_to': '3',
                       'eventid': ['4'], 'publish_timestamp': '5', 'include_decay_score': 0,
                       'include_sightings': 0, 'include_correlations': 0, 'enforceWarninglist': 0,
                       'limit': 10, 'tags': {'NOT': ['param3']}, 'org': 7, 'value': 6, 'category': '7',
                       'with_attachments': 1}),
                     ({}, {'limit': '50', 'controller': 'attributes', 'with_attachments': 0})  # default value
                     ]

TEST_EVENTS_INCLUDE_DETECTED_TAG = [("2", ['149', '145', '144']),  # 3 events include the detected tag
                                    ("278", ['145']),  # 1 event includes the detected attribute's tag
                                    (None, []),  # no tag was detected, no event returns
                                    ("104", ['149'])]  # 1 event includes the detected event's tag


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
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
            raise AssertionError


@pytest.mark.parametrize('malicious_tag_ids, suspicious_tag_ids, benign_tag_ids, return_malicious_tag_ids, '
                         'return_suspicious_tag_ids, return_benign_tag_ids',
                         TAG_IDS_LISTS)
def test_handle_tag_duplication_ids(mocker, malicious_tag_ids, suspicious_tag_ids, benign_tag_ids, return_malicious_tag_ids,
                                    return_suspicious_tag_ids, return_benign_tag_ids):
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
    assert (return_malicious_tag_ids, return_suspicious_tag_ids, return_benign_tag_ids) == handle_tag_duplication_ids(
        malicious_tag_ids,
        suspicious_tag_ids,
        benign_tag_ids
    )


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


@pytest.mark.parametrize('dbot_type, dbot_score_type, value, expected_type_object', [
    ("IP", DBotScoreType.IP, "123.123.123.123", Common.IP),
    ("DOMAIN", DBotScoreType.DOMAIN, "example.org", Common.Domain),
    ("EMAIL", DBotScoreType.EMAIL, "admin@admin.test", Common.EMAIL),
    ("URL", DBotScoreType.URL, "https://example.org", Common.URL)
])
def test_get_dbot_indicator(
    dbot_type: str,
    dbot_score_type: DBotScoreType,
    value: Any,
    expected_type_object: Any
) -> None:

    from MISPV3 import get_dbot_indicator
    score: Common.DBotScore = Common.DBotScore(
        indicator=value,
        indicator_type=dbot_score_type,
        score=Common.DBotScore.GOOD,
        reliability=DBotScoreReliability.A,
        malicious_description="Match found in MISP")
    object = get_dbot_indicator(dbot_type, score, value)
    assert isinstance(object, expected_type_object)


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


@pytest.mark.parametrize('attribute_tags_ids, event_tags_ids, malicious_tag_ids, suspicious_tag_ids, benign_tag_ids, '
                         'expected_score, found_tag, is_attribute_in_event_with_bad_threat_level', TEST_TAG_SCORES)
def test_get_score(mocker, attribute_tags_ids, event_tags_ids, malicious_tag_ids, suspicious_tag_ids, benign_tag_ids,
                   expected_score, found_tag, is_attribute_in_event_with_bad_threat_level):
    """

    Given:
    - 4 lists that include tag ids.
        attribute_tags_ids : all tag ids of an attribute.
        event_tags_ids: all tag ids of an event.
        malicious_tag_ids: tag ids that defined to be recognized as malicious.
        suspicious_tag_ids: tag ids that defined to be recognized as suspicious.
        benign_tag_ids: tag ids that defined to be recognized as benign.

    When:
    - Running a reputation command and want to get the dbot score.

    Then:
    - Check that the returned score matches the expected one, depends on the given lists.
    - Check that the tag id matched the expected one to be identified, depends on the given lists.
    """
    mock_misp(mocker)
    from MISPV3 import get_score
    score, tag = get_score(attribute_tags_ids, event_tags_ids, malicious_tag_ids, suspicious_tag_ids,
                           benign_tag_ids, is_attribute_in_event_with_bad_threat_level)
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
    benign_tag_ids = []
    attribute_limit = 3
    outputs, _, _, _ = parse_response_reputation_command(reputation_response, malicious_tag_ids, suspicious_tag_ids,
                                                         benign_tag_ids, attribute_limit)
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


def test_warninglist_response(mocker):
    """

    Given:
    - A MISP warninglist response (json).

    When:
    - Running misp-check-warninglist command.

    Then:
    - Ensure that the readable output to context data is valid and was parsed correctly.
    """
    mock_misp(mocker)
    from MISPV3 import warninglist_command
    demisto_args = {"value": "8.8.8.8"}
    warninglist_response = util_load_json("test_data/warninglist_response.json")
    with open("test_data/warninglist_outputs.md", encoding="utf-8") as f:
        warninglist_expected_output = f.read()
    mocker.patch("pymisp.ExpandedPyMISP.values_in_warninglist", return_value=warninglist_response)
    assert warninglist_command(demisto_args).to_context()['HumanReadable'] == warninglist_expected_output


def get_response(status_code, mocker, mock_response_key):
    the_response = Response()
    the_response.status_code = status_code
    the_response.request = mocker.patch.object(
        demisto,
        'internalHttpRequest',
        return_value={
            'body': json.dumps({'key': 'value'}),
            'headers': json.dumps({'key': 'value'})
        }
    )
    file = util_load_json("test_data/response_mock_add_email_object_test.json")[mock_response_key]

    def json_func():
        return file
    the_response.json = json_func
    return the_response


@pytest.mark.parametrize('file_path, expected_output_key, mock_response_key', [
    ("test_data/test_add_email_object_case_1.eml", "expected_output_case_1", "response_mock_case_1"),
    ("test_data/test_add_email_object_case_2.eml", "expected_output_case_2", "response_mock_case_2"),
    ("test_data/test_add_email_object_case_3.eml", "expected_output_case_3", "response_mock_case_3")])
def test_add_email_object(file_path, expected_output_key, mock_response_key, mocker):
    """
    Given:
    - file path to a .eml file.
    - case 1: regular gmail format mail.
    - case 2: mail from TPB.
    - case 3: mail with attachments.
    When:
    - Running add_email_object command.
    Then:
    - Ensure that the extraction of the information occured correctly and in the right format.
    - case 1: should return true.
    - case 2: should return true.
    - case 3: should return true.
    """
    from MISPV3 import add_email_object
    import pymisp
    event_id = 1231
    demisto_args: dict = {'entry_id': "", 'event_id': event_id}
    mocker.patch.object(demisto, "getFilePath", return_value={
                        "path": file_path
                        })
    mocked_response = get_response(200, mocker, mock_response_key)
    mocker.patch.object(pymisp.api.PyMISP, "_prepare_request", return_value=mocked_response)
    mocker.patch.object(pymisp.api.PyMISP, "_check_response", return_value=mocked_response.json())
    pymisp.ExpandedPyMISP.global_pythonify = False
    output = add_email_object(demisto_args).outputs
    expected_output = util_load_json("test_data/response_mock_add_email_object_test.json")[expected_output_key]
    assert output == expected_output


def test_fail_to_add_email_object(mocker):
    """
    Given:
    - case 1: 404 status code.
    When:
    - Running add_email_object command.
    Then:
    - Ensure that the error code was parsed into the response, was caught and handeled as a DemistoException.
    - case 1: Should catch a DemistoException and return true.
    """
    from MISPV3 import add_email_object
    import pymisp
    event_id = 1231
    demisto_args: dict = {'entry_id': "", 'event_id': event_id}
    mocker.patch.object(demisto, "getFilePath", return_value={
                        "path": "test_data/test_add_email_object_case_1.eml"
                        })
    mocked_response = get_response(404, mocker, "response_mock_case_1")
    mocker.patch.object(pymisp.api.PyMISP, "_prepare_request", return_value=mocked_response)
    pymisp.ExpandedPyMISP.global_pythonify = True
    with pytest.raises(DemistoException) as exception_info:
        add_email_object(demisto_args)
    assert "404" in str(exception_info.value)


def test_add_msg_email_object(mocker):
    """
    Given:
    - an msg email file.
    When:
    - Running add_email_object command.
    Then:
    - Ensure Demisto exception is raised with the correct error.
    """
    from MISPV3 import add_email_object
    event_id = 1231
    demisto_args: dict = {'entry_id': "", 'event_id': event_id}
    mocker.patch.object(demisto, "getFilePath", return_value={
                        "name": "test_add_email_object_case_1.msg",
                        "path": "test_data/test_add_email_object_case_1.msg"
                        })
    with pytest.raises(DemistoException) as exception_info:
        add_email_object(demisto_args)
    assert 'misp-add-email-object command does not support *.msg files' in str(exception_info.value)


def test_add_custom_object(mocker):
    """
    Given:
    - A custom template name.
    When:
    - Running add_custom_object command.
    Then:
    - Ensure that the readable output is valid.
    """
    from MISPV3 import add_custom_object_command
    event_id = 1572

    result_object_templates = util_load_json('test_data/response_object_templates.json')
    mocker.patch('MISPV3.PYMISP.object_templates', return_value=result_object_templates)

    response_raw_obj_tempalte = util_load_json('test_data/response_raw_object_template.json')
    mocker.patch('MISPV3.PYMISP.get_raw_object_template', return_value=response_raw_obj_tempalte)

    response_add_obj = util_load_json('test_data/response_add_object.json')
    mocker.patch('MISPV3.PYMISP.add_object', return_value=response_add_obj)

    demisto_args = {
        "event_id": event_id,
        "template": "corporate-asset",
        "attributes": "{'asset-type': 'Server','asset-id': '1','text': 'test text'}"
    }

    result = add_custom_object_command(demisto_args)
    expected_output = {
        'readable_output': f'Object has been added to MISP event ID {event_id}',
        'outputs': response_add_obj
    }
    assert result.readable_output == expected_output['readable_output']


@pytest.mark.parametrize(
    'demisto_args, is_attribute, expected_result',
    [
        (
            {'uuid': 'test_uuid', 'tag': 'test_tag', 'disable_output': True},
            True,
            {
                'readable_output': 'Tag test_tag has been successfully added to attribute test_uuid',
                'outputs': None,
                'outputs_prefix': None,
            }
        ),
        (
            {'uuid': 'test_uuid', 'tag': 'test_tag', 'disable_output': False},
            True,
            {
                'readable_output': 'Tag test_tag has been successfully added to attribute test_uuid',
                'outputs': {'test': 'test'},
                'outputs_prefix': 'MISP.Attribute',
            }
        ),
        (
            {'uuid': 'test_uuid', 'tag': 'test_tag', 'disable_output': False},
            False,
            {
                'readable_output': 'Tag test_tag has been successfully added to event test_uuid',
                'outputs': {'test': 'test'},
                'outputs_prefix': 'MISP.Event',
            }
        )
    ]
)
def test_add_tag(demisto_args: dict, is_attribute: bool, expected_result: dict, mocker):
    """
    Given:
    - Various arguments that the add_tag function accepts.

    When:
    - The `disable_output` and `is_attribute` arguments changes each run.

    Then:
    - Ensure that the returned `CommandResults` are modified by the given arguments.
    """
    mock_misp(mocker)
    from MISPV3 import add_tag
    from pymisp import ExpandedPyMISP
    mocker.patch.object(ExpandedPyMISP, 'tag', return_value={})
    mocked_search = mocker.patch.object(ExpandedPyMISP, 'search', return_value={})
    mocker.patch('MISPV3.build_attributes_search_response', return_value={'test': 'test'})
    mocker.patch('MISPV3.build_events_search_response', return_value={'test': 'test'})
    result = add_tag(demisto_args, is_attribute=is_attribute)

    assert bool(mocked_search.call_count) == ((is_attribute and not demisto_args['disable_output']) or not is_attribute)
    assert result.readable_output == expected_result['readable_output']
    assert result.outputs == expected_result['outputs']
    assert result.outputs_prefix == expected_result['outputs_prefix']


def test_add_user_to_misp(mocker):
    """
    Given:
    - A mocker object for patching the 'add_user' function.
    - A mock response representing the user details.

    When:
    - Calling the `add_user_to_misp` function with a set of arguments.

    Then:
    - Ensure that the function successfully adds a new user to MISP and returns the expected output.
    """
    from MISPV3 import add_user_to_misp
    mock_response = {
        'User':
        {
            'id': '1',
            'password': '*****',
            'org_id': '1',
            'server_id': '1',
            'email': 'test@example.com',
            'autoalert': False,
            'authkey': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
            'invited_by': '1',
            'gpgkey': '',
            'certif_public': '',
            'nids_sid': '1111111',
            'termsaccepted': False,
            'newsread': '1',
            'role_id': '1',
            'change_pw': True,
            'contactalert': False,
            'disabled': False,
            'expiration': None,
            'current_login': '0',
            'last_login': '0',
            'force_logout': False,
            'date_created': '1111111111',
            'date_modified': '1111111111'
        }
    }
    mocker.patch('MISPV3.PYMISP.add_user', return_value=mock_response)
    demisto_args = {
        'email': 'test@example.com',
        'org_id': '123',
        'role_id': '456',
        'password': 'password123'
    }
    result = add_user_to_misp(demisto_args)
    expected_output = {
        'readable_output': '## MISP add user\nNew user was added to MISP.\nEmail:test@example.com',
        'raw_response': mock_response.get('User', {}),
        'outputs': mock_response.get('User', {})
    }
    assert result.readable_output == expected_output['readable_output']
    assert result.raw_response == expected_output['raw_response']
    assert result.outputs == expected_output['outputs']


def test_get_organizations_info(mocker):
    """
    Given:
    - A mocker object for patching the `organisations` function.

    When:
    - Calling the `get_organizations_info` function.

    Then:
    - Ensure that the function successfully retrieves the organizations information and returns the expected output.
    """
    from MISPV3 import get_organizations_info

    mock_organizations = [
        {'Organisation': {'id': 1, 'name': 'Org1'}},
        {'Organisation': {'id': 2, 'name': 'Org2'}}
    ]
    mocker.patch('MISPV3.PYMISP.organisations', return_value=mock_organizations)
    result = get_organizations_info()
    expected_output = {
        'MISP.Organization': [
            {'id': 1, 'name': 'Org1'},
            {'id': 2, 'name': 'Org2'}
        ]
    }
    assert result.outputs == expected_output['MISP.Organization']


def test_get_role_info(mocker):
    """
    Given:
    - A mocker object for patching the `roles` function.

    When:
    - Calling the `get_role_info` function.

    Then:
    - Ensure that the function successfully retrieves the role information and returns the expected output.
    """
    from MISPV3 import get_role_info
    mock_roles = [
        {'Role': {'id': 1, 'name': 'Role1'}},
        {'Role': {'id': 2, 'name': 'Role2'}}
    ]
    mocker.patch('MISPV3.PYMISP.roles', return_value=mock_roles)
    result = get_role_info()
    expected_output = {
        'MISP.Role': [
            {'id': 1, 'name': 'Role1'},
            {'id': 2, 'name': 'Role2'}
        ]
    }
    assert result.outputs == expected_output['MISP.Role']


@pytest.mark.parametrize(('value, dbot_type, malicious_tag_ids'
                          ', suspicious_tag_ids, benign_tag_ids, reliability'
                          ', attributes_limit, search_warninglists'), [
    ("192.168.0.1", "IP", {}, {}, {}, DBotScoreReliability.A, 50, True)
])
def test_get_indicator_results(
    value,
    dbot_type,
    malicious_tag_ids,
    suspicious_tag_ids,
    benign_tag_ids,
    reliability,
    attributes_limit,
    search_warninglists,
    mocker
):
    """Tests the get indicator results function"""

    mock_misp(mocker)
    from MISPV3 import get_indicator_results
    from pymisp import ExpandedPyMISP
    import pymisp
    mocker.patch.object(ExpandedPyMISP, 'search', return_value={})
    mocker.patch('MISPV3.build_attributes_search_response', return_value={'test': 'test'})
    mocker.patch('MISPV3.build_events_search_response', return_value={'test': 'test'})
    response: Response = Response()

    def json_func():
        return {
            "192.168.0.1": [{
                "id": "100",
                "name": "my_custom_list"
            }]
        }
    response.json = json_func
    mocker.patch.object(pymisp.api.PyMISP, "_prepare_request", return_value=response)
    mocker.patch.object(pymisp.api.PyMISP, "_check_response", return_value=response.json())
    result = get_indicator_results(
        value,
        dbot_type,
        malicious_tag_ids,
        suspicious_tag_ids,
        benign_tag_ids,
        reliability,
        attributes_limit,
        search_warninglists
    )
    assert "my_custom_list" in result.readable_output
    assert isinstance(result.indicator, Common.IP)
    assert result.indicator.dbot_score.score == Common.DBotScore.GOOD
