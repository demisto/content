import pytest
from FeedUnit42v2 import Client, fetch_indicators, get_indicators_command

from test_data.feed_data import INDICATORS_DATA, ATTACK_PATTERN_DATA, MALWARE_DATA, RELATIONSHIP_DATA, REPORTS_DATA, \
    REPORTS_INDICATORS, ID_TO_OBJECT, INDICATORS_RESULT, CAMPAIGN_RESPONSE, CAMPAIGN_INDICATOR, COURSE_OF_ACTION_DATA, \
    PUBLICATIONS, ATTACK_PATTERN_INDICATOR, COURSE_OF_ACTION_INDICATORS, RELATIONSHIP_OBJECTS, \
    DUMMY_INDICATOR_WITH_RELATIONSHIP_LIST


@pytest.mark.parametrize('command, args, response, length', [
    (get_indicators_command, {'limit': 2}, INDICATORS_DATA, 2),
    (get_indicators_command, {'limit': 5}, INDICATORS_DATA, 5),
])  # noqa: E124
def test_commands(command, args, response, length, mocker):
    """
    Given
    - get_indicators_command func
    - command args
    - command raw response
    When
    - mock the Client's get_stix_objects.
    Then
    - convert the result to human readable table
    - create the context
    validate the raw_response
    """
    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'fetch_stix_objects_from_api', return_value=response)
    command_results = command(client, args)
    indicators = command_results.raw_response
    assert len(indicators) == length


TYPE_TO_RESPONSE = {
    'indicator': INDICATORS_DATA,
    'report': REPORTS_DATA,
    'attack-pattern': ATTACK_PATTERN_DATA,
    'malware': MALWARE_DATA,
    'campaign': CAMPAIGN_RESPONSE,
    'relationship': RELATIONSHIP_DATA,
    'course-of-action': COURSE_OF_ACTION_DATA
}


def test_fetch_indicators_command(mocker):
    """
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_stix_objects.
    Then
    - run the fetch incidents command using the Client
    Validate the amount of indicators fetched
    Validate that the dummy indicator with the relationships list fetched
    """

    def mock_get_stix_objects(test, **kwargs):
        type_ = kwargs.get('type')
        client.objects_data[type_] = TYPE_TO_RESPONSE[type_]

    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'fetch_stix_objects_from_api', side_effect=mock_get_stix_objects)

    indicators = fetch_indicators(client, create_relationships=True)
    assert len(indicators) == 17
    assert DUMMY_INDICATOR_WITH_RELATIONSHIP_LIST in indicators


def test_feed_tags_param(mocker):
    """
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the feed tags param.
    - mock the Client's get_stix_objects.
    Then
    - run the fetch incidents command using the Client
    Validate The value of the tags field.
    """

    def mock_get_stix_objects(test, **kwargs):
        type_ = kwargs.get('type')
        client.objects_data[type_] = TYPE_TO_RESPONSE[type_]

    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'fetch_stix_objects_from_api', side_effect=mock_get_stix_objects)

    indicators = fetch_indicators(client, ['test_tag'])
    assert set(indicators[0].get('fields').get('tags')) == {'malicious-activity', 'test_tag'}


@pytest.mark.parametrize('field_name, field_value, expected_result', [
    ('created', '2017-05-31T21:31:43.540Z', '2017-05-31T21:31:43.540Z'),
    ('created', '2019-04-25T20:53:07.719Z\n2019-04-25T20:53:07.814Z', '2019-04-25T20:53:07.719Z'),
    ('modified', '2017-05-31T21:31:43.540Z', '2017-05-31T21:31:43.540Z'),
    ('modified', '2020-03-16T15:38:37.650Z\n2020-01-17T16:45:24.252Z', '2020-03-16T15:38:37.650Z'),
])
def test_handle_multiple_dates_in_one_field(field_name, field_value, expected_result):
    """
    Given
    - created / modified indicator field
    When
    - this field contains two dates
    Then
    - run the handle_multiple_dates_in_one_field
    Validate The field contain one specific date.
    """
    from FeedUnit42v2 import handle_multiple_dates_in_one_field
    assert handle_multiple_dates_in_one_field(field_name, field_value) == expected_result


def test_get_indicator_publication():
    """
    Given
    - Indicator with external_reference field
    When
    - we extract this field to publications grid field
    Then
    - run the get_indicator_publication
    Validate The grid field extracted successfully.
    """
    from FeedUnit42v2 import get_indicator_publication
    assert get_indicator_publication(ATTACK_PATTERN_DATA[0]) == PUBLICATIONS


@pytest.mark.parametrize('indicator_name, expected_result', [
    ({"name": "T1564.004: NTFS File Attributes"}, ("T1564.004", "NTFS File Attributes")),
    ({"name": "T1078: Valid Accounts"}, ("T1078", "Valid Accounts"))
])
def test_get_attack_id_and_value_from_name(indicator_name, expected_result):
    """
    Given
    - Indicator with name field
    When
    - we extract this field to ID and value fields
    Then
    - run the get_attack_id_and_value_from_name
    Validate The ID and value fields extracted successfully.
    """
    from FeedUnit42v2 import get_attack_id_and_value_from_name
    assert get_attack_id_and_value_from_name(indicator_name) == expected_result


def test_parse_indicators():
    """
    Given
    - list of IOCs in STIX format.
    When
    - we extract this IOCs list to Demisto format
    Then
    - run the parse_indicators
    Validate The IOCs list extracted successfully.
    """
    from FeedUnit42v2 import parse_indicators
    assert parse_indicators(INDICATORS_DATA, [], '')[0] == INDICATORS_RESULT


def test_parse_reports():
    """
    Given
    - list of reports in STIX format.
    When
    - we extract this reports list to Demisto format
    Then
    - run the parse_reports
    Validate The reports list extracted successfully.
    """
    from FeedUnit42v2 import parse_reports
    assert parse_reports(REPORTS_DATA, [], '') == REPORTS_INDICATORS


def test_parse_campaigns():
    """
    Given
    - list of campaigns in STIX format.
    When
    - we extract this campaigns list to Demisto format
    Then
    - run the parse_campaigns
    Validate The campaigns list extracted successfully.
    """
    from FeedUnit42v2 import parse_campaigns
    assert parse_campaigns(CAMPAIGN_RESPONSE, [], '') == CAMPAIGN_INDICATOR


def test_create_attack_pattern_indicator():
    """
    Given
    - list of IOCs in STIX format.
    When
    - we extract this attack pattern list to Demisto format
    Then
    - run the attack_pattern_indicator
    Validate The attack pattern list extracted successfully.
    """
    from FeedUnit42v2 import create_attack_pattern_indicator
    assert create_attack_pattern_indicator(ATTACK_PATTERN_DATA, [], '') == ATTACK_PATTERN_INDICATOR


def test_create_course_of_action_indicators():
    """
    Given
    - list of course of action in STIX format.
    When
    - we extract this course of action list to Demisto format
    Then
    - run the create_course_of_action_indicators
    Validate The course of action list extracted successfully.
    """
    from FeedUnit42v2 import create_course_of_action_indicators
    assert create_course_of_action_indicators(COURSE_OF_ACTION_DATA, [], '') == COURSE_OF_ACTION_INDICATORS


def test_get_ioc_type():
    """
    Given
    - IOC ID to get its type.
    When
    - we extract its type from the pattern field
    Then
    - run the get_ioc_type
    Validate The IOC type extracted successfully.
    """
    from FeedUnit42v2 import get_ioc_type
    assert get_ioc_type('indicator--01a5a209-b94c-450b-b7f9-946497d91055', ID_TO_OBJECT) == 'IP'
    assert get_ioc_type('indicator--fd0da09e-a0b2-4018-9476-1a7edd809b59', ID_TO_OBJECT) == 'URL'


def test_get_ioc_value():
    """
    Given
    - IOC ID to get its value.
    When
    - we extract its value from the name field
    Then
    - run the get_ioc_value
    Validate The IOC value extracted successfully.
    """
    from FeedUnit42v2 import get_ioc_value
    assert get_ioc_value('indicator--01a5a209-b94c-450b-b7f9-946497d91055', ID_TO_OBJECT) == 'T111: Software Discovery'
    assert get_ioc_value('indicator--fd0da09e-a0b2-4018-9476-1a7edd809b59', ID_TO_OBJECT) == 'Deploy XSOAR Playbook'
    assert get_ioc_value('report--0f86dccd-29bd-46c6-83fd-e79ba040bf0', ID_TO_OBJECT) == '[Unit42 ATOM] Maze Ransomware'


def test_create_list_relationships():
    """
    Given
    - list of relationships in STIX format.
    When
    - we extract this relationships list to Demisto format
    Then
    - run the create_list_relationships
    Validate The relationships list extracted successfully.
    """
    from FeedUnit42v2 import create_list_relationships
    assert create_list_relationships(RELATIONSHIP_DATA, ID_TO_OBJECT) == RELATIONSHIP_OBJECTS
