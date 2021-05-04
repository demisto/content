import pytest
from FeedUnit42v2 import Client, fetch_indicators, get_indicators_command
# sort_report_objects_by_type, parse_reports,
# match_relationships, parse_related_indicators, create_mitre_indicator,
from test_data.feed_data import INDICATORS_DATA, ATTACK_PATTERN_DATA, MALWARE_DATA, RELATIONSHIP_DATA, REPORTS_DATA, \
    REPORTS_INDICATORS, MATCHED_RELATIONSHIPS, ID_TO_OBJECT, INDICATORS_RESULT, CAMPAIGN_RESPONSE, CAMPAIGN_INDICATOR, \
    PUBLICATIONS


@pytest.mark.parametrize('command, args, response, length', [
    (get_indicators_command, {'limit': 2}, INDICATORS_DATA, 2),
    (get_indicators_command, {'limit': 5}, INDICATORS_DATA, 5),
])  # noqa: E124
def test_commands(command, args, response, length, mocker):
    """Unit test
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
    'campaign': [],
    'relationship': RELATIONSHIP_DATA,
    'course-of-action': []
}


def test_fetch_indicators_command(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_stix_objects.
    Then
    - run the fetch incidents command using the Client
    Validate the amount of indicators fetched
    """

    def mock_get_stix_objects(test, **kwargs):
        type_ = kwargs.get('type')
        client.objects_data[type_] = TYPE_TO_RESPONSE[type_]

    client = Client(api_key='1234', verify=False)
    mocker.patch.object(client, 'fetch_stix_objects_from_api', side_effect=mock_get_stix_objects)

    indicators = fetch_indicators(client)
    assert len(indicators) == 13


def test_feed_tags_param(mocker):
    """Unit test
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
    from FeedUnit42v2 import handle_multiple_dates_in_one_field
    assert handle_multiple_dates_in_one_field(field_name, field_value) == expected_result


def test_get_indicator_publication():
    from FeedUnit42v2 import get_indicator_publication
    assert get_indicator_publication(ATTACK_PATTERN_DATA[0]) == PUBLICATIONS


@pytest.mark.parametrize('indicator_name, expected_result', [
    ({"name": "T1564.004: NTFS File Attributes"}, ("T1564.004", "NTFS File Attributes")),
    ({"name": "T1078: Valid Accounts"}, ("T1078", "Valid Accounts"))
])
def test_get_attack_id_and_value_from_name(indicator_name, expected_result):
    from FeedUnit42v2 import get_attack_id_and_value_from_name
    assert get_attack_id_and_value_from_name(indicator_name) == expected_result


def test_parse_indicators():
    from FeedUnit42v2 import parse_indicators
    assert parse_indicators(INDICATORS_DATA, [], '')[0] == INDICATORS_RESULT


def test_parse_reports():
    from FeedUnit42v2 import parse_reports
    assert parse_reports(REPORTS_DATA, [], '') == REPORTS_INDICATORS


def test_parse_campaigns():
    from FeedUnit42v2 import parse_campaigns
    assert parse_campaigns(CAMPAIGN_RESPONSE, [], '') == CAMPAIGN_INDICATOR


def test_create_attack_pattern_indicator():
    from FeedUnit42v2 import create_attack_pattern_indicator
    assert create_attack_pattern_indicator(ATTACK_PATTERN_DATA, [], '') == 1
#
#
# def test_fetch_indicators_with_feedrelatedindicators(mocker):
#     """Unit test
#     Given
#     - fetch incidents command
#     - command args
#     - command raw response
#     When
#     - mock the Client's get_stix_objects.
#     Then
#     - run the fetch incidents command using the Client
#     Validate the connections in between the indicators
#     """
#
#     def mock_get_stix_objects(test, **kwargs):
#         type_ = kwargs.get('type')
#         client.objects_data[type_] = TYPE_TO_RESPONSE[type_]
#
#     client = Client(api_key='1234', verify=False)
#     mocker.patch.object(client, 'fetch_stix_objects_from_api', side_effect=mock_get_stix_objects)
#
#     indicators = fetch_indicators(client)
#     for indicator in indicators:
#         indicator_fields = indicator.get('fields')
#         if indicator_fields.get('indicatoridentification') == 'indicator--010bb9ad-5686-485d-97e5-93c2187e56ce':
#             assert indicator_fields.get('feedrelatedindicators') == [
#                 {
#                     'description': 'example.com,https://attack.mitre.org/techniques/T1047,https://msdn.microsoft.com'
#                                    '/en-us/library/aa394582.aspx,https://technet.microsoft.com/en-us/library/cc787851'
#                                    '.aspx,https://en.wikipedia.org/wiki/Server_Message_Block',
#                     'type': 'MITRE ATT&CK',
#                     'value': 'T1047'}
#             ]
#
#             break
#
#
# def test_fetch_indicators_with_malware_reference(mocker):
#     """Unit test
#     Given
#     - fetch incidents command
#     - command args
#     - command raw response
#     When
#     - mock the Client's get_stix_objects.
#     Then
#     - run the fetch incidents command using the Client
#     Validate the connections in between the indicators
#     """
#
#     def mock_get_stix_objects(test, **kwargs):
#         type_ = kwargs.get('type')
#         client.objects_data[type_] = TYPE_TO_RESPONSE[type_]
#
#     client = Client(api_key='1234', verify=False)
#     mocker.patch.object(client, 'fetch_stix_objects_from_api', side_effect=mock_get_stix_objects)
#
#     indicators = fetch_indicators(client)
#     for indicator in indicators:
#         indicator_fields = indicator.get('fields')
#         if indicator_fields.get('indicatoridentification') == 'indicator--0025039e-f0b5-4ad2-aaab-5374fe3734be':
#             assert set(indicator_fields.get('malwarefamily')) == {'Muirim', 'XBash', 'Muirim2'}
#             break
#
#
# def test_sort_reports():
#     """
#
#     Given
#         - List of raw report objects.
#
#     When
#         - Parsing STIX Report indicators.
#
#     Then
#         - Sort the object into two types: main and sub.
#
#     """
#     assert sort_report_objects_by_type(REPORTS_DATA) == ([REPORTS_DATA[0]], [REPORTS_DATA[1]])
#
#
# @pytest.mark.parametrize('report, tags, tlp_color, expected',
#                          [
#                              (REPORTS_DATA[0], [], None, REPORTS_INDICATORS[0]),
#                              (REPORTS_DATA[0], [], 'AMBER', REPORTS_INDICATORS[1])
#                          ])
# def test_parse_reports(report, tags, tlp_color, expected):
#     """
#
#     Given
#         - List of main raw report objects.
#
#     When
#         - Parsing STIX Report indicators.
#
#     Then
#         - Create a STIX Report indicator.
#
#     """
#     assert parse_reports([report], tags, tlp_color) == expected
#
#
# def test_parse_reports_relationships(mocker):
#     """
#
#     Given
#         - STIX Report indicators.
#         - Relationship objects.
#         - Malware and Attack-Pattern objects.
#
#     When
#         - Parsing STIX Report indicators.
#
#     Then
#         - Update a STIX Report indicator with relationships' data.
#
#     """
#
#     def mock_get_stix_objects(test, **kwargs):
#         type_ = kwargs.get('type')
#         client.objects_data[type_] = TYPE_TO_RESPONSE[type_]
#
#     client = Client(api_key='1234', verify=False)
#     mocker.patch.object(client, 'fetch_stix_objects_from_api', side_effect=mock_get_stix_objects)
#
#     indicators = fetch_indicators(client)
#     for indicator in indicators:
#         indicator_fields = indicator.get('fields')
#         if indicator_fields.get('stixid') == 'report--a':
#             assert set([i.get('value') for i in indicator_fields.get('feedrelatedindicators')]) == \
#                    {'T1047', 'XBash', 'c1ec28bc82500bd70f95edcbdf9306746198bbc04a09793ca69bb87f2abdb839'}
#             break
#
#
# def test_match_relationships():
#     """
#
#     Given
#         - Relationship objects.
#
#     When
#         - Parsing indicators.
#
#     Then
#         - Creates a dict of relationship in the form of `id: [related_ids]`
#
#     """
#     assert match_relationships(RELATIONSHIP_DATA) == (MATCHED_RELATIONSHIPS,
#                                                       {'course-of-action--fd0da09e-a0b2-4018-9476-1a7edd809b59': 'No product'})
#
#
# def test_parse_related_indicators():
#     """
#
#     Given
#         - Stix report object.
#         - Malware objects ids related to the report.
#         - Dict in the form of `id: stix_object`.
#
#     When
#         - Parsing related indicator from Stix report object.
#
#     Then
#         - Creates indicator and update the feedrelatedindicators field in the report.
#
#     """
#     report = {'fields': {'feedrelatedindicators': []}}
#     indicators = parse_related_indicators(report, ['attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055'],
#                                           ID_TO_OBJECT, {}, {})
#
#     assert len(report['fields']['feedrelatedindicators']) == 1
#     assert report['fields']['feedrelatedindicators'][0]['value'] == '8.8.8.8'
#     assert len(indicators) == 1
#     assert indicators[0]['value'] == '8.8.8.8'
#     assert indicators[0]['fields']['mitrecourseofaction'] == 'No courses of action found.'
#     assert indicators[0]['fields']['mitredescription'] == 'description'
#     assert indicators[0]['fields']['mitrename'] == 'Software Discovery'
#
#
# def test_create_mitre_indicator():
#     """
#
#     Given
#         - Indicator value.
#         - Stix relationship object.
#         - Dict of relationships in the form of `id: list(related_ids)`.
#         - Dict in the form of `id: stix_object`.
#         - Dict Connects courses of action id with the relationship product.
#
#     When
#         - Parsing the indicator.
#
#     Then
#         - Creates indicator and update the mitrecourseofaction field with markdown table.
#
#     """
#     indicator = create_mitre_indicator('8.8.8.8',
#                                        {'id': 'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055'},
#                                        MATCHED_RELATIONSHIPS,
#                                        ID_TO_OBJECT,
#                                        {'course-of-action--fd0da09e-a0b2-4018-9476-1a7edd809b59': 'NGFW'})
#
#     assert indicator['value'] == '8.8.8.8'
#     assert indicator['type'] == 'MITRE ATT&CK'
#     assert indicator['fields']['mitrecourseofaction'] == '\n### NGFW\n|Name|Title|Description|\n|---|---|---|' \
#                                                          '\n| Deploy XSOAR Playbook | Deploy XSOAR Playbook |' \
#                                                          ' Deploy XSOAR Playbook - Phishing Investigation - Generic V2 |\n'
