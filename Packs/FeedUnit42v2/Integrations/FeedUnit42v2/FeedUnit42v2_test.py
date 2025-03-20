import pytest
import demistomock as demisto
from FeedUnit42v2 import (
    Client,
    fetch_indicators,
    get_indicators_command,
    handle_multiple_dates_in_one_field,
    parse_indicators,
    parse_campaigns,
    parse_reports_and_report_relationships,
    create_attack_pattern_indicator,
    create_course_of_action_indicators,
    get_ioc_type,
    get_ioc_value,
    create_list_relationships,
    extract_ioc_value,
    DemistoException,
)

from test_data.feed_data import (
    INDICATORS_DATA,
    ATTACK_PATTERN_DATA,
    MALWARE_DATA,
    RELATIONSHIP_DATA,
    REPORTS_DATA,
    REPORTS_INDICATORS,
    ID_TO_OBJECT,
    INDICATORS_RESULT,
    CAMPAIGN_RESPONSE,
    CAMPAIGN_INDICATOR,
    COURSE_OF_ACTION_DATA,
    ATTACK_PATTERN_INDICATOR,
    COURSE_OF_ACTION_INDICATORS,
    RELATIONSHIP_OBJECTS,
    INTRUSION_SET_DATA,
    DUMMY_INDICATOR_WITH_RELATIONSHIP_LIST,
    STIX_ATTACK_PATTERN_INDICATOR,
    SUB_TECHNIQUE_INDICATOR,
    SUB_TECHNIQUE_DATA,
    INVALID_ATTACK_PATTERN_STRUCTURE,
    FETCH_RESULTS,
    FETCH_MOCK_RESPONSE,
    REPORTS_INDICATORS_WITH_RELATIONSHIPS,
    COURSE_OF_ACTION_INDICATORS_WITH_TLP,
)


@pytest.mark.parametrize(
    "command, args, response, length",
    [
        (get_indicators_command, {"limit": 2, "indicators_type": "indicator"}, INDICATORS_DATA, 2),
        (get_indicators_command, {"limit": 5, "indicators_type": "indicator"}, INDICATORS_DATA, 5),
    ],
)  # noqa: E124
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
    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "fetch_stix_objects_from_api", return_value=response)
    command_results = command(client, args)
    indicators = command_results.raw_response
    assert len(indicators) == length


TYPE_TO_RESPONSE = {
    "indicator": INDICATORS_DATA,
    "report": REPORTS_DATA,
    "attack-pattern": ATTACK_PATTERN_DATA,
    "malware": MALWARE_DATA,
    "campaign": CAMPAIGN_RESPONSE,
    "relationship": RELATIONSHIP_DATA,
    "course-of-action": COURSE_OF_ACTION_DATA,
    "intrusion-set": INTRUSION_SET_DATA,
}

TYPE_TO_RESPONSE_WIITH_INVALID_ATTACK_PATTERN_DATA = {
    "indicator": INDICATORS_DATA,
    "report": REPORTS_DATA,
    "attack-pattern": INVALID_ATTACK_PATTERN_STRUCTURE,
    "malware": MALWARE_DATA,
    "campaign": CAMPAIGN_RESPONSE,
    "relationship": RELATIONSHIP_DATA,
    "course-of-action": COURSE_OF_ACTION_DATA,
    "intrusion-set": INTRUSION_SET_DATA,
}


TYPE_TO_RESPONSE_FETCH = {
    "indicator": INDICATORS_DATA,
    "report": REPORTS_DATA,
    "attack-pattern": ATTACK_PATTERN_DATA,
    "malware": MALWARE_DATA,
    "campaign": CAMPAIGN_RESPONSE,
    "relationship": RELATIONSHIP_DATA,
    "course-of-action": COURSE_OF_ACTION_DATA,
    "intrusion-set": INTRUSION_SET_DATA,
}


TYPE_TO_RESPONSE_FETCH = {
    "indicator": INDICATORS_DATA,
    "report": FETCH_MOCK_RESPONSE,
    "attack-pattern": ATTACK_PATTERN_DATA,
    "malware": MALWARE_DATA,
    "campaign": CAMPAIGN_RESPONSE,
    "relationship": RELATIONSHIP_DATA,
    "course-of-action": COURSE_OF_ACTION_DATA,
    "intrusion-set": INTRUSION_SET_DATA,
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
        type_ = kwargs.get("type")
        client.objects_data[type_] = TYPE_TO_RESPONSE[type_]

    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "fetch_stix_objects_from_api", side_effect=mock_get_stix_objects)

    indicators = fetch_indicators(client, create_relationships=True)
    assert len(indicators) == 24
    assert DUMMY_INDICATOR_WITH_RELATIONSHIP_LIST in indicators
    assert indicators == FETCH_RESULTS


def test_fetch_indicators_fails_on_invalid_attack_pattern_structure(mocker):
    """
    Given
        - Invalid attack pattern indicator structure

    When
        - fetching indicators

    Then
        - DemistoException is raised.
    """

    def mock_get_stix_objects(test, **kwargs):
        type_ = kwargs.get("type")
        client.objects_data[type_] = TYPE_TO_RESPONSE_WIITH_INVALID_ATTACK_PATTERN_DATA[type_]

    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "fetch_stix_objects_from_api", side_effect=mock_get_stix_objects)

    with pytest.raises(DemistoException, match=r"Failed parsing attack indicator"):
        fetch_indicators(client, create_relationships=True)


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
        type_ = kwargs.get("type")
        client.objects_data[type_] = TYPE_TO_RESPONSE[type_]

    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "fetch_stix_objects_from_api", side_effect=mock_get_stix_objects)

    indicators = fetch_indicators(client, ["test_tag"])
    assert set(indicators[0].get("fields").get("tags")) == {"malicious-activity", "test_tag"}


@pytest.mark.parametrize(
    "field_name, field_value, expected_result",
    [
        ("created", "2017-05-31T21:31:43.540Z", "2017-05-31T21:31:43.540Z"),
        ("created", "2019-04-25T20:53:07.719Z\n2019-04-25T20:53:07.814Z", "2019-04-25T20:53:07.719Z"),
        ("modified", "2017-05-31T21:31:43.540Z", "2017-05-31T21:31:43.540Z"),
        ("modified", "2020-03-16T15:38:37.650Z\n2020-01-17T16:45:24.252Z", "2020-03-16T15:38:37.650Z"),
    ],
)
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
    assert handle_multiple_dates_in_one_field(field_name, field_value) == expected_result


def test_parse_indicators():
    """
    Given
    - list of IOCs in STIX format.
    When
    - we extract this IOCs list to Demisto format
    Then
    - run the parse_indicators
    - Validate The IOCs list extracted successfully.

    """
    assert parse_indicators(INDICATORS_DATA, [], "")[0] == INDICATORS_RESULT


def test_parse_indicators_ioc_in_pattern():
    """
    Given
    - IOC in STIX format where the name value is file name and the ioc is in the pattern.
    When
    - we extract this IOCs list to Demisto format.
    Then
    - run the parse_indicators
    - Validate The indicator value is the file hash.
    - Validate The associatedfilenames value is the file name.

    """
    file_indicator = parse_indicators(INDICATORS_DATA, [], "")[10]
    assert file_indicator["value"] == "ca5fb5814ec621f4b79d"
    assert file_indicator["fields"]["associatedfilenames"] == "Jrdhtjydhjf.exe"


def test_parse_reports(mocker):
    """
    Given
    - list of reports in STIX format.
    When
    - we extract this reports list to Demisto format
    Then
    - run the parse_reports
    Validate The reports list extracted successfully.
    """
    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "get_report_object", return_value=REPORTS_DATA[1])
    result = parse_reports_and_report_relationships(client, REPORTS_DATA, [], "")
    assert len(result) == 2
    assert result == REPORTS_INDICATORS


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
    client = Client(api_key="1234", verify=False)
    assert parse_campaigns(client, CAMPAIGN_RESPONSE, [], "") == CAMPAIGN_INDICATOR


def test_create_attack_pattern_indicator(mocker):
    """
    Given
    - list of IOCs in STIX format.
    When
    - we extract this attack pattern list to Demisto format
    Then
    - run the attack_pattern_indicator
    Validate The attack pattern list extracted successfully.
    """
    import TAXII2ApiModule

    client = Client(api_key="1234", verify=False)
    mocker.patch.object(TAXII2ApiModule, "is_demisto_version_ge", side_effect=[True, False, True])
    assert create_attack_pattern_indicator(client, ATTACK_PATTERN_DATA, [], "") == ATTACK_PATTERN_INDICATOR
    assert create_attack_pattern_indicator(client, ATTACK_PATTERN_DATA, [], "") == STIX_ATTACK_PATTERN_INDICATOR
    assert create_attack_pattern_indicator(client, SUB_TECHNIQUE_DATA, [], "") == SUB_TECHNIQUE_INDICATOR


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
    client = Client(api_key="1234", verify=False)
    assert create_course_of_action_indicators(client, COURSE_OF_ACTION_DATA, [], "") == COURSE_OF_ACTION_INDICATORS


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
    assert get_ioc_type("indicator--01a5a209-b94c-450b-b7f9-946497d91055", ID_TO_OBJECT) == "IP"
    assert get_ioc_type("indicator--fd0da09e-a0b2-4018-9476-1a7edd809b59", ID_TO_OBJECT) == "URL"


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
    assert get_ioc_value("indicator--01a5a209-b94c-450b-b7f9-946497d91055", ID_TO_OBJECT) == "T111: Software Discovery"
    assert get_ioc_value("indicator--fd0da09e-a0b2-4018-9476-1a7edd809b59", ID_TO_OBJECT) == "Deploy XSOAR Playbook"
    assert get_ioc_value("report--0f86dccd-29bd-46c6-83fd-e79ba040bf0", ID_TO_OBJECT) == "[Unit42 ATOM] Maze Ransomware"
    assert (
        get_ioc_value("attack-pattern--4bed873f-0b7d-41d4-b93a-b6905d1f90b0", ID_TO_OBJECT)
        == "Virtualization/Sandbox Evasion: Time Based Evasion"
    )


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
    assert create_list_relationships(RELATIONSHIP_DATA, ID_TO_OBJECT) == RELATIONSHIP_OBJECTS


def test_extract_ioc_value():
    """
    Given
    - IOC obj to get its value.
    When
    - we extract its value from the name field
    Then
    - run the get_ioc_value
    Validate The IOC value extracted successfully.
    """
    name = "([file:name = 'blabla' OR file:name = 'blabla'] AND [file:hashes.'SHA-256' = '4f75622c2dd839f'])"
    assert extract_ioc_value(name) == "4f75622c2dd839f"


def test_fetch_indicators_command_with_relationship(mocker):
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
        type_ = kwargs.get("type")
        client.objects_data[type_] = TYPE_TO_RESPONSE_FETCH[type_]

    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "fetch_stix_objects_from_api", side_effect=mock_get_stix_objects)

    indicators = fetch_indicators(client, create_relationships=True)
    assert len(indicators) == 23
    assert DUMMY_INDICATOR_WITH_RELATIONSHIP_LIST in indicators
    assert REPORTS_INDICATORS_WITH_RELATIONSHIPS in indicators


def test_create_course_of_action_indicators_with_tlp():
    """
    Given
    - fetch indicator command.
    - mock Client.
    When
    - call the create_course_of_action_indicators method
    Then
    - run the create_course_of_action_indicators method with TLP
    - Validate that the TLP value was set correctly.
    """

    client = Client(api_key="1234", verify=False)
    assert create_course_of_action_indicators(client, COURSE_OF_ACTION_DATA, [], "WHITE") == COURSE_OF_ACTION_INDICATORS_WITH_TLP


def test_fetch_indicators_malware(mocker):
    """
    Given
    - fetch indicator command.
    - mock Client.
    When
    - call the fetch_indicators method
    Then
    - run the fetch_indicators method.
    - Validate that the malware objects created correctly.
    """

    def mock_get_stix_objects(test, **kwargs):
        type_ = kwargs.get("type")
        client.objects_data[type_] = TYPE_TO_RESPONSE_FETCH[type_]

    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "fetch_stix_objects_from_api", side_effect=mock_get_stix_objects)
    indicators = fetch_indicators(client, create_relationships=True)
    for i in range(18, 23):
        assert indicators[i]["type"] == "Malware"
    assert len(indicators) == 23


@pytest.mark.parametrize(
    "report_obj, expected_result",
    [
        ({"object_refs": ["indicator--a", "indicator--b", "indicator--c", "indicator--d"]}, True),
        ({"object_refs": ["intrusion-set--a", "indicator--ab"]}, True),
        ({"object_refs": ["intrusion-set--a", "indicator--ab"], "description": "description"}, False),
        ({"object_refs": ["intrusion-set--a"], "description": "description"}, False),
        ({"object_refs": ["intrusion-set--a"]}, False),
        ({"object_refs": ["indicator--a", "indicator--ab"]}, True),
        ({"object_refs": ["indicator--a", "indicator--ab"], "description": "description"}, False),
        ({"object_refs": ["intrusion-set--a", "report--ab"], "description": "description"}, False),
        ({"object_refs": ["intrusion-set--a", "report--ab"]}, False),
    ],
)
def test_is_atom42_sub_report(report_obj, expected_result):
    """
    Given
    - report object.
    When
    - call the is_atom42_sub_report method
    Then
    - run the is_atom42_sub_report method with a report.
    - Validate that the function output is correct.
    """
    from FeedUnit42v2 import is_atom42_sub_report

    assert is_atom42_sub_report(report_obj) is expected_result


@pytest.mark.parametrize(
    "report_obj, expected_result",
    [
        ({"object_refs": ["indicator--a", "indicator--b", "indicator--c", "indicator--d"]}, False),
        ({"object_refs": ["indicator--a", "indicator--b", "indicator--c", "indicator--d"], "description": "description"}, False),
        ({"object_refs": ["intrusion-set--a", "indicator--ab"]}, False),
        ({"object_refs": ["intrusion-set--a", "indicator--ab"], "description": "description"}, False),
        ({"object_refs": ["intrusion-set--a"], "description": "description"}, False),
        ({"object_refs": ["intrusion-set--a"]}, False),
        ({"object_refs": ["indicator--a", "indicator--ab"]}, False),
        ({"object_refs": ["indicator--a", "indicator--ab"], "description": "description"}, False),
        ({"object_refs": ["intrusion-set--a", "report--ab"], "description": "description"}, True),
        ({"object_refs": ["intrusion-set--a", "report--ab"]}, True),
    ],
)
def test_is_atom42_main_report(report_obj, expected_result):
    """
    Given
    - report object.
    When
    - call the is_atom42_main_report method
    Then
    - run the is_atom42_main_report method with report
    - Validate that the function output is correct.
    """

    from FeedUnit42v2 import is_atom42_main_report

    assert is_atom42_main_report(report_obj) is expected_result


def test_test_module(mocker):
    """
    Given
    - A response from the API.
    When
    - call the test_module method
    Then
    - run the test_module method
    - Validate that the response is correct.
    """

    def mock_get_stix_objects(test, **kwargs):
        type_ = kwargs.get("type")
        client.objects_data[type_] = TYPE_TO_RESPONSE_FETCH[type_]

    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "fetch_stix_objects_from_api", side_effect=mock_get_stix_objects)
    from FeedUnit42v2 import test_module

    assert test_module(client) == "ok"


def test_get_report_object(mocker):
    """
    Given
    - A Client.
    When
    - call the fetch_stix_objects_from_api method
    Then
    - run the fetch_stix_objects_from_api method
    - Validate the debug logs.
    """

    def mock_get_stix_objects(**kwargs):
        type_ = kwargs.get("type")
        client.objects_data[type_] = TYPE_TO_RESPONSE_FETCH[type_]
        return TYPE_TO_RESPONSE_FETCH[type_]

    client = Client(api_key="1234", verify=False)
    mocker.patch.object(client, "fetch_stix_objects_from_api", side_effect=mock_get_stix_objects)
    debug_logs_mock = mocker.patch.object(demisto, "debug")
    client.get_report_object("object_id")
    assert (
        "Unit42v2 Feed: Found more then one object for report object object_id skipping" in debug_logs_mock.call_args_list[0][0]
    )


def test_parse_indicators_no_name():
    """
    Given
    - An indicator without a name.
    When
    - Calling the fetch-indicators command.
    Then
    - Use value in the pattern.
    """
    indicators = [{"pattern": "[domain-name:value = 'www.example.com']"}]

    res = parse_indicators(indicators)

    assert res[0]["value"] == "www.example.com"
