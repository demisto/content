import json
import pytest
from stix2 import TAXIICollectionSource, parse
import demistomock as demisto  # noqa: F401
from test_data.mitre_test_data import ATTACK_PATTERN, COURSE_OF_ACTION, INTRUSION_SET, MALWARE, TOOL, ID_TO_NAME, \
    RELATION, MALWARE_LIST_WITHOUT_PREFIX, MALWARE_LIST_WITH_PREFIX, \
    INDICATORS_LIST, NEW_INDICATORS_LIST, MITRE_ID_TO_MITRE_NAME, OLD_ID_TO_NAME, NEW_ID_TO_NAME, RELATIONSHIP_ENTITY, \
    CAMPAIGN, ATTACK_PATTERNS

ENTERPRISE_COLLECTION_ID = '	x-mitre-collection–1f5f1533-f617-4ca8-9ab4-6a02367fa019'
NON_ENTERPRISE_COLLECTION_ID = '101010101010101010101010101010101'


class MockCollection:
    def __init__(self, id_, title):
        self.id = id_
        self.title = title


def mock_create_relations(original):
    def mock(item_json, id_to_name):
        return original(item_json, ID_TO_NAME)
    return mock


@pytest.mark.parametrize('indicator, expected_result', [
    ([ATTACK_PATTERN.get('response')], ATTACK_PATTERN.get('indicator')),
    ([COURSE_OF_ACTION.get('response')], COURSE_OF_ACTION.get('indicator')),
    ([INTRUSION_SET.get('response')], INTRUSION_SET.get('indicator')),
    ([MALWARE.get('response')], MALWARE.get('indicator')),
    ([TOOL.get('response')], TOOL.get('indicator')),
])
def test_fetch_indicators(mocker, indicator, expected_result):
    """
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's get_stix_objects.
    Then
    - run the fetch incidents command using the Client
    Validate that all the indicators extracted successfully
    """
    import FeedMitreAttackv2 as fm
    from FeedMitreAttackv2 import Client, create_relationship
    client = Client(url="https://test.org", proxies=False, verify=False, tags=[], tlp_color=None)
    client.tactic_name_to_mitre_id = {"Defense Evasion": "TA0005",
                                      "Privilege Escalation": "TA0004",
                                      "Resource Development": "TA0042"}

    default_id = ENTERPRISE_COLLECTION_ID
    nondefault_id = 2
    client.collections = [MockCollection(default_id, 'enterprise att&ck'), MockCollection(nondefault_id, 'not_default')]
    mocker.patch.object(client, 'initialise')

    mocker.patch.object(TAXIICollectionSource, "__init__", return_value=None)
    mocker.patch.object(TAXIICollectionSource, 'query', return_value=indicator)
    # mocker.patch.object(json, 'loads', return_value=indicator[0])
    mocker.patch.object(fm, 'create_relationship', wraps=mock_create_relations(create_relationship))

    indicators = client.build_iterator(create_relationships=True, limit=7)
    assert indicators == expected_result

    default_id = NON_ENTERPRISE_COLLECTION_ID
    nondefault_id = 2
    client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]
    mocker.patch.object(client, 'initialise')

    mocker.patch.object(TAXIICollectionSource, "__init__", return_value=None)
    mocker.patch.object(TAXIICollectionSource, 'query', return_value=indicator)
    mocker.patch.object(json, 'loads', return_value=indicator[0])
    mocker.patch.object(fm, 'create_relationship', wraps=mock_create_relations(create_relationship))

    indicators = client.build_iterator(create_relationships=True, limit=7)
    assert indicators == ([], [], {}, {})


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
    from FeedMitreAttackv2 import handle_multiple_dates_in_one_field
    assert handle_multiple_dates_in_one_field(field_name, field_value) == expected_result


@pytest.mark.parametrize('indicator, expected_result', [
    ({"x_mitre_deprecated": True}, True),
    ({"revoked": True}, True),
    ({}, False)
])
def test_is_indicator_deprecated_or_revoked(indicator, expected_result):
    """
   Given
   - indicator in STIX format.
   When
   - we cheed
   Then
   - run the create_list_relationships
   Validate The relationships list extracted successfully.
   """
    from FeedMitreAttackv2 import is_indicator_deprecated_or_revoked
    assert is_indicator_deprecated_or_revoked(indicator) == expected_result


@pytest.mark.parametrize('indicator_type, indicator_json, expected_result', [
    ('Attack Pattern', ATTACK_PATTERN.get('response'), ATTACK_PATTERN.get('map_result')),
    ('Course of Action', COURSE_OF_ACTION.get('response'), COURSE_OF_ACTION.get('map_result')),
    ('Intrusion Set', INTRUSION_SET.get('response'), INTRUSION_SET.get('map_result')),
    ('Malware', MALWARE.get('response'), MALWARE.get('map_result')),
    ('Tool', TOOL.get('response'), TOOL.get('map_result')),
    ('Campaign', CAMPAIGN.get('response'), CAMPAIGN.get('map_result')),
])
def test_map_fields_by_type(indicator_type, indicator_json, expected_result):
    from FeedMitreAttackv2 import map_fields_by_type
    assert map_fields_by_type(indicator_type, indicator_json) == expected_result


def test_create_relationship():
    """
   Given
   - relationship obj in STIX format.
   When
   - we extract this relationship to Demisto format
   Then
   - run the create_relationship
   Validate The relationship extracted successfully.
   """
    from FeedMitreAttackv2 import create_relationship
    relation = create_relationship(RELATION.get('response'), ID_TO_NAME)
    relation._entity_a = 'entity a'
    relation._entity_a_type = 'STIX Malware'
    relation._entity_b = 'entity b'
    relation._entity_b_type = 'STIX Attack Pattern'
    relation._name = 'uses'
    relation._relation_type = 'IndicatorToIndicator'
    relation._reverse_name = 'used-by'


def test_get_item_type():
    from FeedMitreAttackv2 import get_item_type
    assert get_item_type('malware', True) == 'Malware'
    assert get_item_type('malware', False) == 'STIX Malware'
    assert get_item_type('intrusion-set', True) == 'Intrusion Set'
    assert get_item_type('intrusion-set', False) == 'Intrusion Set'


def test_create_relationship_list():
    from FeedMitreAttackv2 import create_relationship_list
    assert create_relationship_list([RELATION.get('response')], ID_TO_NAME) == RELATION.get('indicator')


def test_add_malware_prefix_to_dup_with_intrusion_set():
    from FeedMitreAttackv2 import add_malware_prefix_to_dup_with_intrusion_set
    malware_list = MALWARE_LIST_WITHOUT_PREFIX
    add_malware_prefix_to_dup_with_intrusion_set(MALWARE_LIST_WITHOUT_PREFIX, ID_TO_NAME)
    assert malware_list == MALWARE_LIST_WITH_PREFIX


def test_add_obj_to_mitre_id_to_mitre_name():
    from FeedMitreAttackv2 import add_obj_to_mitre_id_to_mitre_name
    mitre_id_to_mitre_name = {}
    add_obj_to_mitre_id_to_mitre_name(mitre_id_to_mitre_name, ATTACK_PATTERN['response'])
    assert mitre_id_to_mitre_name == {'T1047': 'ATTACK_PATTERN 1'}


def test_add_technique_prefix_to_sub_technique():
    from FeedMitreAttackv2 import add_technique_prefix_to_sub_technique
    indicators = INDICATORS_LIST
    mitre_id_to_mitre_name = MITRE_ID_TO_MITRE_NAME
    id_to_name = OLD_ID_TO_NAME

    add_technique_prefix_to_sub_technique(indicators, id_to_name, mitre_id_to_mitre_name)
    assert indicators == NEW_INDICATORS_LIST
    assert id_to_name == NEW_ID_TO_NAME


def test_publication_link_not_none():
    from FeedMitreAttackv2 import map_fields_by_type
    indicator = {'created': '2022-01-05T14:27:46.612705Z',
                 'modified': '2022-01-05T14:27:46.612705Z',
                 'external_references': [{}]}

    res = map_fields_by_type('Malware', indicator)
    assert res['publications'][0]['link'] is not None


def test_create_relationships_invalid():
    from FeedMitreAttackv2 import create_relationship
    item_json = {'source_ref': '',
                 'target_ref': ''}
    assert create_relationship(item_json, {}) is None


def test_create_relationship_with_unknown_relationship_name():
    from FeedMitreAttackv2 import create_relationship
    item_json = {'source_ref--source_ref': 'source_ref',
                 'target_ref--target_ref': 'target_ref'}
    output = create_relationship(RELATIONSHIP_ENTITY, item_json)
    assert output is not None


@pytest.mark.parametrize('attack_id, attack_pattern_obj, expected_result', [
    ("T1111", {"external_references": [{"external_id": 'T1111'}]}, True),
    ("T1098", {"external_references": [{"external_id": 'T1111'}]}, False)
])
def test_filter_attack_pattern_object_by_attack_id(attack_id, attack_pattern_obj, expected_result):
    from FeedMitreAttackv2 import filter_attack_pattern_object_by_attack_id
    output = filter_attack_pattern_object_by_attack_id(attack_id, attack_pattern_obj)
    assert output == expected_result


@pytest.mark.parametrize('description, expected_result', [
    ('Test (23)', ''),
    ('Test (2020, Mar)', '2020-03-01T00:00:00'),
    ('Test (Test) (2020, Mar)', '2020-03-01T00:00:00'),
    ('Test 2033)', ''),
    ('Test ()', ''),
    ('Test (Test)', ''),
    ('Gross, J. (2016, February 23). Operation Dust Storm. Retrieved December 22, 2021.', '2016-02-23T00:00:00'),
    ('Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Command History. Retrieved October 21, 2020.', ''),
    ('Citation: Security Affairs Elderwood Sept 2012)', ''),
    ('Insikt Group (Recorded Future). (2017, May 17).',
     '2017-05-17T00:00:00'),
    ('Insikt Group (Recorded Future). (2017, May17).',
     '2017-05-17T00:00:00'),
    ('Insikt Group (Recorded Future). (2017,May17).',
     '2017-05-17T00:00:00'),
    ('Insikt Group (Recorded Future). (2017,March17).',
     '2017-03-17T00:00:00'),
    ('Insikt Group (Recorded Future). (2017, March 17).',
     '2017-03-17T00:00:00')
])
def test_extract_date_time_from_description(description, expected_result):
    from FeedMitreAttackv2 import extract_date_time_from_description
    output = extract_date_time_from_description(description)
    assert output == expected_result


def test_attack_pattern_reputation_command(mocker):
    """
    Given:
        Some attack patterns to retrieve, with and without sub-technique

    When:
        Running attack-pattern reputation command

    Then:
        Returns the wanted attack patterns
    """
    from FeedMitreAttackv2 import attack_pattern_reputation_command

    stix_objs = [parse(stix_obj_dict, allow_custom=True) for stix_obj_dict in ATTACK_PATTERNS]
    mocker.patch('FeedMitreAttackv2.get_mitre_data_by_filter', return_value=stix_objs)

    args = {'attack_pattern': 'Abuse Elevation Control Mechanism, Active Scanning: Wordlist Scanning'}
    command_results = attack_pattern_reputation_command('', args)

    assert command_results[0].indicator.value == 'Abuse Elevation Control Mechanism'
    assert command_results[1].indicator.value == 'Active Scanning: Wordlist Scanning'


def test_attack_pattern_reputation_without_answer_command(mocker):
    """
    Given:
        One attach pattern to retrive data on, that is not found in the collection

    When:
        Running attack-pattern reputation command

    Then:
        Ensures the command_results is not empty and readable_output is as expected
    """
    from FeedMitreAttackv2 import attack_pattern_reputation_command

    stix_objs = [parse(stix_obj_dict, allow_custom=True) for stix_obj_dict in ATTACK_PATTERNS]
    mocker.patch('FeedMitreAttackv2.get_mitre_data_by_filter', return_value=stix_objs)

    args = {'attack_pattern': 'dummy attack pattern'}
    command_results = attack_pattern_reputation_command('', args)

    assert command_results
    assert command_results.readable_output == "MITRE ATTACK Attack Patterns values: No Attack " \
                                              "Patterns found for ['dummy attack pattern'] in the Enterprise collection."


def test_get_mitre_value_from_id_without_answer_command(mocker):
    """
    Given:
        One attach pattern to retrive data on, that is not found in the collection

    When:
        Running attack-pattern reputation command

    Then:
        Ensures the command_results is not empty and readable_output is as expected
    """
    from FeedMitreAttackv2 import get_mitre_value_from_id

    stix_objs = [parse(stix_obj_dict, allow_custom=True) for stix_obj_dict in ATTACK_PATTERNS]
    mocker.patch('FeedMitreAttackv2.get_mitre_data_by_filter', return_value=stix_objs)

    args = {'attack_ids': ['dummy attack pattern id']}
    command_results = get_mitre_value_from_id('', args)

    assert command_results
    assert command_results.readable_output == "MITRE ATTACK Attack Patterns values: " \
                                              "No Attack Patterns found for ['dummy attack pattern id'] in the " \
                                              "Enterprise collection."


@pytest.mark.parametrize('description, expected_result', [
    ("Waterbear is modular malware attributed to BlackTech ...(Citation: Trend Micro Waterbear December 2019)",
     "Waterbear is modular malware attributed to BlackTech ..."),
    ("Adversaries may employ various means to detect and avoid debuggers.(Citation: ProcessHacker Github)\
(assuming a present debugger would “swallow” or handle the potential error).\
(Citation: hasherezade debug)(Citation: AlKhaser Debug)(Citation: vxunderground debug)\
<code>OutputDebugStringW()</code>.(Citation: wardle evilquest partii)(Citation: Checkpoint Dridex Jan 2021)",
     "Adversaries may employ various means to detect and avoid debuggers.\
(assuming a present debugger would “swallow” or handle the potential error).\
<code>OutputDebugStringW()</code>.")
])
def test_remove_citations(description, expected_result):
    """
    Given:
        A description with Citation.
    When:
        Calling remove_citation method.
    Then:
        Output description will not contain Citation parts.
    """
    from FeedMitreAttackv2 import remove_citations
    actual_result = remove_citations(description)
    assert "Citation" not in actual_result
    assert actual_result == expected_result


def test_show_feeds_command(mocker):
    """
    Given:
        A Client.
    When:
        Calling show_feeds_command method.
    Then:
        Validate the output extracted successfully.
    """
    from FeedMitreAttackv2 import show_feeds_command, Client
    client = Client(url="https://test.org", proxies=False, verify=False, tags=[], tlp_color=None)
    default_id = NON_ENTERPRISE_COLLECTION_ID
    nondefault_id = 2
    client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]
    mocker.patch.object(demisto, 'results')
    show_feeds_command(client)
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == {'Type': 1,
                                               'Contents': [{'Name': 'default', 'ID': '101010101010101010101010101010101'},
                                                            {'Name': 'not_default', 'ID': 2}],
                                               'ContentsFormat': 'json',
                                               'HumanReadable': '### MITRE ATT&CK Feeds:\n|Name|ID|\n|---|---|\n| default |\
 101010101010101010101010101010101 |\n| not_default | 2 |\n', 'ReadableContentsFormat': 'markdown'}
