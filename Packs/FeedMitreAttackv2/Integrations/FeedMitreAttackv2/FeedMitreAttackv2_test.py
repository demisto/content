import json
import pytest
from stix2 import TAXIICollectionSource
from test_data.mitre_test_data import ATTACK_PATTERN, COURSE_OF_ACTION, INTRUSION_SET, MALWARE, TOOL, ID_TO_NAME, \
    RELATION, STIX_TOOL, STIX_MALWARE, STIX_ATTACK_PATTERN, MALWARE_LIST_WITHOUT_PREFIX, MALWARE_LIST_WITH_PREFIX, \
    INDICATORS_LIST, NEW_INDICATORS_LIST, MITRE_ID_TO_MITRE_NAME, OLD_ID_TO_NAME, NEW_ID_TO_NAME

ENTERPRISE_COLLECTION_ID = '95ecc380-afe9-11e4-9b6c-751b66dd541e'
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

    default_id = ENTERPRISE_COLLECTION_ID
    nondefault_id = 2
    client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]
    mocker.patch.object(client, 'initialise')

    mocker.patch.object(TAXIICollectionSource, "__init__", return_value=None)
    mocker.patch.object(TAXIICollectionSource, 'query', return_value=indicator)
    mocker.patch.object(json, 'loads', return_value=indicator[0])
    mocker.patch.object(fm, 'create_relationship', wraps=mock_create_relations(create_relationship))

    indicators = client.build_iterator(create_relationships=True, limit=6)
    assert indicators == expected_result

    default_id = NON_ENTERPRISE_COLLECTION_ID
    nondefault_id = 2
    client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]
    mocker.patch.object(client, 'initialise')

    mocker.patch.object(TAXIICollectionSource, "__init__", return_value=None)
    mocker.patch.object(TAXIICollectionSource, 'query', return_value=indicator)
    mocker.patch.object(json, 'loads', return_value=indicator[0])
    mocker.patch.object(fm, 'create_relationship', wraps=mock_create_relations(create_relationship))

    indicators = client.build_iterator(create_relationships=True, limit=6)
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
    ('STIX Tool', STIX_TOOL.get('response'), STIX_TOOL.get('map_result')),
    ('STIX Malware', STIX_MALWARE.get('response'), STIX_MALWARE.get('map_result')),
    ('STIX Attack Pattern', STIX_ATTACK_PATTERN.get('response'), STIX_ATTACK_PATTERN.get('map_result'))
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
