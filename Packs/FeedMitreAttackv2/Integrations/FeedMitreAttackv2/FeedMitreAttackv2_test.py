import json
import pytest
from stix2 import TAXIICollectionSource
from test_data.mitre_test_data import ATTACK_PATTERN, COURSE_OF_ACTION, INTRUSION_SET, MALWARE, TOOL, ID_TO_NAME, \
    RELATION, STIX_TOOL, STIX_MALWARE, STIX_ATTACK_PATTERN


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
    default_id = 1
    nondefault_id = 2
    client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]
    mocker.patch.object(client, 'initialise')

    mocker.patch.object(TAXIICollectionSource, "__init__", return_value=None)
    mocker.patch.object(TAXIICollectionSource, 'query', return_value=indicator)
    mocker.patch.object(json, 'loads', return_value=indicator[0])
    mocker.patch.object(fm, 'create_relationship', wraps=mock_create_relations(create_relationship))

    indicators = client.build_iterator(create_relationships=True, limit=6)
    assert indicators == expected_result


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
