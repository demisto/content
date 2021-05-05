import json
import pytest
from stix2 import TAXIICollectionSource
from test_data.mitre_test_data import ATTACK_PATTERN, COURSE_OF_ACTION, INTRUSION_SET, MALWARE, TOOL, ID_TO_NAME, \
    RELATION


@pytest.mark.parametrize('indicator, expected_result', [
    ([ATTACK_PATTERN.get('response')], ATTACK_PATTERN.get('indicator')),
    ([COURSE_OF_ACTION.get('response')], COURSE_OF_ACTION.get('indicator')),
    ([INTRUSION_SET.get('response')], INTRUSION_SET.get('indicator')),
    ([MALWARE.get('response')], MALWARE.get('indicator')),
    ([TOOL.get('response')], TOOL.get('indicator'))
])
def test_fetch_indicators(mocker, indicator, expected_result):
    from FeedMitreAttackv2 import Client
    client = Client(url="https://cti-taxii.mitre.org", proxies=False, verify=False, tags=[], tlp_color=None)
    client.initialise()
    mocker.patch.object(TAXIICollectionSource, 'query', return_value=indicator)
    mocker.patch.object(json, 'loads', return_value=indicator[0])
    indicators = client.build_iterator(create_relationships=True, limit=6)
    assert indicators == expected_result


@pytest.mark.parametrize('field_name, field_value, expected_result', [
    ('created', '2017-05-31T21:31:43.540Z', '2017-05-31T21:31:43.540Z'),
    ('created', '2019-04-25T20:53:07.719Z\n2019-04-25T20:53:07.814Z', '2019-04-25T20:53:07.719Z'),
    ('modified', '2017-05-31T21:31:43.540Z', '2017-05-31T21:31:43.540Z'),
    ('modified', '2020-03-16T15:38:37.650Z\n2020-01-17T16:45:24.252Z', '2020-03-16T15:38:37.650Z'),
])
def test_handle_multiple_dates_in_one_field(field_name, field_value, expected_result):
    from FeedMitreAttackv2 import handle_multiple_dates_in_one_field
    assert handle_multiple_dates_in_one_field(field_name, field_value) == expected_result


@pytest.mark.parametrize('indicator, expected_result', [
    ({"x_mitre_deprecated": True}, True),
    ({"revoked": True}, True),
    ({}, False)
])
def test_is_indicator_deprecated_or_revoked(indicator, expected_result):
    from FeedMitreAttackv2 import is_indicator_deprecated_or_revoked
    assert is_indicator_deprecated_or_revoked(indicator) == expected_result


@pytest.mark.parametrize('indicator_type, indicator_json, expected_result', [
    ('STIX Attack Pattern', ATTACK_PATTERN.get('response'), ATTACK_PATTERN.get('map_result')),
    ('Course of Action', COURSE_OF_ACTION.get('response'), COURSE_OF_ACTION.get('map_result')),
    ('Intrusion Set', INTRUSION_SET.get('response'), INTRUSION_SET.get('map_result')),
    ('STIX Malware', MALWARE.get('response'), MALWARE.get('map_result')),
    ('STIX Tool', TOOL.get('response'), TOOL.get('map_result'))
])
def test_map_fields_by_type(indicator_type, indicator_json, expected_result):
    from FeedMitreAttackv2 import map_fields_by_type
    assert map_fields_by_type(indicator_type, indicator_json) == expected_result


def test_create_relationship():
    from FeedMitreAttackv2 import create_relationship
    relation = create_relationship(RELATION.get('response'), ID_TO_NAME)
    relation._entity_a = 'entity a'
    relation._entity_a_type = 'STIX Malware'
    relation._entity_b = 'entity b'
    relation._entity_b_type = 'STIX Attack Pattern'
    relation._name = 'uses'
    relation._relation_type = 'IndicatorToIndicator'
    relation._reverse_name = 'used-by'
