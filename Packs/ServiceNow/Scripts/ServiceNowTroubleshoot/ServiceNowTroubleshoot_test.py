import json
from ServiceNowTroubleshoot import (get_integrations_details, filter_instances_data, categorize_active_incidents,
                                    parse_disabled_instances, parse_enabled_instances)
import demistomock as demisto


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        res = json.loads(f.read())
        if 'body' in res:
            res['body'] = json.dumps(res.get('body'))
        return res


def test_get_integrations_details(mocker):
    """
    Given:
        - A mock HTTP response loaded from a JSON file containing integration details.
    When:
        - `get_integrations_details` is called.
    Then:
        - The function should return a dictionary with two integrations.
        - The dictionary keys should match the expected integration instance names.
        - Each integration entry should contain a 'health' field.
    """
    http_response = util_load_json("test_data/setting_integration_search_http_response.json")
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=http_response)
    res = get_integrations_details()
    assert len(res) == 2
    assert list(res.keys()) == ['ServiceNow v2_instance_2', 'ServiceNow v2_instance_1']
    assert 'health' in res['ServiceNow v2_instance_2']
    assert 'health' in res['ServiceNow v2_instance_1']


def test_filter_instances_data():
    """
    Given:
        - A dictionary containing health and configuration details of multiple integration instances.
        - Some instances are enabled, while others are disabled.
    When:
        - `filter_instances_data` is called.
    Then:
        - Enabled instances should be included in the filtered data.
        - Disabled instances should be listed separately.
        - The function should correctly classify instances based on their enabled status.
    """
    instances_health = util_load_json("test_data/filtering_instances_data.json")
    filtered_data, disabled_instances = filter_instances_data(instances_health)
    assert 'ServiceNow v2_instance_2' in filtered_data
    assert 'ServiceNow v2_instance_1' in disabled_instances


def test_categorize_active_incidents(mocker):
    """
    Given:
        - A list of disabled instances containing 'ServiceNow v2_instance_1'.
        - A mock HTTP response with active incidents.
    When:
        - `categorize_active_incidents` is called.
    Then:
        - Incidents should be correctly grouped under enabled and disabled instances.
    """
    disabled_instances = ['ServiceNow v2_instance_1']
    http_response = util_load_json("test_data/incidents_search_http_response.json")
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=http_response)
    res_enabled_incidents_instances, res_disabled_incidents_instances = categorize_active_incidents(disabled_instances)
    assert res_enabled_incidents_instances == {'ServiceNow v2_instance_2': ['ServiceNow Incident INC0011111']}
    assert res_disabled_incidents_instances == {'ServiceNow v2_instance_1': ['ServiceNow Incident INC0022222']}


def test_parse_disabled_instances():
    """
    Given:
        - A dictionary containing disabled instances with their active incidents.
    When:
        - `parse_disabled_instances` is called.
    Then:
        - The function should return a formatted markdown string listing disabled instances and their active incidents.
    """

    disabled_incidents_instances = {'ServiceNow v2_instance_1': ['ServiceNow Incident INC0022222']}
    res = parse_disabled_instances(disabled_incidents_instances)
    expected_result = ('### Disabled instances with active incidents created more than 30 days ago\n'
                       '|Active incidents more than created 30 days ago|Instance|Total|\n|---|---|---|\n|'
                       ' ServiceNow Incident INC0022222 | ServiceNow v2_instance_1 | 1 |\n')
    assert res == expected_result


def test_parse_enabled_instances():
    """
    Given:
        - A dictionary containing disabled instances with their active incidents.
    When:
        - `parse_disabled_instances` is called.
    Then:
        - It should return a formatted markdown string listing disabled instances and their active incidents.
    """
    enabled_instances_health = {
        'ServiceNow v2_instance_2': {
            'id': '11111', 'name': 'ServiceNow v2_instance_2', 'version': 5, 'sequenceNumber': 453233, 'primaryTerm': 1,
            'modified': '2025-01-27T09:14:18.207475895Z', 'sizeInBytes': 3066, 'enabled': 'true',
            'configvalues': {'api_version': 'None', 'close_custom_state': 'None', 'close_incident': 'None',
                             'close_ticket': 'False', 'close_ticket_multiple_options': 'None', 'comment_tag': 'comments',
                             'comment_tag_from_servicenow': 'CommentFromServiceNow', 'custom_fields': 'None',
                             'display_date_format': 'None', 'fetch_limit': '10', 'fetch_time': '1 year',
                             'file_tag': 'ForServiceNow', 'file_tag_from_service_now': 'FromServiceNow',
                             'get_attachments': 'False', 'incidentFetchInterval': '1', 'incidentType': 'None',
                             'incident_name': 'number', 'insecure': 'False', 'isFetch': 'True', 'look_back': '0',
                             'mirror_direction': 'None', 'mirror_limit': '100', 'mirror_notes_for_new_incidents': 'False',
                             'proxy': 'False', 'server_close_custom_state': 'None', 'server_custom_close_code': 'None',
                             'sysparm_query': 'stateNOT IN6,7', 'ticket_type': 'incident', 'timestamp_field': 'opened_at',
                             'update_timestamp_field': 'sys_updated_on', 'url': 'https://url_dummy/',
                             'use_display_value': 'False', 'use_oauth': 'False', 'work_notes_tag': 'work_notes',
                             'work_notes_tag_from_servicenow': 'WorkNoteFromServiceNow'},
            'brand': 'ServiceNow v2', 'category': 'Case Management',
            'health': {'id': 'ServiceNow v2.ServiceNow v2_instance_2', 'version': 16,
                       'sequenceNumber': 454401, 'primaryTerm': 1, 'modified': '2025-01-27T09:26:49.458264357Z',
                       'sizeInBytes': 516, 'sortValues': ['5994'], 'brand': 'ServiceNow v2',
                       'instance': 'ServiceNow v2_instance_2', 'incidentsPulled': 10, 'incidentsDropped': 0,
                       'lastPullTime': '2025-01-27T09:26:45.226409678Z', 'lastError': ''
                       }
        }
    }
    enabled_incidents_instances = {'ServiceNow v2_instance_2': ['ServiceNow Incident INC0011111']}
    expected = ('### Enabled Instances Health Information\n'
                '|Instance Name|Last Pull Time|Names of Active Incidents Created 30 days ago|'
                'Number of Incidents Pulled in Last Fetch|Query|Size In Bytes|Total Active Incidents Created 30 days ago|\n'
                '|---|---|---|---|---|---|---|\n| ServiceNow v2_instance_2 | 2025-01-27T09:26:45.226409678Z |'
                ' ServiceNow Incident INC0011111 | 10 | stateNOT IN6,7 | 3066 | 1 |\n'
                )
    res = parse_enabled_instances(enabled_instances_health, enabled_incidents_instances)
    assert res == expected
