from copy import deepcopy

from CommonServerPython import DemistoException
import demistomock as demisto
import pytest
import json
import QRadar_v2  # import module separately for mocker
from QRadar_v2 import (
    QRadarClient,
    FetchMode,
    search_command,
    get_search_command,
    get_search_results_command,
    get_assets_command,
    get_asset_by_id_command,
    get_closing_reasons_command,
    create_note_command,
    get_note_command,
    fetch_incidents_long_running_no_events,
    fetch_incidents_long_running_events,
    enrich_offense_with_events,
    try_create_search_with_retry,
    try_poll_offense_events_with_retry,
    enrich_offense_result,
    get_asset_ips_and_enrich_offense_addresses
)

with open("TestData/commands_outputs.json", "r") as f:
    COMMAND_OUTPUTS = json.load(f)
with open("TestData/raw_responses.json", "r") as f:
    RAW_RESPONSES = json.load(f)


command_tests = [
    ("qradar-searches", search_command, {"query_expression": "SELECT sourceip AS 'MY Source IPs' FROM events"},),
    ("qradar-get-search", get_search_command, {"search_id": "6212b614-074e-41c1-8fcf-1492834576b8"},),
    ("qradar-get-search-results", get_search_results_command, {"search_id": "6212b614-074e-41c1-8fcf-1492834576b8"},),
    ("qradar-get-assets", get_assets_command, {"range": "0-1"}),
    ("qradar-get-asset-by-id", get_asset_by_id_command, {"asset_id": "1928"}),
    ("qradar-get-closing-reasons", get_closing_reasons_command, {}),
    (
        "qradar-create-note",
        create_note_command,
        {"offense_id": "450", "note_text": "XSOAR has the best documentation!"},
    ),
    ("qradar-get-note", get_note_command, {"offense_id": "450", "note_id": "1232"}),
]


@pytest.mark.parametrize("command,command_func,args", command_tests)
def test_commands(command, command_func, args, mocker):
    """
    Test a set of commands given input->output
    tested commands:
      * qradar-searches
      * qradar-get-search
      * qradar-get-search-results
      * qradar-get-assets
      * qradar-get-asset-by
      * qradar-get-closing-reasons
      * qradar-create-note
      * qradar-get-note

    Given:
        - command - command name
        - command_func - function of command
        - args - arguments for command
    When:
        - Command `command` is being called
    Then:
        - Assert the entryContext matches the COMMAND_OUTPUTS map entry value (expected output)
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    mocker.patch.object(client, "send_request", return_value=RAW_RESPONSES[command])
    mocker.patch.object(demisto, "debug")
    res = command_func(client, **args)
    assert COMMAND_OUTPUTS[command] == res.get("EntryContext")


def test_fetch_incidents_long_running_no_events(mocker):
    """
    Assert fetch_incidents_long_running_no_events updates integration context with the expected id and samples

    Given:
        - Fetch incidents is set to: FetchMode.no_events
        - There is an offense to fetch: 450
    When:
        - Fetch loop is triggered
    Then:
        - Assert integration context id is set correctly
        - Assert integration context samples is set with correct length
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    mocker.patch.object(QRadar_v2, "get_integration_context", return_value={})
    mocker.patch.object(QRadar_v2, "fetch_raw_offenses", return_value=[RAW_RESPONSES["fetch-incidents"]])
    mocker.patch.object(demisto, "createIncidents")
    mocker.patch.object(demisto, "debug")
    sic_mock = mocker.patch.object(QRadar_v2, "set_integration_context")

    fetch_incidents_long_running_no_events(client, '', user_query="", ip_enrich=False, asset_enrich=False)

    assert sic_mock.call_args[0][0]['id'] == 450
    assert len(sic_mock.call_args[0][0]['samples']) == 1


def test_fetch_incidents_long_running_events(mocker):
    """
    Assert fetch_incidents_long_running_events updates integration context with the expected id, samples and events

    Given:
        - Fetch incidents is set to: FetchMode.all_events
        - There is an offense to fetch: 450
    When:
        - Fetch loop is triggered
    Then:
        - Assert integration context id is set correctly
        - Assert integration context samples is set with correct length
        - Assert integration context events is set with correct value
    """
    expected_events = "assert ok"

    def mock_enrich_offense_with_events(client, offense, fetch_mode, events_columns, events_limit):
        offense['events'] = expected_events
        return offense

    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    fetch_mode = FetchMode.all_events
    mocker.patch.object(QRadar_v2, "get_integration_context", return_value={})
    mocker.patch.object(QRadar_v2, "fetch_raw_offenses", return_value=[RAW_RESPONSES["fetch-incidents"]])
    QRadar_v2.enrich_offense_with_events = mock_enrich_offense_with_events
    mocker.patch.object(demisto, "createIncidents")
    mocker.patch.object(demisto, "debug")
    sic_mock = mocker.patch.object(QRadar_v2, "set_integration_context")

    fetch_incidents_long_running_events(client, "", "", False, False, fetch_mode, "", "")

    assert sic_mock.call_args[0][0]['id'] == 450
    assert len(sic_mock.call_args[0][0]['samples']) == 1
    incident_raw_json = json.loads(sic_mock.call_args[0][0]['samples'][0]['rawJSON'])
    assert incident_raw_json['events'] == expected_events


def test_enrich_offense_with_events__correlations(mocker):
    """
    Assert enrich_offense_with_events adds an additional WHERE query when FetchMode.correlations_only

    Given:
        - Fetch incidents is set to: FetchMode.correlations_only
    When:
        - Event fetch query is built via in enrich_offense_with_event
    Then:
        - Assert search is created with additional WHERE query
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense = RAW_RESPONSES["fetch-incidents"]
    fetch_mode = FetchMode.correlations_only
    events_cols = ""
    events_limit = ""

    poee_mock = mocker.patch.object(QRadar_v2, "perform_offense_events_enrichment", return_value=offense)
    enrich_offense_with_events(client, offense, fetch_mode, events_cols, events_limit)
    assert poee_mock.call_args[0][1] == "AND LOGSOURCETYPENAME(devicetype) = 'Custom Rule Engine'"


def test_enrich_offense_with_events__all_events(mocker):
    """
    Assert enrich_offense_with_events doesn't add an additional WHERE query when FetchMode.all_events

    Given:
        - Fetch incidents is set to: FetchMode.all_events
    When:
        - Event fetch query is built via in enrich_offense_with_event
    Then:
        - Assert search is created without additional WHERE query
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense = RAW_RESPONSES["fetch-incidents"]
    fetch_mode = FetchMode.all_events
    events_cols = ""
    events_limit = ""

    poee_mock = mocker.patch.object(QRadar_v2, "perform_offense_events_enrichment", return_value=offense)
    enrich_offense_with_events(client, offense, fetch_mode, events_cols, events_limit)
    assert poee_mock.call_args[0][1] == ""


def test_try_create_search_with_retry__semi_happy(mocker):
    """
    Create an event search with a connection error first, and succesful try after

    Given:
        - Event fetch is to be created via the qradar client
    When:
        - Search first returns ConnectionError
        - Search then returns search object
    Then:
        - Assert search is created with id and status
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    events_query = ""
    offense = RAW_RESPONSES["fetch-incidents"]
    max_retries = 3

    mocker.patch.object(client, "search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-searches"]])

    actual_status, actual_id = try_create_search_with_retry(client, events_query, offense, max_retries)
    assert actual_status == "EXECUTE"
    assert actual_id == "a135f4cb-c22a-4b3a-aa7d-83058c219d33"


def test_try_create_search_with_retry__sad(mocker):
    """
    Create an event search with a connection error first, and succesful try after

    Given:
        - Event fetch is to be created via the qradar client
    When:
        - Search first returns ConnectionError
        - Search then returns search object
    Then:
        - Assert search is created with id and status
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    events_query = ""
    offense = RAW_RESPONSES["fetch-incidents"]
    max_retries = 0
    exception_raised = False
    mocker.patch.object(client, "search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-searches"]])

    try:
        try_create_search_with_retry(client, events_query, offense, max_retries)
    except DemistoException:
        exception_raised = True
    assert exception_raised


def test_try_poll_offense_events_with_retry__semi_happy(mocker):
    """
    Poll event with a failure, recovery and success flow

    Given:
        - Event fetch is to be polled via the qradar client
    When:
        - Search first returns ConnectionError
        - Search then returns search is COMPLETED
    Then:
        - Assert events are fetched correctly
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense_id = 450
    query_status = "EXECUTE"
    search_id = "1"
    max_retries = 3
    expected = [{'MY Source IPs': '8.8.8.8'}]

    mocker.patch.object(QRadar_v2, "is_reset_triggered", return_value=False)
    mocker.patch.object(client, "get_search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-get-search"]])
    mocker.patch.object(client, "get_search_results", return_value=RAW_RESPONSES["qradar-get-search-results"])
    mocker.patch.object(demisto, "debug")

    actual = try_poll_offense_events_with_retry(client, offense_id, query_status, search_id, max_retries)
    assert actual == expected


def test_try_poll_offense_events_with_retry__reset(mocker):
    """
    Poll event with when reset is set

    Given:
        - Event fetch is to be polled via the qradar client
    When:
        - Reset trigger is waiting
    Then:
        - Stop fetch and return empty list
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense_id = 450
    query_status = "EXECUTE"
    search_id = "1"
    max_retries = 3

    mocker.patch.object(QRadar_v2, "is_reset_triggered", return_value=True)
    mocker.patch.object(client, "get_search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-get-search"]])
    mocker.patch.object(client, "get_search_results", return_value=RAW_RESPONSES["qradar-get-search-results"])
    mocker.patch.object(demisto, "debug")

    actual = try_poll_offense_events_with_retry(client, offense_id, query_status, search_id, max_retries)
    assert actual == []


def test_try_poll_offense_events_with_retry__sad(mocker):
    """
    Poll event with a failure

    Given:
        - Event fetch is to be polled via the qradar client
    When:
        - Search first returns ConnectionError
        - Recovery is set to 0
    Then:
        - Stop fetch and return empty list
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense_id = 450
    query_status = "EXECUTE"
    search_id = "1"
    max_retries = 0

    mocker.patch.object(QRadar_v2, "is_reset_triggered", return_value=False)
    mocker.patch.object(client, "get_search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-get-search"]])
    mocker.patch.object(demisto, "debug")

    actual = try_poll_offense_events_with_retry(client, offense_id, query_status, search_id, max_retries)
    assert actual == []


def test_enrich_offense_result(mocker):
    """
    Enrich offense results with assets, domains and rules

    Given:
        - Offense response was fetched from QRadar with rule ids and domain ids
    When:
        - Enriching fetched offense
    Then:
        - domain_name has been added to offense
        - domain_name has been added to offense asset
        - rule name has been added to offense
    """
    closing_reason_dict = [{'is_deleted': False, 'is_reserved': False, 'text': 'False-Positive, Tuned', 'id': 2}]
    offense_types = [{'property_name': 'sourceIP', 'custom': False, 'name': 'Source IP', 'id': 0}]
    domains = [{'name': '', 'tenant_id': 0, 'id': 0, 'log_source_group_ids': []}]
    rules = [{'name': 'Outbound port scan', 'id': 100452}]
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense = deepcopy(RAW_RESPONSES["qradar-update-offense"])
    offense['assets'] = deepcopy(RAW_RESPONSES['qradar-get-asset-by-id'])
    response = [offense]

    mocker.patch.object(client, "get_closing_reasons", return_value=closing_reason_dict)
    mocker.patch.object(client, "get_offense_types", return_value=offense_types)
    mocker.patch.object(client, "get_devices", return_value=domains)
    mocker.patch.object(client, "get_rules", return_value=rules)

    enrich_offense_result(client, response)
    assert 'domain_name' in response[0]
    assert 'domain_name' in response[0]['assets'][0]
    assert 'name' in response[0]['rules'][0]


def test_get_asset_ips_and_enrich_offense_addresses__no_enrich():
    """
    Run offense ips enrichment with skip_enrichment=True

    Given:
        - Offense response was fetched from QRadar with source_ip and destination_ip
    When:
        - Enriching fetched offense with skip_enrichment=True
    Then:
        - IPs are not enriched
        - Asset map is returned as a result
    """
    offense = deepcopy(RAW_RESPONSES["qradar-update-offense"])
    src_adrs = {254: '8.8.8.8'}
    dst_adrs = {4: '1.2.3.4'}
    expected = {'8.8.8.8', '1.2.3.4'}
    actual = get_asset_ips_and_enrich_offense_addresses(
        offense, src_adrs, dst_adrs, skip_enrichment=True)
    assert offense == RAW_RESPONSES["qradar-update-offense"]
    assert expected == actual


def test_get_asset_ips_and_enrich_offense_addresses__with_enrich():
    """
    Run offense ips enrichment with skip_enrichment=False

    Given:
        - Offense response was fetched from QRadar with source_ip and destination_ip
    When:
        - Enriching fetched offense with skip_enrichment=False
    Then:
        - IPs are enriched
        - Asset map is returned as a result
    """
    offense = deepcopy(RAW_RESPONSES["qradar-update-offense"])
    src_adrs = {254: '8.8.8.8', 5: '1.2.3.5'}
    dst_adrs = {4: '1.2.3.4'}
    expected_assets = {'8.8.8.8', '1.2.3.4'}
    actual = get_asset_ips_and_enrich_offense_addresses(
        offense, src_adrs, dst_adrs, skip_enrichment=False)
    assert offense != RAW_RESPONSES["qradar-update-offense"]
    assert offense['source_address_ids'] == [src_adrs[254]]
    assert offense['local_destination_address_ids'] == [dst_adrs[4]]
    assert expected_assets == actual


def test_get_assets_for_offense__empty():
    """Check get assets for offense returns an empty list when no value is given

    Given:
    - No assets_ips
    When:
    - Calling get_assets_for_offense
    Then:
    - Return an empty list
    """
    from QRadar_v2 import get_assets_for_offense
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    assert [] == get_assets_for_offense(client, [])


def test_get_assets_for_offense__happy(requests_mock, mocker):
    """Check get assets for offense returns the expected assets

    Given:
    - 1 item in assets_ips
    When:
    - Calling get_assets_for_offense
    Then:
    - Return the asset correlating to assets_ips
    - The asset properties are flatten
    - The interfaces are simplified
    - The assets match the mapping fields
    """
    from QRadar_v2 import get_assets_for_offense, get_mapping_fields
    client = QRadarClient("https://example.com", {}, {"identifier": "*", "password": "*"})
    requests_mock.get(
        'https://example.com/api/asset_model/assets',
        json=RAW_RESPONSES['qradar-get-asset-by-id']
    )
    mocker.patch.object(QRadarClient, 'get_custom_fields', return_value=[])
    mapping_fields = get_mapping_fields(client)

    res = get_assets_for_offense(client, ['8.8.8.8'])
    res_interfaces = res[0]['interfaces'][0]

    assert res[0]['id'] == 1928

    # flatten properties check
    assert res[0]['Unified Name'] == 'ec2-44-234-115-112.us-west-2.compute.amazonaws.com'

    # simplify interfaces check
    assert len(res_interfaces) == 3
    assert res_interfaces['mac_address'] == 'Unknown NIC'
    assert res_interfaces['id'] == 1915
    assert res_interfaces['ip_addresses'] == [{'type': 'IPV4', 'value': '8.8.8.8'}]

    # assets match the mapping fields
    mapping_fields_interfaces = mapping_fields['Assets']['assets']['interfaces']
    assert set(res_interfaces.keys()).issubset(mapping_fields_interfaces.keys())
    assert res_interfaces['ip_addresses'][0].keys() == mapping_fields_interfaces['ip_addresses'].keys()


def test_get_mapping_fields(mocker):
    """Check keys available in the mapping

    Given:
    - One custom field

    When:
    - Calling get-mapping-fields from the UI

    Then:
    - Validate main keys are in
    - Validate custom field came back as intended
    """
    from QRadar_v2 import get_mapping_fields
    custom_fields = [{'name': 'bloop', 'property_type': 'string'}]
    mocker.patch.object(QRadarClient, 'get_custom_fields', return_value=custom_fields)
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    response = get_mapping_fields(client)
    assert response['Offense']
    assert response['Events: Builtin Fields']
    assert response['Assets']
    assert response['Events: Custom Fields']['events']['bloop'] == 'string'


class TestGetCustomProperties:
    error = 'Can\'t send the `filter` argument with `field_name` or `like_name`'
    client = QRadarClient("https://example.com", {}, {"identifier": "*", "password": "*"})

    def test_filter_with_field_name(self):
        from QRadar_v2 import get_custom_properties_command
        with pytest.raises(DemistoException, match=self.error):
            get_custom_properties_command(self.client, filter='name="hatul"', field_name='b,c')

    def test_filter_with_like_name(self):
        from QRadar_v2 import get_custom_properties_command
        with pytest.raises(DemistoException, match=self.error):
            get_custom_properties_command(self.client, filter='name="hatul"', like_name='b,c')

    def test_filter_with_like_name_and_name_field(self):
        from QRadar_v2 import get_custom_properties_command
        with pytest.raises(DemistoException, match=self.error):
            get_custom_properties_command(self.client, filter='name="hatul"', field_name='a,g', like_name='b,c')

    def test_filter_only(self, requests_mock):
        from QRadar_v2 import get_custom_properties_command
        requests_mock.get(
            'https://example.com/api/config/event_sources/custom_properties/regex_properties?filter=name%3D%22trol%22',
            json=[{'name': 'bloop'}]
        )
        resp = get_custom_properties_command(self.client, filter='name="trol"')
        assert resp['EntryContext']['QRadar.Properties'][0]['name'] == 'bloop'

    def test_name_field_only(self, requests_mock):
        from QRadar_v2 import get_custom_properties_command
        requests_mock.get(
            'https://example.com/api/config/event_sources/custom_properties/regex_properties?filter=name%3D+%22trol%22',
            json=[{'name': 'bloop'}]
        )
        resp = get_custom_properties_command(self.client, field_name='trol')
        assert resp['EntryContext']['QRadar.Properties'][0]['name'] == 'bloop'

    def test_like_name_only(self, requests_mock):
        from QRadar_v2 import get_custom_properties_command
        requests_mock.get(
            'https://example.com/api/config/event_sources/custom_properties/regex_properties?filter=name+ILIKE+%22%25trol%25%22',
            json=[{'name': 'bloop'}]
        )
        resp = get_custom_properties_command(self.client, like_name='trol')
        assert resp['EntryContext']['QRadar.Properties'][0]['name'] == 'bloop'
