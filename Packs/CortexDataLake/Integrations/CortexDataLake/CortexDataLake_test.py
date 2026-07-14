import base64
import pytest
import json
import re
from datetime import datetime, timedelta
from unittest.mock import MagicMock

from pytest_mock import MockerFixture
from CommonServerPython import parse_date_range, DemistoException
from CortexDataLake import (
    FIRST_FAILURE_TIME_CONST,
    LAST_FAILURE_TIME_CONST,
    STANDARD_TOKEN_URL,
    IS_FEDRAMP_CONST,
    FEDRAMP_TOKEN_URL,
)

HUMAN_READABLE_TIME_FROM_EPOCH_TIME_TEST_CASES = [
    (1582210145000000, False, "2020-02-20T14:49:05"),
    (1582210145000000, True, "2020-02-20T14:49:05Z"),
]

QUERY_TIMESTAMPS_TEST_CASES = [
    (
        {"start_time": "2018-04-26 00:00:00", "end_time": "2020-04-26 00:00:00"},
        ("2018-04-26 00:00:00", "2020-04-26 00:00:00"),
        "Only start time and end time",
    ),
    ({"time_range": "1 days"}, "1 days", "Only time range"),
    (
        {"start_time": "2018-04-26 00:00:00", "end_time": "2020-04-26 00:00:00", "time_range": "1 days"},
        "1 days",
        "Both start/end time and time range",
    ),
]


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


@pytest.mark.parametrize("epoch_time, utc_time, expected_response", HUMAN_READABLE_TIME_FROM_EPOCH_TIME_TEST_CASES)
def test_human_readable_time_from_epoch_time(epoch_time, utc_time, expected_response):
    from CortexDataLake import human_readable_time_from_epoch_time

    assert human_readable_time_from_epoch_time(epoch_time, utc_time=utc_time) == expected_response


@pytest.mark.parametrize("args, expected_response, test_case", QUERY_TIMESTAMPS_TEST_CASES)
def test_query_timestamp(args, expected_response, test_case):
    from CortexDataLake import query_timestamp

    if expected_response == "1 days":
        expected_start, expected_end = parse_date_range(expected_response)
        expected_start = expected_start.replace(microsecond=0)
        expected_end = expected_end.replace(microsecond=0)
        generated_start, generated_end = query_timestamp(args)
        generated_start = generated_start
        generated_end = generated_end
        assert (generated_start, generated_end) == (expected_start, expected_end), f"Failed: {test_case}"
    else:
        generated_start, generated_end = query_timestamp(args)
        assert (str(generated_start), str(generated_end)) == expected_response, f"Failed: {test_case}"


def test_parse_tree_by_root_to_leaf_paths():
    from CortexDataLake import parse_tree_by_root_to_leaf_paths

    root = "a"
    body = {"b": 2, "c": 3, "d": {"e": 5, "f": 6, "g": {"h": 8, "i": 9}}}
    expected_output = {"a.b": 2, "a.c": 3, "a.d.e": 5, "a.d.f": 6, "a.d.g.h": 8, "a.d.g.i": 9}
    assert expected_output == parse_tree_by_root_to_leaf_paths(root, body)


def test_build_where_clause():
    from CortexDataLake import build_where_clause

    test_cases = [
        ({"query": "Test"}, "Test"),
        ({"rule": "rule"}, '(rule_matched = "rule")'),
        ({"rule": "rule,another_rule"}, '(rule_matched = "rule" OR rule_matched = "another_rule")'),
        ({"rule": "rule", "from_zone": "UTC"}, '(rule_matched = "rule") AND (from_zone = "UTC")'),
        (
            {
                "source_ip": "ip1,ip2",
                "dest_ip": "ip3,ip4",
                "rule_matched": "rule1",
                "from_zone": "UTC,UTC2",
                "dest_port": "555,666",
                "action": "allow,unknown",
                "file_sha_256": "hash1,hash2",
                "file_name": "name1,name2",
            },
            '(source_ip.value = "ip1" OR source_ip.value = "ip2") '
            'AND (dest_ip.value = "ip3" OR dest_ip.value = "ip4") '
            'AND (rule_matched = "rule1") '
            'AND (from_zone = "UTC" OR from_zone = "UTC2") '
            'AND (action.value = "allow" OR action.value = "unknown") '
            'AND (file_sha_256 = "hash1" OR file_sha_256 = "hash2") '
            'AND (file_name = "name1" OR file_name = "name2") '
            "AND (dest_port = 555 OR dest_port = 666)",
        ),
        ({"source_ip": "ip1", "non_relevant_arg": "value"}, '(source_ip.value = "ip1")'),
    ]
    for args, expected_result in test_cases:
        assert build_where_clause(args) == expected_result


def test_build_where_clause_ip_port():
    from CortexDataLake import build_where_clause

    test_cases = [
        ({"query": "Test"}, "Test"),
        (
            {"ip": "ip1,ip2", "port": "555,888"},
            '(source_ip.value = "ip1" OR dest_ip.value = "ip1" OR '
            'source_ip.value = "ip2" OR dest_ip.value = "ip2") '
            "AND (source_port = 555 OR dest_port = 555 OR source_port = 888 OR dest_port = 888)",
        ),
        ({"source_ip": "ip1", "non_relevant_arg": "value"}, '(source_ip.value = "ip1")'),
    ]
    for args, expected_result in test_cases:
        assert build_where_clause(args) == expected_result


def test_prepare_fetch_incidents_query():
    from CortexDataLake import prepare_fetch_incidents_query

    timestamp = "2020-02-20T16:49:05"
    firewall_subtype = ["attack", "url"]
    fetch_fields = "*"
    firewall_severity = ["Critical", "High"]
    table_name = "firewall.threat"
    fetch_limit = 10
    expected_response = (
        "SELECT * FROM `firewall.threat` WHERE "
        'time_generated Between TIMESTAMP("2020-02-20T16:49:05") '
        "AND CURRENT_TIMESTAMP AND"
        ' (sub_type.value = "attack" OR sub_type.value = "url") AND'
        ' (vendor_severity.value = "Critical" OR vendor_severity.value = "High") '
        "ORDER BY time_generated ASC "
        "LIMIT 10"
    )
    assert expected_response == prepare_fetch_incidents_query(
        timestamp, firewall_severity, table_name, firewall_subtype, fetch_fields, fetch_limit
    )

    # Assert that an exception is raised in case the fetch filter_query and fetch subtype/severity are given:
    filter_query = "dest_port = 54321 AND session_id = 97425"
    try:
        prepare_fetch_incidents_query(
            timestamp, firewall_severity, table_name, firewall_subtype, fetch_fields, fetch_limit, filter_query
        )
    except DemistoException as e:
        assert "Fetch Filter parameter cannot be used with Subtype/Severity parameters" in str(e)

    # Given the fetch filter_query and no fetch subtype/severity filters, assert the returned response is as expected:
    firewall_severity = []
    firewall_subtype = []
    expected_response = (
        "SELECT * FROM `firewall.threat` WHERE "
        'time_generated Between TIMESTAMP("2020-02-20T16:49:05") '
        "AND CURRENT_TIMESTAMP AND"
        " dest_port = 54321 AND session_id = 97425 "
        "ORDER BY time_generated ASC "
        "LIMIT 10"
    )
    assert expected_response == prepare_fetch_incidents_query(
        timestamp, firewall_severity, table_name, firewall_subtype, fetch_fields, fetch_limit, filter_query
    )


MILLISECONDS_HUMAN_READABLE_TIME_FROM_EPOCH_TIME_TEST_CASES = [
    (1582017903000000, "2020-02-18T09:25:03.001Z"),
    (1582027208002000, "2020-02-18T12:00:08.003Z"),
]


@pytest.mark.parametrize("epoch_time, expected_response", MILLISECONDS_HUMAN_READABLE_TIME_FROM_EPOCH_TIME_TEST_CASES)
def test_epoch_to_timestamp_and_add_milli(epoch_time, expected_response):
    from CortexDataLake import epoch_to_timestamp_and_add_milli

    assert epoch_to_timestamp_and_add_milli(epoch_time) == expected_response


def test_get_table_name():
    from CortexDataLake import get_table_name

    query = 'SELECT pcap FROM `firewall.threat` WHERE is_packet_capture = true  AND severity = "Critical" LIMIT 10'
    assert get_table_name(query) == "firewall.threat"
    query = "Wrongly formmated query"
    assert get_table_name(query) == "Unrecognized table name"


def test_query_logs_command_transform_results_1():
    """
    Given:
        - a list of CDL query results
    When
        - running query_logs_command function
    Then
        - if transform_results is not specified, CDL query results are mapped into the CDL common context (test 1)
        - if transform_results is set to false, CDL query results are returned unaltered (test 2)
    """
    from CortexDataLake import query_logs_command

    cdl_records = load_test_data("./test_data/test_query_logs_command_transform_results_original.json")
    cdl_records_xform = load_test_data("./test_data/test_query_logs_command_transform_results_xformed.json")

    class MockClient:
        def query_loggings(self, query, page_number=None, page_size=None):
            return cdl_records, []

    # test 1, with no transform_results options, should transform to common context
    _, results_xform, _ = query_logs_command({"limit": "1", "query": "SELECT * FROM `firewall.traffic`"}, MockClient())
    assert results_xform == {"CDL.Logging": cdl_records_xform}

    # test 2, with transform_results options, should transform to common context
    _, results_noxform, _ = query_logs_command(
        {"limit": "1", "query": "SELECT * FROM `firewall.traffic`", "transform_results": "false"}, MockClient()
    )
    assert results_noxform == {"CDL.Logging": cdl_records}


def test_query_logs_sls_command_transform_results_1():
    """
    Given:
        - a list of SLS query results
    When
        - running query_logs_sls_command function
    Then
        - if transform_results is not specified, SLS query results are mapped into the SLS common context (test 1)
        - if transform_results is set to false, SLS query results are returned unaltered (test 2)
    """
    from CortexDataLake import query_logs_sls_command

    cdl_records = load_test_data("./test_data/test_query_logs_sls_command_transform_results_original.json")
    cdl_records_xform = load_test_data("./test_data/test_query_logs_sls_command_transform_results_xformed.json")

    class MockClient:
        def query_loggings(self, query, page_number=None, page_size=None):
            return cdl_records, []

    # test 1, with no transform_results options, should transform to common context
    _, results_xform, _ = query_logs_sls_command({"limit": "1", "query": "SELECT * FROM `firewall.traffic`"}, MockClient())
    assert results_xform == {"SLS.Logging": cdl_records_xform}

    # test 2, with transform_results options, should transform to common context
    _, results_noxform, _ = query_logs_sls_command(
        {"limit": "1", "query": "SELECT * FROM `firewall.traffic`", "transform_results": "false"}, MockClient()
    )
    assert results_noxform == {"SLS.Logging": cdl_records}


def test_query_logs_command_transform_sysmtem_logs():
    """
    Given:
        - a list of CDL query results from the log.system table.
    When
        - running query_logs_command function
    Then
        - the CDL query results from the log.system table should be transformed to the system log context format.
    """
    from CortexDataLake import query_logs_command

    cdl_records = load_test_data("./test_data/test_query_logs_command_transform_results_system_logs.json")
    cdl_records_xform = load_test_data("./test_data/test_query_logs_command_transform_results_system_logs_xformed.json")

    class MockClient:
        def query_loggings(self, query, page_number=None, page_size=None):
            return cdl_records, []

    _, results_xform, _ = query_logs_command({"limit": "1", "query": "SELECT * FROM `log.system`"}, MockClient())

    assert results_xform == {"CDL.Logging": cdl_records_xform}


def test_query_logs_sls_command_transform_sysmtem_logs():
    """
    Given:
        - a list of SLS query results from the log.system table.
    When
        - running query_logs_sls_command function
    Then
        - the SLS query results from the log.system table should be transformed to the system log context format.
    """
    from CortexDataLake import query_logs_sls_command

    cdl_records = load_test_data("./test_data/test_query_logs_sls_command_transform_results_system_logs.json")
    cdl_records_xform = load_test_data("./test_data/test_query_logs_sls_command_transform_results_system_logs_xformed.json")

    class MockClient:
        def query_loggings(self, query, page_number=None, page_size=None):
            return cdl_records, []

    _, results_xform, _ = query_logs_sls_command({"limit": "1", "query": "SELECT * FROM `log.system`"}, MockClient())

    assert results_xform == {"SLS.Logging": cdl_records_xform}


def test_query_gp_logs_command():
    """
    Given:
        - a list of CDL query results from the firewall.globalprotect table.
    When
        - running query_gp_logs_command function
    Then
        - the CDL query results from the firewall.globalprotect table should be transformed to the GP log context format.
    """
    from CortexDataLake import query_gp_logs_command

    cdl_records = load_test_data("./test_data/test_query_logs_command_transform_results_gp_logs.json")
    cdl_records_xform = load_test_data("./test_data/test_query_logs_command_transform_results_gp_logs_xformed.json")

    class MockClient:
        def query_loggings(self, query, page_number=None, page_size=None):
            return cdl_records, []

    _, results_xform, _ = query_gp_logs_command({"limit": "1", "start_time": "1970-01-01 00:00:00"}, MockClient())

    assert results_xform == {"CDL.Logging.GlobalProtect": cdl_records_xform}


def test_query_gp_logs_sls_command():
    """
    Given:
        - a list of SLS query results from the firewall.globalprotect table.
    When
        - running query_gp_logs_sls_command function
    Then
        - the SLS query results from the firewall.globalprotect table should be transformed to the GP log context format.
    """
    from CortexDataLake import query_gp_logs_sls_command

    cdl_records = load_test_data("./test_data/test_query_logs_sls_command_transform_results_gp_logs.json")
    cdl_records_xform = load_test_data("./test_data/test_query_logs_sls_command_transform_results_gp_logs_xformed.json")

    class MockClient:
        def query_loggings(self, query, page_number=None, page_size=None):
            return cdl_records, []

    _, results_xform, _ = query_gp_logs_sls_command({"limit": "1", "start_time": "1970-01-01 00:00:00"}, MockClient())

    assert results_xform == {"SLS.Logging.GlobalProtect": cdl_records_xform}


class TestPagination:
    """
    A class to test the pagination mechanism in the Cortex Data Lake integration
    """

    args = {"page_size": "10", "page": "2", "limit": "10", "fields": "all", "start_time": "1970-01-01 00:00:00"}

    class MockClient:
        def query_loggings(self, query, page_number=None, page_size=None):
            assert "LIMIT" not in query
            assert page_number is not None
            return [], []

    @pytest.mark.parametrize(
        "command_function",
        [
            "query_logs_command",
            "get_critical_logs_command",
            "get_social_applications_command",
            "search_by_file_hash_command",
            "query_threat_logs_command",
            "query_url_logs_command",
            "query_file_data_command",
            "query_gp_logs_command",
        ],
    )
    def test_command_pagination(self, command_function):
        """
        Given:
            - A query to fetch data from the Cortex Data Lake
            - A page size of 10
            - A page number of 2
        When
            - Running any command function that involves pagination
        Then
            - Validate that the query is built correctly without the LIMIT value, and the page number is set
        """
        command = getattr(__import__("CortexDataLake"), command_function)
        _, _, _ = command(self.args, self.MockClient())

    def test_build_query(self):
        """
        Given:
            - A query to fetch data from the Cortex Data Lake
            - A page size of 10
            - A page number of 2
        When
            - Building the query to fetch data from the Cortex Data Lake
        Then
            - Validate that the query is built correctly without the LIMIT value
        """
        from CortexDataLake import build_query

        fields, query = build_query(self.args, "firewall.traffic")
        assert "LIMIT" not in query


class TestBackoffStrategy:
    """A class to test the backoff strategy mechanism"""

    @pytest.mark.parametrize(
        "integration_context, exception",
        [
            (
                {
                    FIRST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                    LAST_FAILURE_TIME_CONST: datetime.utcnow().isoformat(),
                },
                True,
            ),
            (
                {
                    FIRST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(hours=3)).isoformat(),
                    LAST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(minutes=3)).isoformat(),
                },
                True,
            ),
            (
                {
                    FIRST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(hours=48)).isoformat(),
                    LAST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                },
                True,
            ),
            (
                {
                    FIRST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                    LAST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(minutes=1)).isoformat(),
                },
                False,
            ),
            (
                {
                    FIRST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(hours=3)).isoformat(),
                    LAST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(minutes=10)).isoformat(),
                },
                False,
            ),
            (
                {
                    FIRST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(hours=48)).isoformat(),
                    LAST_FAILURE_TIME_CONST: (datetime.utcnow() - timedelta(minutes=60)).isoformat(),
                },
                False,
            ),
            ({}, False),
        ],
    )
    def test_backoff_strategy(self, integration_context, exception):
        """
        Given:
            - An integration context that represents a try to fetch in the 1st hour & 1st minute window
            - An integration context that represents a try to fetch in the first 48 hours & 10 minutes window
            - An integration context that represents a try to fetch after 48 hours & 60 minutes window
            - An integration context that represents a try to fetch in the 1st hour & after 1st minute window
            - An integration context that represents a try to fetch in the first 48 hours & after 10 minutes window
            - An integration context that represents a try to fetch after 48 hours & after 60 minutes window
            - An integration context that represents the first time the integration has failed to fetch the access token
        When
            - Checking whether to allow access token fetching or failing the integration
        Then
            - Validate that a DemistoException is being raised
            - Validate that a DemistoException is being raised
            - Validate that a DemistoException is being raised
            - Validate that no DemistoException is being raised
            - Validate that no DemistoException is being raised
            - Validate that no DemistoException is being raised
            - Validate that no DemistoException is being raised
        """
        from CortexDataLake import Client

        if exception:
            with pytest.raises(DemistoException):
                Client._backoff_strategy(integration_context)
        else:
            Client._backoff_strategy(integration_context)

    @pytest.mark.parametrize(
        "integration_context",
        [
            ({}),
            (
                {
                    FIRST_FAILURE_TIME_CONST: datetime(2020, 12, 10, 11, 27, 55, 764401).isoformat(),
                    LAST_FAILURE_TIME_CONST: (datetime(2020, 12, 10, 11, 27, 55, 764401) + timedelta(minutes=1)).isoformat(),
                }
            ),
        ],
    )
    def test_cache_failure_times(self, integration_context):
        """
        Given:
            - An empty integration context
            - An integration context with first failure data & last failure data
        When
            - Caching the failure times in the integration context
        Then
            - Validate that both first failure data & last failure data are in the integration context and have the
            same data
            - Validate that both first failure data & last failure data are in the integration context and have
            different data

        """
        from CortexDataLake import Client

        updated_ic = Client._cache_failure_times(integration_context.copy())
        assert FIRST_FAILURE_TIME_CONST in updated_ic
        assert LAST_FAILURE_TIME_CONST in updated_ic
        if integration_context:
            assert updated_ic[LAST_FAILURE_TIME_CONST] != updated_ic[FIRST_FAILURE_TIME_CONST]
        else:
            assert updated_ic[LAST_FAILURE_TIME_CONST] == updated_ic[FIRST_FAILURE_TIME_CONST]

    @pytest.mark.parametrize(
        "exc, res", [("Error in API call [400] - $REASON", True), ("Error in API call [403] - $REASON", False)]
    )
    def test_is_bad_request_error(self, exc, res):
        """
        Given:
            - An exception message of status 400
            - An exception message of status 403
        When
            - Checking if the exception message is of status code 400
        Then
            - Validate that there's a match with the BAD_REQUEST_REGEX regex
            - Validate that there's no match with the BAD_REQUEST_REGEX regex
        """
        from CortexDataLake import BAD_REQUEST_REGEX

        ans = re.match(BAD_REQUEST_REGEX, exc)
        if res:
            assert ans is not None
        else:
            assert ans is None


@pytest.mark.parametrize(
    "configured_reg_id_url, mock_is_fedramp_return_value, expected_result",
    [
        pytest.param(
            "test_id_custom@https://custom.test.com/api",
            False,
            ("https://custom.test.com/api", "test_id_custom"),
            id="FedRAMP tenant with URL in registration ID",
        ),
        pytest.param(
            "test_id_fr",
            True,
            (FEDRAMP_TOKEN_URL, "test_id_fr"),
            id="FedRAMP tenant without URL in registration ID",
        ),
        pytest.param(
            "test_id_std@https://custom.test.com/api",
            False,
            ("https://custom.test.com/api", "test_id_std"),
            id="Standard tenant with URL in registration ID",
        ),
        pytest.param(
            "test_id_std_nohost",
            False,
            (STANDARD_TOKEN_URL, "test_id_std_nohost"),
            id="Standard tenant without URL in registration ID",
        ),
    ],
)
def test_extract_client_args(
    mocker: MockerFixture,
    configured_reg_id_url: str,
    mock_is_fedramp_return_value: bool,
    expected_result: tuple,
):
    """
    Given:
        - Configured "Registration ID" param value.
    When:
        - Calling `extract_client_args`.
    Then:
        - Assert returned token retrieval URL and registration ID are as expected.
    """
    from CortexDataLake import extract_client_args

    mocker.patch("CortexDataLake.is_fedramp_tenant", return_value=mock_is_fedramp_return_value)
    result = extract_client_args(configured_reg_id_url)
    assert result == expected_result


@pytest.mark.parametrize(
    "license_field_url, integration_context, expected_is_fedramp",
    [
        pytest.param(
            "https://tenant1.paloaltonetworks.com",
            {IS_FEDRAMP_CONST: False},
            False,
            id="Standard tenant with 'https' scheme and integration context",
        ),
        pytest.param(
            "https://tenant1.paloaltonetworks.com",
            {},
            False,
            id="Standard tenant with 'https' scheme and no integration context",
        ),
        pytest.param(
            "tenant2.paloaltonetworks.com",
            {},
            False,
            id="Standard tenant without 'https' scheme and no integration context",
        ),
        pytest.param(
            "https://fr-tenant1.federal.paloaltonetworks.com",
            {IS_FEDRAMP_CONST: True},
            True,
            id="FedRAMP tenant with 'https' scheme and integration context",
        ),
        pytest.param(
            "https://fr-tenant1.federal.paloaltonetworks.com",
            {},
            True,
            id="FedRAMP tenant with 'https' scheme and no integration context",
        ),
        pytest.param(
            "fr-tenant2.federal.paloaltonetworks.com",
            {},
            True,
            id="FedRAMP tenant without 'https' scheme and no integration context",
        ),
    ],
)
def test_is_fedramp_tenant(
    mocker: MockerFixture,
    integration_context,
    license_field_url: str,
    expected_is_fedramp: bool,
):
    """
    Given:
        - The integration context and the domain name from `demisto.getLicenseCustomField`.
    When:
        - Calling `is_fedramp_tenant`.
    Then:
        - Assert function calls are as expected and returned FedRAMP status is correct.
    """
    from CortexDataLake import demisto, is_fedramp_tenant

    mock_get_integration_context = mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)
    mock_set_integration_context = mocker.patch.object(demisto, "setIntegrationContext")
    mocker_get_license_custom_field = mocker.patch.object(demisto, "getLicenseCustomField", return_value=license_field_url)
    is_cached = IS_FEDRAMP_CONST in integration_context

    is_fedramp = is_fedramp_tenant()

    assert mock_get_integration_context.call_count == 1
    assert mocker_get_license_custom_field.call_count == 0 if is_cached else 1
    assert mock_set_integration_context.call_count == 0 if is_cached else 1
    assert is_fedramp == expected_is_fedramp


# A valid base64-encoded 32-byte AES-GCM encryption key used across the SCM tests.
VALID_SCM_ENC_KEY_B64 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii")
SCM_CLIENT_SECRET = "super-secret-client-secret"  # guardrails-disable-line
SCM_REGISTRATION_ID = "reg-id-123"


def _build_scm_client(mocker: MockerFixture, integration_context: dict | None = None):
    """Constructs a Client in SCM auth mode with demisto context mocked so __init__ performs no network I/O.

    The integration_context passed here is what demisto.getIntegrationContext() returns during __init__.
    Callers that want to exercise a real authorize path should pass an empty/mismatched context AND mock
    the relevant authorize method (or Client._http_request) before calling.
    """
    from CortexDataLake import AUTH_MODE_SCM, demisto

    mocker.patch.object(
        demisto, "getIntegrationContext", return_value=integration_context if integration_context is not None else {}
    )
    mocker.patch.object(demisto, "setIntegrationContext")
    from CortexDataLake import Client

    return Client(
        token_retrieval_url="https://oproxy.demisto.ninja",  # guardrails-disable-line
        registration_id=SCM_REGISTRATION_ID,
        use_ssl=True,
        proxy=False,
        refresh_token=None,
        enc_key=VALID_SCM_ENC_KEY_B64,
        client_secret=SCM_CLIENT_SECRET,
        auth_mode=AUTH_MODE_SCM,
    )


def _decrypt_scm_signature(signature_b64: str, enc_key_b64: str) -> dict:
    """Decrypts a base64 (gcm_nonce + ciphertext) SCM signature and returns the recovered JSON plaintext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.b64decode(signature_b64)
    gcm_nonce, ciphertext = raw[:12], raw[12:]
    key = base64.b64decode(enc_key_b64)
    plaintext = AESGCM(key).decrypt(gcm_nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def test_build_scm_signature_round_trip():
    """
    Given:
        - A known base64-encoded 32-byte AES-GCM encryption key, a client secret, and a timestamp.
    When:
        - Calling build_scm_signature and decrypting the produced blob (first 12 bytes = gcm nonce).
    Then:
        - The recovered JSON contains the expected client_secret and timestamp.
        - The recovered anti-replay nonce, once base64-decoded, is between 12 and 24 bytes.
    """
    from CortexDataLake import build_scm_signature

    timestamp = 1_700_000_000
    signature = build_scm_signature(VALID_SCM_ENC_KEY_B64, SCM_CLIENT_SECRET, timestamp)

    recovered = _decrypt_scm_signature(signature, VALID_SCM_ENC_KEY_B64)

    assert recovered["client_secret"] == SCM_CLIENT_SECRET
    assert recovered["timestamp"] == timestamp
    decoded_nonce = base64.b64decode(recovered["nonce"])
    assert 12 <= len(decoded_nonce) <= 24


@pytest.mark.parametrize(
    "raw_key_len",
    [
        pytest.param(31, id="31-byte key is rejected"),
        pytest.param(33, id="33-byte key is rejected"),
    ],
)
def test_build_scm_signature_invalid_key_length(raw_key_len: int):
    """
    Given:
        - A base64-encoded encryption key whose decoded length is not exactly 32 bytes.
    When:
        - Calling build_scm_signature.
    Then:
        - A DemistoException is raised (invalid encryption key length).
    """
    from CortexDataLake import build_scm_signature

    bad_key_b64 = base64.b64encode(b"x" * raw_key_len).decode("ascii")
    with pytest.raises(DemistoException):
        build_scm_signature(bad_key_b64, SCM_CLIENT_SECRET, 1_700_000_000)


def test_build_scm_request_body_binds_inner_and_outer_timestamp(mocker: MockerFixture):
    """
    Given:
        - A frozen time source so int(time.time()) is deterministic.
    When:
        - Calling build_scm_request_body.
    Then:
        - The returned body carries registration_id, timestamp and signature.
        - The outer body timestamp equals the inner signed timestamp (verified by decrypting the signature).
    """
    from CortexDataLake import build_scm_request_body

    frozen_ts = 1_712_345_678
    mocker.patch("CortexDataLake.time.time", return_value=frozen_ts + 0.9)

    body = build_scm_request_body(SCM_REGISTRATION_ID, VALID_SCM_ENC_KEY_B64, SCM_CLIENT_SECRET)

    assert body["registration_id"] == SCM_REGISTRATION_ID
    assert body["timestamp"] == frozen_ts
    assert "signature" in body

    recovered = _decrypt_scm_signature(body["signature"], VALID_SCM_ENC_KEY_B64)
    assert recovered["timestamp"] == body["timestamp"]


@pytest.mark.parametrize(
    "is_fedramp, expected_base",
    [
        pytest.param(False, "https://cortex-gateway.paloaltonetworks.com", id="commercial when not fedramp"),
        pytest.param(True, "https://cortex-gateway-federal.paloaltonetworks.com", id="federal when fedramp"),
    ],
)
def test_get_scm_token_url(mocker: MockerFixture, is_fedramp: bool, expected_base: str):
    """
    Given:
        - A tenant that is either commercial or FedRAMP (is_fedramp_tenant mocked).
    When:
        - Calling get_scm_token_url.
    Then:
        - The commercial base URL is used when not FedRAMP and the federal base URL when FedRAMP.
        - The resulting URL ends with SCM_TOKEN_PATH.
    """
    from CortexDataLake import SCM_TOKEN_PATH, get_scm_token_url

    mocker.patch("CortexDataLake.is_fedramp_tenant", return_value=is_fedramp)

    url = get_scm_token_url()

    assert url == f"{expected_base}{SCM_TOKEN_PATH}"
    assert url.endswith(SCM_TOKEN_PATH)


def test_scm_authorize_success(mocker: MockerFixture):
    """
    Given:
        - A commercial tenant and a mocked SCM POST returning access_token, expires_in and token_type.
    When:
        - Constructing a Client in SCM mode (which triggers _scm_authorize via _set_access_token).
    Then:
        - The client's access_token, api_url (DEFAULT_API_URL) and instance_id default are set correctly.
        - The POST is made to the resolved SCM URL with a body containing registration_id/timestamp/signature.
    """
    from CortexDataLake import (
        AUTH_MODE_SCM,
        DEFAULT_API_URL,
        EXPIRES_IN,
        REFRESH_TOKEN_CONST,
        SCM_TOKEN_PATH,
        SECONDS_30,
        demisto,
        get_scm_token_url,
    )

    mocker.patch("CortexDataLake.is_fedramp_tenant", return_value=False)
    # Freeze time so the persisted EXPIRES_IN (now + expires_in - SECONDS_30) is deterministic.
    frozen_now = 1_000_000
    mocker.patch("CortexDataLake.time.time", return_value=frozen_now)
    # _scm_authorize calls _http_request(..., resp_type="response") and then reads the raw response
    # object's .text/.json()/.status_code/.headers/.url/.history attributes. Return a response-like
    # MagicMock exposing exactly those attributes rather than a plain dict.
    success_body = {"access_token": "scm-access-token", "expires_in": 3599, "token_type": "Bearer"}
    success_text = json.dumps(success_body)
    scm_response = MagicMock()
    scm_response.status_code = 200
    scm_response.headers = {"Content-Type": "application/json", "Content-Length": str(len(success_text))}
    scm_response.text = success_text
    scm_response.url = get_scm_token_url()
    scm_response.history = []
    scm_response.json.return_value = success_body
    http_mock = mocker.patch(
        "CortexDataLake.Client._http_request",
        return_value=scm_response,
    )

    client = _build_scm_client(mocker, integration_context={})

    assert client.access_token == "scm-access-token"
    assert client.api_url == DEFAULT_API_URL
    assert client.instance_id == ""
    assert client.auth_mode == AUTH_MODE_SCM

    assert http_mock.call_count == 1
    _, call_kwargs = http_mock.call_args
    assert call_kwargs["full_url"] == get_scm_token_url()
    assert call_kwargs["full_url"].endswith(SCM_TOKEN_PATH)
    posted_body = call_kwargs["json_data"]
    assert posted_body["registration_id"] == SCM_REGISTRATION_ID
    assert "timestamp" in posted_body
    assert "signature" in posted_body

    # The SCM POST must send a clean header set: no inherited OProxy Authorization or X-Content-* headers.
    sent_headers = call_kwargs["headers"]
    assert "Authorization" not in sent_headers
    assert not any(key.lower().startswith("x-content-") for key in sent_headers)
    assert sent_headers == {"Content-Type": "application/json", "Accept": "application/json"}

    # _scm_authorize returns refresh_token=None and expires_in=3599; verify via the persisted context:
    # EXPIRES_IN is stored as now + expires_in - SECONDS_30 and no refresh token is written when None.
    written_context = demisto.setIntegrationContext.call_args[0][0]
    assert written_context[EXPIRES_IN] == frozen_now + 3599 - SECONDS_30
    assert REFRESH_TOKEN_CONST not in written_context


def test_set_access_token_routes_to_scm_when_no_stored_token(mocker: MockerFixture):
    """
    Given:
        - An empty integration context and auth_mode=SCM.
    When:
        - Constructing a Client (which calls _set_access_token).
    Then:
        - _scm_authorize is used (not _oproxy_authorize) and the written context records AUTH_MODE_CONST=scm.
    """
    from CortexDataLake import AUTH_MODE_CONST, AUTH_MODE_SCM, Client, demisto

    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    set_context_mock = mocker.patch.object(demisto, "setIntegrationContext")
    scm_mock = mocker.patch.object(Client, "_scm_authorize", return_value=("tok", "https://api.example", "", None, 3600))
    oproxy_mock = mocker.patch.object(Client, "_oproxy_authorize")

    Client(
        token_retrieval_url="https://oproxy.demisto.ninja",  # guardrails-disable-line
        registration_id=SCM_REGISTRATION_ID,
        use_ssl=True,
        proxy=False,
        refresh_token=None,
        enc_key=VALID_SCM_ENC_KEY_B64,
        client_secret=SCM_CLIENT_SECRET,
        auth_mode=AUTH_MODE_SCM,
    )

    assert scm_mock.call_count == 1
    assert oproxy_mock.call_count == 0
    assert set_context_mock.call_count == 1
    written_context = set_context_mock.call_args[0][0]
    assert written_context[AUTH_MODE_CONST] == AUTH_MODE_SCM


def test_set_access_token_reauth_when_stored_auth_mode_differs(mocker: MockerFixture):
    """
    Given:
        - A stored, still-valid access token stamped with auth_mode=oproxy, but the client uses auth_mode=SCM.
    When:
        - Constructing a Client in SCM mode.
    Then:
        - The stored token is not reused (mode mismatch) and re-authentication via _scm_authorize occurs,
          verifying switch-to-new-auth invalidation.
    """
    from CortexDataLake import (
        ACCESS_TOKEN_CONST,
        AUTH_MODE_CONST,
        AUTH_MODE_OPROXY,
        AUTH_MODE_SCM,
        EXPIRES_IN,
        Client,
        demisto,
    )

    stale_but_valid_context = {
        ACCESS_TOKEN_CONST: "old-oproxy-token",
        EXPIRES_IN: int(datetime.utcnow().timestamp()) + 100_000,  # not yet expired
        AUTH_MODE_CONST: AUTH_MODE_OPROXY,
    }
    mocker.patch.object(demisto, "getIntegrationContext", return_value=stale_but_valid_context)
    mocker.patch.object(demisto, "setIntegrationContext")
    scm_mock = mocker.patch.object(
        Client, "_scm_authorize", return_value=("new-scm-token", "https://api.example", "", None, 3600)
    )
    oproxy_mock = mocker.patch.object(Client, "_oproxy_authorize")

    client = Client(
        token_retrieval_url="https://oproxy.demisto.ninja",  # guardrails-disable-line
        registration_id=SCM_REGISTRATION_ID,
        use_ssl=True,
        proxy=False,
        refresh_token=None,
        enc_key=VALID_SCM_ENC_KEY_B64,
        client_secret=SCM_CLIENT_SECRET,
        auth_mode=AUTH_MODE_SCM,
    )

    assert scm_mock.call_count == 1
    assert oproxy_mock.call_count == 0
    assert client.access_token == "new-scm-token"


def test_set_access_token_oproxy_regression(mocker: MockerFixture):
    """
    Given:
        - An empty integration context and the default auth_mode=oproxy.
    When:
        - Constructing a Client (which calls _set_access_token).
    Then:
        - The legacy path is unaffected: _oproxy_authorize is used (not _scm_authorize).
    """
    from CortexDataLake import AUTH_MODE_CONST, AUTH_MODE_OPROXY, Client, demisto

    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    set_context_mock = mocker.patch.object(demisto, "setIntegrationContext")
    oproxy_mock = mocker.patch.object(
        Client,
        "_oproxy_authorize",
        return_value=("oproxy-tok", "https://api.example.com", "instance-1", "refresh-tok", 3600),
    )
    scm_mock = mocker.patch.object(Client, "_scm_authorize")

    client = Client(
        token_retrieval_url="https://oproxy.demisto.ninja",  # guardrails-disable-line
        registration_id=SCM_REGISTRATION_ID,
        use_ssl=True,
        proxy=False,
        refresh_token=None,
        enc_key=VALID_SCM_ENC_KEY_B64,
        auth_mode=AUTH_MODE_OPROXY,
    )

    assert oproxy_mock.call_count == 1
    assert scm_mock.call_count == 0
    assert client.access_token == "oproxy-tok"
    written_context = set_context_mock.call_args[0][0]
    assert written_context[AUTH_MODE_CONST] == AUTH_MODE_OPROXY


def test_set_access_token_legacy_oproxy_token_reused(mocker: MockerFixture):
    """
    Given:
        - A pre-upgrade integration context holding a valid, unexpired access_token but NO AUTH_MODE_CONST key
          (the stamp did not exist before the upgrade), and the client is in OProxy mode (no client_secret).
    When:
        - Constructing a Client (which calls _set_access_token).
    Then:
        - The absent stamp defaults to OProxy, so the stored token is reused: neither _oproxy_authorize nor
          _scm_authorize is called (no manual OProxy token refresh is triggered) and the context is not rewritten.
    """
    from CortexDataLake import (
        ACCESS_TOKEN_CONST,
        API_URL_CONST,
        AUTH_MODE_OPROXY,
        EXPIRES_IN,
        INSTANCE_ID_CONST,
        Client,
        demisto,
    )

    legacy_context = {
        ACCESS_TOKEN_CONST: "legacy-oproxy-token",
        EXPIRES_IN: int(datetime.utcnow().timestamp()) + 100_000,  # not yet expired
        API_URL_CONST: "https://api.example.com",
        INSTANCE_ID_CONST: "instance-legacy",
        # NOTE: no AUTH_MODE_CONST key simulates a pre-upgrade context.
    }
    mocker.patch.object(demisto, "getIntegrationContext", return_value=legacy_context)
    set_context_mock = mocker.patch.object(demisto, "setIntegrationContext")
    oproxy_mock = mocker.patch.object(Client, "_oproxy_authorize")
    scm_mock = mocker.patch.object(Client, "_scm_authorize")

    client = Client(
        token_retrieval_url="https://oproxy.demisto.ninja",  # guardrails-disable-line
        registration_id=SCM_REGISTRATION_ID,
        use_ssl=True,
        proxy=False,
        refresh_token=None,
        enc_key=VALID_SCM_ENC_KEY_B64,
        auth_mode=AUTH_MODE_OPROXY,
    )

    assert oproxy_mock.call_count == 0
    assert scm_mock.call_count == 0
    assert set_context_mock.call_count == 0
    assert client.access_token == "legacy-oproxy-token"
