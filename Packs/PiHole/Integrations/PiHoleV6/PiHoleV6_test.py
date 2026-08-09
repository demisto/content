"""PiHole V6 Integration - Unit Tests

Pytest Unit Tests: all function names must start with "test_"

Uses demistomock and mocker for mocking API calls.
"""

import pytest
from CommonServerPython import DemistoException
from PiHoleV6 import (
    PiHoleV6Client,
    test_module,
    get_summary_command,
    get_top_domains_command,
    get_top_clients_command,
    get_upstreams_command,
    get_query_types_command,
    get_recent_blocked_command,
    get_history_command,
    get_history_clients_command,
    get_queries_command,
    get_blocking_status_command,
    set_blocking_command,
    get_domains_command,
    add_domain_command,
    delete_domain_command,
    get_version_command,
    get_system_info_command,
    get_ftl_info_command,
    get_host_info_command,
    get_sensors_command,
    run_gravity_command,
    restart_dns_command,
    flush_logs_command,
    flush_network_command,
    get_network_devices_command,
    get_network_gateway_command,
    search_domain_command,
    get_dhcp_leases_command,
    get_groups_command,
    add_group_command,
    delete_group_command,
    get_lists_command,
    add_list_command,
    delete_list_command,
)


BASE_URL = "https://pihole.example.com/api"

AUTH_RESPONSE = {"session": {"valid": True, "sid": "test-session-id"}}


@pytest.fixture
def client(mocker) -> PiHoleV6Client:
    """Fixture to create a PiHoleV6Client instance with mocked authentication."""
    c = PiHoleV6Client(base_url=BASE_URL, password="testpass", verify=False, proxy=False)
    mocker.patch.object(c, "authenticate")
    c.sid = "test-session-id"
    return c


def test_test_module(mocker):
    """
    Given:
        - A PiHoleV6 client with valid credentials.
    When:
        - Running the test-module command.
    Then:
        - Should return 'ok' after successful authentication and logout.
    """
    client = PiHoleV6Client(base_url=BASE_URL, password="testpass", verify=False, proxy=False)
    mocker.patch.object(client, "authenticate")
    mocker.patch.object(client, "logout")
    result = test_module(client)
    assert result == "ok"
    client.authenticate.assert_called_once()
    client.logout.assert_called_once()


def test_authenticate_success(mocker):
    """
    Given:
        - Valid PiHole credentials.
    When:
        - Authenticating with the API.
    Then:
        - Should set the session ID.
    """
    client = PiHoleV6Client(base_url=BASE_URL, password="testpass", verify=False, proxy=False)
    mocker.patch.object(client, "_http_request", return_value=AUTH_RESPONSE)
    client.authenticate()
    assert client.sid == "test-session-id"


def test_authenticate_failure(mocker):
    """
    Given:
        - Invalid PiHole credentials.
    When:
        - Authenticating with the API.
    Then:
        - Should raise a DemistoException.
    """
    client = PiHoleV6Client(base_url=BASE_URL, password="wrong", verify=False, proxy=False)
    mocker.patch.object(client, "_http_request", return_value={"session": {"valid": False, "message": "Invalid password"}})
    with pytest.raises(DemistoException, match="Authentication failed"):
        client.authenticate()


def test_get_summary_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-summary command.
    Then:
        - Should return summary data with queries and gravity info.
    """
    mock_data = {
        "queries": {"total": 1000, "blocked": 200, "cached": 300, "forwarded": 500},
        "clients": {"total": 10, "active": 5},
        "gravity": {"domains_being_blocked": 50000},
    }
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_summary_command(client)
    results.assert_called_once()
    cmd_results = results.call_args[0][0]
    assert cmd_results.outputs["queries"]["total"] == 1000
    assert "Summary" in cmd_results.readable_output


def test_get_top_domains_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with count and blocked arguments.
    When:
        - Running pihole-get-top-domains command.
    Then:
        - Should return top domains data.
    """
    mock_data = {"domains": [{"domain": "example.com", "count": 100}], "total_queries": 1000}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_top_domains_command(client, {"count": "5", "blocked": "false"})
    results.assert_called_once()
    client.api_request.assert_called_with("GET", "/stats/top_domains", params={"count": 5, "blocked": False})


def test_get_top_clients_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-top-clients command.
    Then:
        - Should return top clients data.
    """
    mock_data = {"clients": [{"name": "pc1", "ip": "192.168.1.10", "count": 50}], "total_queries": 500}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_top_clients_command(client, {"count": "10", "blocked": "true"})
    results.assert_called_once()
    client.api_request.assert_called_with("GET", "/stats/top_clients", params={"count": 10, "blocked": True})


def test_get_upstreams_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-upstreams command.
    Then:
        - Should return upstream DNS data.
    """
    mock_data = {"upstreams": [{"ip": "8.8.8.8", "count": 300}], "forwarded_queries": 300}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_upstreams_command(client)
    results.assert_called_once()


def test_get_query_types_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-query-types command.
    Then:
        - Should return query type breakdown.
    """
    mock_data = {"types": [{"name": "A", "count": 500}, {"name": "AAAA", "count": 200}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_query_types_command(client)
    results.assert_called_once()


def test_get_recent_blocked_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with count argument.
    When:
        - Running pihole-get-recent-blocked command.
    Then:
        - Should return recently blocked domains.
    """
    mock_data = {"blocked": [{"domain": "ads.example.com"}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_recent_blocked_command(client, {"count": "5"})
    results.assert_called_once()
    client.api_request.assert_called_with("GET", "/stats/recent_blocked", params={"count": 5})


def test_get_history_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-history command.
    Then:
        - Should return history data.
    """
    mock_data = {"history": [{"timestamp": 1000, "total": 100, "blocked": 10}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_history_command(client)
    results.assert_called_once()


def test_get_history_clients_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with N argument.
    When:
        - Running pihole-get-history-clients command.
    Then:
        - Should return per-client history data.
    """
    mock_data = {"clients": [{"name": "pc1"}], "history": []}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_history_clients_command(client, {"N": "5"})
    results.assert_called_once()
    client.api_request.assert_called_with("GET", "/history/clients", params={"N": 5})


def test_get_queries_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with filter arguments.
    When:
        - Running pihole-get-queries command.
    Then:
        - Should return filtered query log.
    """
    mock_data = {"queries": [{"domain": "example.com", "type": "A"}], "recordsTotal": 1}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_queries_command(client, {"length": "10", "domain": "example.com"})
    results.assert_called_once()
    client.api_request.assert_called_with("GET", "/queries", params={"length": 10, "domain": "example.com"})


def test_get_blocking_status_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-blocking-status command.
    Then:
        - Should return current blocking status.
    """
    mock_data = {"blocking": "enabled", "timer": None}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_blocking_status_command(client)
    results.assert_called_once()
    cmd_results = results.call_args[0][0]
    assert cmd_results.outputs["blocking"] == "enabled"
    assert "Blocking Status" in cmd_results.readable_output


def test_set_blocking_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with blocking and timer arguments.
    When:
        - Running pihole-set-blocking command.
    Then:
        - Should set blocking status and return result.
    """
    mock_data = {"blocking": "enabled", "timer": 60}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    set_blocking_command(client, {"blocking": "true", "timer": "60"})
    results.assert_called_once()
    client.api_request.assert_called_with("POST", "/dns/blocking", json_data={"blocking": True, "timer": 60})


def test_set_blocking_permanent(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with blocking but no timer.
    When:
        - Running pihole-set-blocking without a timer.
    Then:
        - Should set blocking permanently (timer=None).
    """
    mock_data = {"blocking": "disabled", "timer": None}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    mocker.patch("PiHoleV6.return_results")
    set_blocking_command(client, {"blocking": "false"})
    client.api_request.assert_called_with("POST", "/dns/blocking", json_data={"blocking": False, "timer": None})


def test_get_domains_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with type and kind filters.
    When:
        - Running pihole-get-domains command.
    Then:
        - Should return filtered domain list.
    """
    mock_data = {"domains": [{"domain": "ads.com", "type": "deny", "kind": "exact"}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_domains_command(client, {"type": "deny", "kind": "exact"})
    results.assert_called_once()
    client.api_request.assert_called_with("GET", "/domains/deny/exact")


def test_get_domains_no_filter(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with no filters.
    When:
        - Running pihole-get-domains command without type/kind.
    Then:
        - Should return all domains.
    """
    mock_data = {"domains": []}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    mocker.patch("PiHoleV6.return_results")
    get_domains_command(client, {})
    client.api_request.assert_called_with("GET", "/domains")


def test_add_domain_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with domain details.
    When:
        - Running pihole-add-domain command.
    Then:
        - Should add the domain and return result.
    """
    mock_data = {"domains": [{"domain": "ads.com", "comment": "block ads"}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    add_domain_command(client, {"type": "deny", "kind": "exact", "domain": "ads.com", "comment": "block ads"})
    results.assert_called_once()
    client.api_request.assert_called_with("POST", "/domains/deny/exact", json_data={"domain": "ads.com", "comment": "block ads"})


def test_delete_domain_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with a domain to delete.
    When:
        - Running pihole-delete-domain command.
    Then:
        - Should delete the domain and return confirmation.
    """
    mocker.patch.object(client, "api_request")
    results = mocker.patch("PiHoleV6.return_results")
    delete_domain_command(client, {"type": "deny", "kind": "exact", "domain": "ads.com"})
    results.assert_called_once()
    cmd_results = results.call_args[0][0]
    assert "ads.com" in cmd_results.readable_output
    assert "deleted" in cmd_results.readable_output


def test_get_version_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-version command.
    Then:
        - Should return version info for all components.
    """
    mock_data = {
        "core": {"local": {"version": "v6.0"}},
        "web": {"local": {"version": "v6.0"}},
        "ftl": {"local": {"version": "v6.0"}},
    }
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_version_command(client)
    results.assert_called_once()
    cmd_results = results.call_args[0][0]
    assert "Version" in cmd_results.readable_output


def test_get_system_info_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-system-info command.
    Then:
        - Should return system information.
    """
    mock_data = {"cpu": {"percent": 5.0}, "memory": {"percent": 30.0}}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_system_info_command(client)
    results.assert_called_once()


def test_get_ftl_info_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-ftl-info command.
    Then:
        - Should return FTL engine information.
    """
    mock_data = {"version": "v6.0", "database": {"queries": 50000}}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_ftl_info_command(client)
    results.assert_called_once()


def test_get_host_info_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-host-info command.
    Then:
        - Should return host information.
    """
    mock_data = {"hostname": "pihole", "uname": "Linux"}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_host_info_command(client)
    results.assert_called_once()


def test_get_sensors_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-sensors command.
    Then:
        - Should return sensor readings.
    """
    mock_data = {"cpu_temp": 45.5}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_sensors_command(client)
    results.assert_called_once()


def test_run_gravity_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-run-gravity command.
    Then:
        - Should trigger gravity update and return output.
    """
    mocker.patch.object(client, "api_request", return_value="Gravity update completed")
    results = mocker.patch("PiHoleV6.return_results")
    run_gravity_command(client)
    results.assert_called_once()
    cmd_results = results.call_args[0][0]
    assert "Gravity" in cmd_results.readable_output


def test_restart_dns_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-restart-dns command.
    Then:
        - Should restart DNS and return result.
    """
    mock_data = {"status": "restarted"}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    restart_dns_command(client)
    results.assert_called_once()


def test_flush_logs_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-flush-logs command.
    Then:
        - Should flush logs and return result.
    """
    mock_data = {"status": "flushed"}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    flush_logs_command(client)
    results.assert_called_once()


def test_flush_network_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-flush-network command.
    Then:
        - Should flush network table and return result.
    """
    mock_data = {"status": "flushed"}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    flush_network_command(client)
    results.assert_called_once()


def test_get_network_devices_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-network-devices command.
    Then:
        - Should return network devices.
    """
    mock_data = {"devices": [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_network_devices_command(client)
    results.assert_called_once()


def test_get_network_gateway_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-network-gateway command.
    Then:
        - Should return gateway information.
    """
    mock_data = {"ip": "192.168.1.1"}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_network_gateway_command(client)
    results.assert_called_once()


def test_search_domain_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with a domain to search.
    When:
        - Running pihole-search-domain command.
    Then:
        - Should return search results for the domain.
    """
    mock_data = {"results": [{"domain": "example.com", "list": "gravity"}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    search_domain_command(client, {"domain": "example.com"})
    results.assert_called_once()
    client.api_request.assert_called_with("GET", "/search/example.com")


def test_get_dhcp_leases_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-dhcp-leases command.
    Then:
        - Should return DHCP lease information.
    """
    mock_data = {"leases": [{"ip": "192.168.1.100", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "device1"}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_dhcp_leases_command(client)
    results.assert_called_once()


def test_get_groups_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-groups command.
    Then:
        - Should return all groups.
    """
    mock_data = {"groups": [{"name": "default", "enabled": True}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_groups_command(client)
    results.assert_called_once()


def test_add_group_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with group details.
    When:
        - Running pihole-add-group command.
    Then:
        - Should create the group and return result.
    """
    mock_data = {"groups": [{"name": "test-group", "comment": "test"}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    add_group_command(client, {"name": "test-group", "comment": "test"})
    results.assert_called_once()
    client.api_request.assert_called_with("POST", "/groups", json_data={"name": "test-group", "comment": "test"})


def test_delete_group_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with a group to delete.
    When:
        - Running pihole-delete-group command.
    Then:
        - Should delete the group and return confirmation.
    """
    mocker.patch.object(client, "api_request")
    results = mocker.patch("PiHoleV6.return_results")
    delete_group_command(client, {"name": "test-group"})
    results.assert_called_once()
    cmd_results = results.call_args[0][0]
    assert "test-group" in cmd_results.readable_output
    assert "deleted" in cmd_results.readable_output


def test_get_lists_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client.
    When:
        - Running pihole-get-lists command.
    Then:
        - Should return all adlists.
    """
    mock_data = {"lists": [{"address": "https://adlist.example.com", "enabled": True}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    get_lists_command(client)
    results.assert_called_once()


def test_add_list_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with adlist details.
    When:
        - Running pihole-add-list command.
    Then:
        - Should add the adlist and return result.
    """
    mock_data = {"lists": [{"address": "https://adlist.example.com", "enabled": True}]}
    mocker.patch.object(client, "api_request", return_value=mock_data)
    results = mocker.patch("PiHoleV6.return_results")
    add_list_command(client, {"address": "https://adlist.example.com", "comment": "ads", "enabled": "true"})
    results.assert_called_once()
    client.api_request.assert_called_with(
        "POST", "/lists", json_data={"address": "https://adlist.example.com", "comment": "ads", "enabled": True}
    )


def test_delete_list_command(client, mocker):
    """
    Given:
        - A connected PiHoleV6 client with an adlist to delete.
    When:
        - Running pihole-delete-list command.
    Then:
        - Should delete the adlist and return confirmation.
    """
    mocker.patch.object(client, "api_request")
    results = mocker.patch("PiHoleV6.return_results")
    delete_list_command(client, {"address": "https://adlist.example.com"})
    results.assert_called_once()
    cmd_results = results.call_args[0][0]
    assert "adlist.example.com" in cmd_results.readable_output
    assert "deleted" in cmd_results.readable_output
