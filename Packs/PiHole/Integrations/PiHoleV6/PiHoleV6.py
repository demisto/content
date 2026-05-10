import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class PiHoleV6Client(BaseClient):
    """Client class to interact with the PiHole v6 API."""

    def __init__(self, base_url: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.password = password
        self.sid: str | None = None

    def authenticate(self) -> None:
        """Authenticate with PiHole v6 and obtain a session ID."""
        result = self._http_request("POST", "/auth", json_data={"password": self.password})
        session = result.get("session", {})
        if session.get("valid"):
            self.sid = session.get("sid")
        else:
            raise DemistoException(f"Authentication failed: {session.get('message', 'Unknown error')}")

    def logout(self) -> None:
        """Delete the current session."""
        if self.sid:
            try:
                self._http_request("DELETE", "/auth", headers={"sid": self.sid}, resp_type="response")
            except Exception:
                pass

    def api_request(
        self, method: str, url_suffix: str, params: dict | None = None, json_data: dict | None = None, resp_type: str = "json"
    ) -> Any:
        """Make an authenticated API request."""
        if not self.sid:
            self.authenticate()
        headers = {"sid": self.sid}
        return self._http_request(method, url_suffix, headers=headers, params=params, json_data=json_data, resp_type=resp_type)


def results_return(command: str, data: Any, title: str = "", headers: list[str] | None = None) -> None:
    if not title:
        title = f"PiHole V6 - {command}"

    table_data: Any = data
    if isinstance(data, dict):
        # Find the best key to use for the table
        for key in data:
            if isinstance(data[key], list):
                table_data = data[key]
                break

    readable = tableToMarkdown(title, table_data, headers=headers, removeNull=True)

    return_results(
        CommandResults(outputs_prefix=f"PiHoleV6.{command}", outputs_key_field="", outputs=data, readable_output=readable)
    )


def test_module(client: PiHoleV6Client) -> str:
    """Test connectivity and authentication."""
    client.authenticate()
    client.logout()
    return "ok"


# --- Stats Commands ---


def get_summary_command(client: PiHoleV6Client) -> None:
    data = client.api_request("GET", "/stats/summary")
    queries = data.get("queries", {})
    gravity = data.get("gravity", {})
    table = [
        {
            "Total Queries": queries.get("total"),
            "Blocked": queries.get("blocked"),
            "Cached": queries.get("cached"),
            "Forwarded": queries.get("forwarded"),
            "Gravity Domains": gravity.get("domains_being_blocked"),
        }
    ]
    readable = tableToMarkdown("PiHole V6 - Summary", table, removeNull=True)
    return_results(
        CommandResults(outputs_prefix="PiHoleV6.Summary", outputs_key_field="", outputs=data, readable_output=readable)
    )


def get_top_domains_command(client: PiHoleV6Client, args: dict) -> None:
    params: dict = {}
    if args.get("count"):
        params["count"] = int(args["count"])
    if args.get("blocked"):
        params["blocked"] = argToBoolean(args["blocked"])
    results_return("TopDomains", client.api_request("GET", "/stats/top_domains", params=params), title="PiHole V6 - Top Domains")


def get_top_clients_command(client: PiHoleV6Client, args: dict) -> None:
    params: dict = {}
    if args.get("count"):
        params["count"] = int(args["count"])
    if args.get("blocked"):
        params["blocked"] = argToBoolean(args["blocked"])
    results_return("TopClients", client.api_request("GET", "/stats/top_clients", params=params), title="PiHole V6 - Top Clients")


def get_upstreams_command(client: PiHoleV6Client) -> None:
    results_return("Upstreams", client.api_request("GET", "/stats/upstreams"), title="PiHole V6 - Upstreams")


def get_query_types_command(client: PiHoleV6Client) -> None:
    results_return("QueryTypes", client.api_request("GET", "/stats/query_types"), title="PiHole V6 - Query Types")


def get_recent_blocked_command(client: PiHoleV6Client, args: dict) -> None:
    params: dict = {}
    if args.get("count"):
        params["count"] = int(args["count"])
    results_return(
        "RecentBlocked", client.api_request("GET", "/stats/recent_blocked", params=params), title="PiHole V6 - Recently Blocked"
    )


# --- History Commands ---


def get_history_command(client: PiHoleV6Client) -> None:
    results_return("History", client.api_request("GET", "/history"), title="PiHole V6 - History")


def get_history_clients_command(client: PiHoleV6Client, args: dict) -> None:
    params: dict = {}
    if args.get("N"):
        params["N"] = int(args["N"])
    results_return(
        "HistoryClients", client.api_request("GET", "/history/clients", params=params), title="PiHole V6 - History Clients"
    )


# --- Queries Commands ---


def get_queries_command(client: PiHoleV6Client, args: dict) -> None:
    params: dict = {}
    for key in ["length", "domain", "client_ip", "client_name", "upstream", "type", "status"]:
        if args.get(key):
            params[key] = args[key]
    if args.get("length"):
        params["length"] = int(args["length"])
    results_return("Queries", client.api_request("GET", "/queries", params=params), title="PiHole V6 - Queries")


# --- DNS Blocking Commands ---


def get_blocking_status_command(client: PiHoleV6Client) -> None:
    data = client.api_request("GET", "/dns/blocking")
    table = [{"Blocking": data.get("blocking"), "Timer": data.get("timer")}]
    readable = tableToMarkdown("PiHole V6 - Blocking Status", table, removeNull=True)
    return_results(
        CommandResults(outputs_prefix="PiHoleV6.Blocking", outputs_key_field="", outputs=data, readable_output=readable)
    )


def set_blocking_command(client: PiHoleV6Client, args: dict) -> None:
    blocking = argToBoolean(args.get("blocking", "true"))
    json_data: dict = {"blocking": blocking}
    timer = args.get("timer")
    if timer:
        json_data["timer"] = int(timer)
    else:
        json_data["timer"] = None
    data = client.api_request("POST", "/dns/blocking", json_data=json_data)
    table = [{"Blocking": data.get("blocking"), "Timer": data.get("timer")}]
    readable = tableToMarkdown("PiHole V6 - Set Blocking", table, removeNull=True)
    return_results(
        CommandResults(outputs_prefix="PiHoleV6.Blocking", outputs_key_field="", outputs=data, readable_output=readable)
    )


# --- Domain Management Commands ---


def get_domains_command(client: PiHoleV6Client, args: dict) -> None:
    domain_type = args.get("type", "")
    kind = args.get("kind", "")
    suffix = "/domains"
    if domain_type:
        suffix += f"/{domain_type}"
    if kind:
        suffix += f"/{kind}"
    results_return("Domains", client.api_request("GET", suffix), title="PiHole V6 - Domains")


def add_domain_command(client: PiHoleV6Client, args: dict) -> None:
    domain_type = args.get("type")
    kind = args.get("kind")
    domain = args.get("domain")
    comment = args.get("comment")
    json_data: dict = {"domain": domain}
    if comment:
        json_data["comment"] = comment
    results_return(
        "Domains",
        client.api_request("POST", f"/domains/{domain_type}/{kind}", json_data=json_data),
        title=f"PiHole V6 - Domain Added ({domain_type}/{kind})",
    )


def delete_domain_command(client: PiHoleV6Client, args: dict) -> None:
    domain_type = args.get("type")
    kind = args.get("kind")
    domain = args.get("domain")
    client.api_request("DELETE", f"/domains/{domain_type}/{kind}/{domain}", resp_type="response")
    return_results(CommandResults(readable_output=f"### Domain '{domain}' deleted from {domain_type}/{kind}."))


# --- Info Commands ---


def get_version_command(client: PiHoleV6Client) -> None:
    data = client.api_request("GET", "/info/version")
    table = [
        {
            "Core": data.get("core", {}).get("local", {}).get("version"),
            "Web": data.get("web", {}).get("local", {}).get("version"),
            "FTL": data.get("ftl", {}).get("local", {}).get("version"),
        }
    ]
    readable = tableToMarkdown("PiHole V6 - Version", table, removeNull=True)
    return_results(
        CommandResults(outputs_prefix="PiHoleV6.Version", outputs_key_field="", outputs=data, readable_output=readable)
    )


def get_system_info_command(client: PiHoleV6Client) -> None:
    results_return("SystemInfo", client.api_request("GET", "/info/system"), title="PiHole V6 - System Info")


def get_ftl_info_command(client: PiHoleV6Client) -> None:
    results_return("FTLInfo", client.api_request("GET", "/info/ftl"), title="PiHole V6 - FTL Info")


def get_host_info_command(client: PiHoleV6Client) -> None:
    results_return("HostInfo", client.api_request("GET", "/info/host"), title="PiHole V6 - Host Info")


def get_sensors_command(client: PiHoleV6Client) -> None:
    results_return("Sensors", client.api_request("GET", "/info/sensors"), title="PiHole V6 - Sensors")


# --- Action Commands ---


def run_gravity_command(client: PiHoleV6Client) -> None:
    result = client.api_request("POST", "/action/gravity", resp_type="text")
    return_results(
        CommandResults(
            outputs_prefix="PiHoleV6.Gravity",
            outputs_key_field="",
            outputs={"output": result},
            readable_output=f"### PiHole V6 - Gravity Update\n{result}",
        )
    )


def restart_dns_command(client: PiHoleV6Client) -> None:
    results_return("RestartDNS", client.api_request("POST", "/action/restartdns"), title="PiHole V6 - Restart DNS")


def flush_logs_command(client: PiHoleV6Client) -> None:
    results_return("FlushLogs", client.api_request("POST", "/action/flush/logs"), title="PiHole V6 - Flush Logs")


def flush_network_command(client: PiHoleV6Client) -> None:
    results_return("FlushNetwork", client.api_request("POST", "/action/flush/network"), title="PiHole V6 - Flush Network")


# --- Network Commands ---


def get_network_devices_command(client: PiHoleV6Client) -> None:
    results_return("NetworkDevices", client.api_request("GET", "/network/devices"), title="PiHole V6 - Network Devices")


def get_network_gateway_command(client: PiHoleV6Client) -> None:
    results_return("Gateway", client.api_request("GET", "/network/gateway"), title="PiHole V6 - Gateway")


# --- Search Command ---


def search_domain_command(client: PiHoleV6Client, args: dict) -> None:
    domain = args.get("domain")
    results_return("Search", client.api_request("GET", f"/search/{domain}"), title=f"PiHole V6 - Search: {domain}")


# --- DHCP Commands ---


def get_dhcp_leases_command(client: PiHoleV6Client) -> None:
    results_return("DHCPLeases", client.api_request("GET", "/dhcp/leases"), title="PiHole V6 - DHCP Leases")


# --- Groups Commands ---


def get_groups_command(client: PiHoleV6Client) -> None:
    results_return("Groups", client.api_request("GET", "/groups"), title="PiHole V6 - Groups")


def add_group_command(client: PiHoleV6Client, args: dict) -> None:
    json_data: dict = {"name": args.get("name")}
    if args.get("comment"):
        json_data["comment"] = args["comment"]
    results_return("Groups", client.api_request("POST", "/groups", json_data=json_data), title="PiHole V6 - Group Added")


def delete_group_command(client: PiHoleV6Client, args: dict) -> None:
    name = args.get("name")
    client.api_request("DELETE", f"/groups/{name}", resp_type="response")
    return_results(CommandResults(readable_output=f"### Group '{name}' deleted."))


# --- Lists (Adlists) Commands ---


def get_lists_command(client: PiHoleV6Client) -> None:
    results_return("Lists", client.api_request("GET", "/lists"), title="PiHole V6 - Adlists")


def add_list_command(client: PiHoleV6Client, args: dict) -> None:
    json_data: dict = {"address": args.get("address")}
    if args.get("comment"):
        json_data["comment"] = args["comment"]
    if args.get("enabled") is not None:
        json_data["enabled"] = argToBoolean(args["enabled"])
    results_return("Lists", client.api_request("POST", "/lists", json_data=json_data), title="PiHole V6 - List Added")


def delete_list_command(client: PiHoleV6Client, args: dict) -> None:
    address = args.get("address")
    client.api_request("DELETE", f"/lists/{address}", resp_type="response")
    return_results(CommandResults(readable_output=f"### List '{address}' deleted."))


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS"""
    password = demisto.params().get("password")
    base_url = urljoin(demisto.params()["url"], "/api")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    LOG(f"Command being called is {demisto.command()}")

    client = PiHoleV6Client(base_url=base_url, password=password, verify=verify_certificate, proxy=proxy)

    try:
        command = demisto.command()
        args = demisto.args()

        if command == "test-module":
            result = test_module(client)
            demisto.results(result)

        # Stats
        elif command == "pihole-get-summary":
            get_summary_command(client)
        elif command == "pihole-get-top-domains":
            get_top_domains_command(client, args)
        elif command == "pihole-get-top-clients":
            get_top_clients_command(client, args)
        elif command == "pihole-get-upstreams":
            get_upstreams_command(client)
        elif command == "pihole-get-query-types":
            get_query_types_command(client)
        elif command == "pihole-get-recent-blocked":
            get_recent_blocked_command(client, args)

        # History
        elif command == "pihole-get-history":
            get_history_command(client)
        elif command == "pihole-get-history-clients":
            get_history_clients_command(client, args)

        # Queries
        elif command == "pihole-get-queries":
            get_queries_command(client, args)

        # DNS Blocking
        elif command == "pihole-get-blocking-status":
            get_blocking_status_command(client)
        elif command == "pihole-set-blocking":
            set_blocking_command(client, args)

        # Domain Management
        elif command == "pihole-get-domains":
            get_domains_command(client, args)
        elif command == "pihole-add-domain":
            add_domain_command(client, args)
        elif command == "pihole-delete-domain":
            delete_domain_command(client, args)

        # Info
        elif command == "pihole-get-version":
            get_version_command(client)
        elif command == "pihole-get-system-info":
            get_system_info_command(client)
        elif command == "pihole-get-ftl-info":
            get_ftl_info_command(client)
        elif command == "pihole-get-host-info":
            get_host_info_command(client)
        elif command == "pihole-get-sensors":
            get_sensors_command(client)

        # Actions
        elif command == "pihole-run-gravity":
            run_gravity_command(client)
        elif command == "pihole-restart-dns":
            restart_dns_command(client)
        elif command == "pihole-flush-logs":
            flush_logs_command(client)
        elif command == "pihole-flush-network":
            flush_network_command(client)

        # Network
        elif command == "pihole-get-network-devices":
            get_network_devices_command(client)
        elif command == "pihole-get-network-gateway":
            get_network_gateway_command(client)

        # Search
        elif command == "pihole-search-domain":
            search_domain_command(client, args)

        # DHCP
        elif command == "pihole-get-dhcp-leases":
            get_dhcp_leases_command(client)

        # Groups
        elif command == "pihole-get-groups":
            get_groups_command(client)
        elif command == "pihole-add-group":
            add_group_command(client, args)
        elif command == "pihole-delete-group":
            delete_group_command(client, args)

        # Lists (Adlists)
        elif command == "pihole-get-lists":
            get_lists_command(client)
        elif command == "pihole-add-list":
            add_list_command(client, args)
        elif command == "pihole-delete-list":
            delete_list_command(client, args)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e!s}")
    finally:
        client.logout()


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
