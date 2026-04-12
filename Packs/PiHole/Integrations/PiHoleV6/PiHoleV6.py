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
        self.sid = None

    def authenticate(self):
        """Authenticate with PiHole v6 and obtain a session ID."""
        result = self._http_request("POST", "/auth", json_data={"password": self.password})
        session = result.get("session", {})
        if session.get("valid"):
            self.sid = session.get("sid")
        else:
            raise DemistoException(f"Authentication failed: {session.get('message', 'Unknown error')}")

    def logout(self):
        """Delete the current session."""
        if self.sid:
            try:
                self._http_request("DELETE", "/auth", headers={"sid": self.sid}, resp_type="response")
            except Exception:
                pass

    def api_request(self, method: str, url_suffix: str, params: dict = None,
                    json_data: dict = None, resp_type: str = "json"):
        """Make an authenticated API request."""
        if not self.sid:
            self.authenticate()
        headers = {"sid": self.sid}
        return self._http_request(
            method, url_suffix, headers=headers, params=params,
            json_data=json_data, resp_type=resp_type
        )


def results_return(command: str, data):
    results = CommandResults(
        outputs_prefix=f"PiHoleV6.{command}",
        outputs_key_field="",
        outputs=data
    )
    return_results(results)


def test_module(client: PiHoleV6Client):
    """Test connectivity and authentication."""
    client.authenticate()
    client.logout()
    return "ok"


# --- Stats Commands ---

def get_summary_command(client: PiHoleV6Client):
    results_return("Summary", client.api_request("GET", "/stats/summary"))


def get_top_domains_command(client: PiHoleV6Client, args: dict):
    params = {}
    if args.get("count"):
        params["count"] = int(args["count"])
    if args.get("blocked"):
        params["blocked"] = argToBoolean(args["blocked"])
    results_return("TopDomains", client.api_request("GET", "/stats/top_domains", params=params))


def get_top_clients_command(client: PiHoleV6Client, args: dict):
    params = {}
    if args.get("count"):
        params["count"] = int(args["count"])
    if args.get("blocked"):
        params["blocked"] = argToBoolean(args["blocked"])
    results_return("TopClients", client.api_request("GET", "/stats/top_clients", params=params))


def get_upstreams_command(client: PiHoleV6Client):
    results_return("Upstreams", client.api_request("GET", "/stats/upstreams"))


def get_query_types_command(client: PiHoleV6Client):
    results_return("QueryTypes", client.api_request("GET", "/stats/query_types"))


def get_recent_blocked_command(client: PiHoleV6Client, args: dict):
    params = {}
    if args.get("count"):
        params["count"] = int(args["count"])
    results_return("RecentBlocked", client.api_request("GET", "/stats/recent_blocked", params=params))


# --- History Commands ---

def get_history_command(client: PiHoleV6Client):
    results_return("History", client.api_request("GET", "/history"))


def get_history_clients_command(client: PiHoleV6Client, args: dict):
    params = {}
    if args.get("N"):
        params["N"] = int(args["N"])
    results_return("HistoryClients", client.api_request("GET", "/history/clients", params=params))


# --- Queries Commands ---

def get_queries_command(client: PiHoleV6Client, args: dict):
    params = {}
    for key in ["length", "domain", "client_ip", "client_name", "upstream", "type", "status"]:
        if args.get(key):
            params[key] = args[key]
    if args.get("length"):
        params["length"] = int(args["length"])
    results_return("Queries", client.api_request("GET", "/queries", params=params))


# --- DNS Blocking Commands ---

def get_blocking_status_command(client: PiHoleV6Client):
    results_return("Blocking", client.api_request("GET", "/dns/blocking"))


def set_blocking_command(client: PiHoleV6Client, args: dict):
    blocking = argToBoolean(args.get("blocking", "true"))
    json_data: dict = {"blocking": blocking}
    timer = args.get("timer")
    if timer:
        json_data["timer"] = int(timer)
    else:
        json_data["timer"] = None
    results_return("Blocking", client.api_request("POST", "/dns/blocking", json_data=json_data))


# --- Domain Management Commands ---

def get_domains_command(client: PiHoleV6Client, args: dict):
    domain_type = args.get("type", "")
    kind = args.get("kind", "")
    suffix = "/domains"
    if domain_type:
        suffix += f"/{domain_type}"
    if kind:
        suffix += f"/{kind}"
    results_return("Domains", client.api_request("GET", suffix))


def add_domain_command(client: PiHoleV6Client, args: dict):
    domain_type = args.get("type")
    kind = args.get("kind")
    domain = args.get("domain")
    comment = args.get("comment")
    json_data: dict = {"domain": domain}
    if comment:
        json_data["comment"] = comment
    results_return("Domains", client.api_request("POST", f"/domains/{domain_type}/{kind}", json_data=json_data))


def delete_domain_command(client: PiHoleV6Client, args: dict):
    domain_type = args.get("type")
    kind = args.get("kind")
    domain = args.get("domain")
    client.api_request("DELETE", f"/domains/{domain_type}/{kind}/{domain}", resp_type="response")
    return_results(CommandResults(readable_output=f"Domain '{domain}' deleted from {domain_type}/{kind}."))


# --- Info Commands ---

def get_version_command(client: PiHoleV6Client):
    results_return("Version", client.api_request("GET", "/info/version"))


def get_system_info_command(client: PiHoleV6Client):
    results_return("SystemInfo", client.api_request("GET", "/info/system"))


def get_ftl_info_command(client: PiHoleV6Client):
    results_return("FTLInfo", client.api_request("GET", "/info/ftl"))


def get_host_info_command(client: PiHoleV6Client):
    results_return("HostInfo", client.api_request("GET", "/info/host"))


def get_sensors_command(client: PiHoleV6Client):
    results_return("Sensors", client.api_request("GET", "/info/sensors"))


# --- Action Commands ---

def run_gravity_command(client: PiHoleV6Client):
    result = client.api_request("POST", "/action/gravity", resp_type="text")
    return_results(CommandResults(
        outputs_prefix="PiHoleV6.Gravity",
        outputs_key_field="",
        outputs={"output": result},
        readable_output=result
    ))


def restart_dns_command(client: PiHoleV6Client):
    results_return("RestartDNS", client.api_request("POST", "/action/restartdns"))


def flush_logs_command(client: PiHoleV6Client):
    results_return("FlushLogs", client.api_request("POST", "/action/flush/logs"))


def flush_network_command(client: PiHoleV6Client):
    results_return("FlushNetwork", client.api_request("POST", "/action/flush/network"))


# --- Network Commands ---

def get_network_devices_command(client: PiHoleV6Client):
    results_return("NetworkDevices", client.api_request("GET", "/network/devices"))


def get_network_gateway_command(client: PiHoleV6Client):
    results_return("Gateway", client.api_request("GET", "/network/gateway"))


# --- Search Command ---

def search_domain_command(client: PiHoleV6Client, args: dict):
    domain = args.get("domain")
    results_return("Search", client.api_request("GET", f"/search/{domain}"))


# --- DHCP Commands ---

def get_dhcp_leases_command(client: PiHoleV6Client):
    results_return("DHCPLeases", client.api_request("GET", "/dhcp/leases"))


# --- Groups Commands ---

def get_groups_command(client: PiHoleV6Client):
    results_return("Groups", client.api_request("GET", "/groups"))


def add_group_command(client: PiHoleV6Client, args: dict):
    json_data: dict = {"name": args.get("name")}
    if args.get("comment"):
        json_data["comment"] = args["comment"]
    results_return("Groups", client.api_request("POST", "/groups", json_data=json_data))


def delete_group_command(client: PiHoleV6Client, args: dict):
    name = args.get("name")
    client.api_request("DELETE", f"/groups/{name}", resp_type="response")
    return_results(CommandResults(readable_output=f"Group '{name}' deleted."))


# --- Lists (Adlists) Commands ---

def get_lists_command(client: PiHoleV6Client):
    results_return("Lists", client.api_request("GET", "/lists"))


def add_list_command(client: PiHoleV6Client, args: dict):
    json_data: dict = {"address": args.get("address")}
    if args.get("comment"):
        json_data["comment"] = args["comment"]
    if args.get("enabled") is not None:
        json_data["enabled"] = argToBoolean(args["enabled"])
    results_return("Lists", client.api_request("POST", "/lists", json_data=json_data))


def delete_list_command(client: PiHoleV6Client, args: dict):
    address = args.get("address")
    client.api_request("DELETE", f"/lists/{address}", resp_type="response")
    return_results(CommandResults(readable_output=f"List '{address}' deleted."))


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS"""
    password = demisto.params().get("password")
    base_url = urljoin(demisto.params()["url"], "/api")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    LOG(f"Command being called is {demisto.command()}")

    client = PiHoleV6Client(
        base_url=base_url,
        password=password,
        verify=verify_certificate,
        proxy=proxy
    )

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
