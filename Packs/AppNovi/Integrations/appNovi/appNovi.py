import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
from typing import Any

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

API_PREFIX = "/api/v1"

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    Interaction with the appNovi API
    """

    def get_search_results(
        self, search_term: str, max_results: int = 25
    ) -> dict[str, Any]:
        """Gets the IP reputation using the '/ip' API endpoint

        :type search_term: ``str``
        :param search_term: Search for anything in appNovi

        :return: dict containing the results as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method="GET",
            url_suffix="/components/search",
            params={
                "string": search_term,
                "include_properties": True,
                "max_results": max_results,
            },
        )

    def get_connected_results(
        self,
        search_identity: str | dict,
        connect_type: Optional[list] = None,
        connect_category: Optional[list] = None,
        max_results: int = 25,
    ) -> list[dict[str, Any]]:
        # Can't use json= since it's already in use by xsoar
        return self._http_request(
            method="POST",
            url_suffix="/components/connected",
            data=json.dumps([search_identity]),
            params={
                "max_results": max_results,
                "type": connect_type,
                "category": connect_category,
            },
        )

    def get_types(self):
        return self._http_request(
            method="GET",
            url_suffix="/components/types",
        )

    def get_prop_search_results(
        self, prop: str, value: str, max_results: int = 25
    ) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="/components/propsearch",
            params={
                "prop": prop,
                "value": value,
                "include_properties": True,
                "max_results": max_results,
            },
        )


""" HELPER FUNCTIONS """


def dict_by_path(full_dict: dict, dict_path: str) -> Any:
    """Get values from dictionary by path

    just some code
    """
    paths = dict_path.split(".")
    return_value = full_dict
    for path in paths:
        try:
            return_value = return_value[path]
        except (KeyError, TypeError):
            return None
    return return_value


def process_sources(source_dict: dict) -> str:
    """Parse source dict into something readable"""
    source = source_dict.keys()
    return ",".join([s for s in source if len(s)])


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Test Integration

    :type client: ``Client``

    :return:
        A ``str`` representing if authentication was successful

    :rtype: ``str``
    """

    # Call the Client function and get the raw response
    try:
        client.get_types()
    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def search_appnovi_command(client: Client, args: dict[str, Any]) -> CommandResults:

    search_term = args.get("search_term", None)
    if not search_term:
        raise ValueError("Search term not specified")

    results = client.get_search_results(search_term, args.get("max_results", 25))

    table_layout = {
        "name": "name",
        "appnoviid": "u._id",
        "type": "u.identity.type",
        "value": "u.identity.value",
        "lastSeen": "u.lastSeen",
        "connections": "connections",
    }

    readable_output = (
        "### Search Results\n" + " | ".join(table_layout.keys()) + " | sources" + "\n"
    )
    readable_output += (
        "|".join(["-----" for th in table_layout]) + "|----" + "\n"
    )

    for result in results["components"]:
        readable_output += (
            " | ".join([str(dict_by_path(result, f)) for f in table_layout.values()])
            + " | "
            + process_sources(result["u"].get("source", {}))
            + "\n"
        )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="appnovi.search",
        outputs_key_field=table_layout["appnoviid"],
        outputs=results,
    )


def search_appnovi_prop_command(client: Client, args: dict[str, Any]) -> CommandResults:

    search_prop = args.get("property", None)
    search_value = args.get("value", None)

    if not search_prop or not search_value:
        raise ValueError("Search terms not specified")

    results = client.get_prop_search_results(
        search_prop, search_value, args.get("max_results", 25)
    )

    table_layout = {
        "name": "name",
        "appnoviid": "u._id",
        "type": "u.identity.type",
        "value": "u.identity.value",
        "lastSeen": "u.lastSeen",
        "connections": "connections",
    }

    readable_output = (
        "### Search Results\n" + " | ".join(table_layout.keys()) + " | sources" + "\n"
    )
    readable_output += (
        "|".join(["-----" for th in table_layout]) + "|----" + "\n"
    )

    for result in results["components"]:
        readable_output += (
            " | ".join([str(dict_by_path(result, f)) for f in table_layout.values()])
            + " | "
            + process_sources(result["u"].get("source", {}))
            + "\n"
        )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="appnovi.searchProp",
        outputs_key_field=table_layout["appnoviid"],
        outputs=results,
    )


def search_appnovi_connected_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Search for components connected to other components.
    Can be limited in the types of things returned"""

    identity = args.get("identity", None)
    if not identity:
        raise ValueError("Identity not specified")

    if appnovi_id := identity.get("_id", None):
        identity = appnovi_id

    # Check for arguments
    cats = argToList(args.get("category", "")) or None
    types = argToList(args.get("type", "")) or None

    # Process identity
    results = client.get_connected_results(identity, types, cats)

    table_layout = {
        "name": "name",
        "appnoviid": "_id",
        "category": "category",
        "type": "identity.type",
        "value": "identity.value",
    }

    readable_output = "### Search Results\n" + " | ".join(table_layout.keys()) + "\n"
    readable_output += "|".join(["-----" for th in table_layout]) + "\n"

    for result in results:
        readable_output += (
            " | ".join([str(dict_by_path(result, f)) for f in table_layout.values()])
            + "\n"
        )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="appnovi.connected",
        outputs_key_field=table_layout["appnoviid"],
        outputs=results,
    )


def search_appnovi_cve_servers_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Find Servers with CVE
    This is a convenience command using the connected search"""

    cve = args.get("cve", None)
    if not cve:
        raise ValueError("CVE not specified")

    results = client.get_connected_results(
        {"type": "cve", "value": cve.upper()}, None, ["Server"]
    )

    table_layout = {
        "name": "name",
        "appnoviid": "_id",
        "category": "category",
        "type": "identity.type",
        "value": "identity.value",
    }

    readable_output = "### Search Results\n" + " | ".join(table_layout.keys()) + "\n"
    readable_output += "|".join(["-----" for th in table_layout]) + "\n"

    for result in results:
        readable_output += (
            " | ".join([str(dict_by_path(result, f)) for f in table_layout.values()])
            + "\n"
        )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="appnovi.cveServers",
        outputs_key_field=table_layout["appnoviid"],
        outputs=results,
    )


def find_server_by_ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Use the connected function to return servers owning a given IP
    Good example of how you an chain requests to walk the graph via command or playbook
    """
    ip = args.get("ip", None)
    if not ip:
        raise ValueError("IP not specified")

    # Keep track of things
    servers = {}
    interfaces: list[str] = []

    # Let's get any servers or interfaces connected to the IP
    first_walk = client.get_connected_results(
        {"type": "ip", "value": ip}, None, ["Server", "Interface"]
    )

    # Examine first walk
    for thing in first_walk:
        category = thing.get("category", None)
        # Collect interfaces for next walk
        if category == "Interface":
            # Make mypy happy by checking thing.get("_id") for str type.
            _id = thing.get("_id")
            if isinstance(_id, str):
                interfaces.append(_id)

        # Servers are usually not directly connected to IP, but in case...
        if category == "Server":
            servers[thing.get("_id")] = thing

    # Walk each interface. Serching by _id is /very/ fast
    for interface in interfaces:
        possible_server = client.get_connected_results(interface, None, ["Server"])
        for server in possible_server:
            servers[server.get("_id")] = server

    # Walk finished, output some results
    readable_output = f"### Servers with IP {ip}\n"
    if len(servers.keys()):
        table_layout = {
            "name": "name",
            "appnoviid": "_id",
            "type": "identity.type",
            "value": "identity.value",
        }
        readable_output = (
            "### Search Results\n" + " | ".join(table_layout.keys()) + "\n"
        )
        readable_output += "|".join(["-----" for th in table_layout]) + "\n"

        for result in servers.values():
            readable_output += (
                " | ".join(
                    [str(dict_by_path(result, f)) for f in table_layout.values()]
                )
                + "\n"
            )

    else:
        readable_output += "No Results \n"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="appnovi.server",
        outputs_key_field="",
        outputs=[v for k, v in servers.items()],
    )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    command = demisto.command()

    api_key = params.get("appnovi_token")
    base_url = urljoin(params["appnovi_url"], API_PREFIX)

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        command = demisto.command()

        if command == "test-module":
            return_results(test_module(client))
            return

        commands = {
            "search-appnovi-components": search_appnovi_command,
            "search-appnovi-component-property": search_appnovi_prop_command,
            "search-appnovi-connected": search_appnovi_connected_command,
            "search-appnovi-cve": search_appnovi_cve_servers_command,
            "search-appnovi-server-by-ip": find_server_by_ip_command,
        }

        fn = commands.get(command, None)
        if fn:
            return_results(fn(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
