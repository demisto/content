import demistomock as demisto
from CommonServerPython import *

import json
from typing import Any


def parse_json_value(value: Any) -> Any:
    """Parse values that may have been JSON encoded."""
    parsed_value = value

    for _ in range(2):
        if not isinstance(parsed_value, str):
            break

        try:
            parsed_value = json.loads(parsed_value)
        except (json.JSONDecodeError, TypeError):
            break

    return parsed_value


def find_connections(value: Any) -> list[dict[str, Any]]:
    """Recursively find connection objects containing a destination port."""
    value = parse_json_value(value)

    if isinstance(value, list):
        connections: list[dict[str, Any]] = []

        for item in value:
            connections.extend(find_connections(item))

        return connections

    if not isinstance(value, dict):
        return []

    if value.get("port") not in (None, ""):
        return [value]

    connections = []

    for nested_value in value.values():
        if isinstance(nested_value, (dict, list, str)):
            connections.extend(find_connections(nested_value))

    return connections


def format_destination_ports(value: Any) -> str:
    """Format connections as '<port> (<protocol>)'."""
    formatted_values = []

    for connection in find_connections(value):
        port = connection.get("port")
        protocol = connection.get("ipProto")

        formatted_value = str(port)

        if protocol not in (None, ""):
            formatted_value = f"{formatted_value} ({str(protocol).lower()})"

        if formatted_value not in formatted_values:
            formatted_values.append(formatted_value)

    return ", ".join(formatted_values)


def main() -> None:
    value = demisto.args().get("value")
    return_results(format_destination_ports(value))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
