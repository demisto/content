from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from octoxlabs import OctoxLabs

import urllib3
from typing import Any, Dict, List, Callable, Optional

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """
""" HELPER FUNCTIONS """


def convert_to_json(obj: object, keys: List[str]) -> Dict[str, Any]:
    return {k: getattr(obj, k, None) for k in keys}


def run_command(
    octox: OctoxLabs, command_name: str, args: Dict[str, Any]
) -> CommandResults:
    commands: Dict[str, Callable] = {
        "test-module": test_module,
        "octoxlabs-get-adapters": get_adapters,
        "octoxlabs-get-connections": get_connections,
        "octoxlabs-get-discoveries": get_discoveries,
        "octoxlabs-get-last-discovery": get_last_discovery,
        "octoxlabs-search-devices": search_devices,
        "octoxlabs-get-device": get_device,
        "octoxlabs-get-queries": get_queries,
        "octoxlabs-get-query-by-id": get_query_by_id,
        "octoxlabs-get-query-by-name": get_query_by_name,
    }
    command_function: Optional[Callable] = commands.get(command_name, None)
    if command_function:
        return command_function(octox=octox, args=args)
    raise Exception("No command.")


""" COMMAND FUNCTIONS """


def test_module(octox: OctoxLabs, *_, **__) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type octox: ``octoxlabs.OctoxLabs``
    :param octoxlabs.OctoxLabs: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    octox.ping()
    return "ok"


def get_adapters(octox: OctoxLabs, *_, **__) -> CommandResults:
    count, adapters = octox.get_adapters()

    return CommandResults(
        outputs_prefix="OctoxLabs.Adapters",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    obj=a,
                    keys=[
                        "id",
                        "name",
                        "slug",
                        "description",
                        "groups",
                        "beta",
                        "status",
                        "hr_status",
                    ],
                )
                for a in adapters
            ],
        },
    )


def get_connections(octox: OctoxLabs, args: Dict[str, Any]) -> CommandResults:
    page = args.get("page", 1)
    count, connections = octox.get_connections(page=page)

    return CommandResults(
        outputs_prefix="OctoxLabs.Connections",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    obj=c,
                    keys=[
                        "id",
                        "adapter_id",
                        "adapter_name",
                        "name",
                        "status",
                        "description",
                        "enabled",
                    ],
                )
                for c in connections
            ],
        },
    )


def get_discoveries(octox: OctoxLabs, args: Dict[str, Any]) -> CommandResults:
    page = args.get("page", 1)
    count, discoveries = octox.get_discoveries(page=page)

    return CommandResults(
        outputs_prefix="OctoxLabs.Discoveries",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    d,
                    keys=[
                        "id",
                        "start_time",
                        "end_time",
                        "status",
                        "hr_status",
                        "progress",
                    ],
                )
                for d in discoveries
            ],
        },
    )


def get_last_discovery(octox: OctoxLabs, *_, **__) -> CommandResults:
    discovery = octox.get_last_discovery()
    return CommandResults(
        outputs_prefix="OctoxLabs.Discovery",
        outputs=convert_to_json(
            obj=discovery,
            keys=["id", "start_time", "end_time", "status", "hr_status", "progress"],
        ),
    )


def search_devices(octox: OctoxLabs, args: Dict[str, Any]) -> CommandResults:
    fields = args.get("fields", None)
    if isinstance(fields, str):
        fields = [f.strip() for f in fields.split(",")]

    count, devices = octox.search_devices(
        query=args.get("query", ""),
        fields=fields,
        page=args.get("page", 1),
        size=args.get("size", 50),
        discovery_id=args.get("discovery_id", None),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.Devices",
        outputs={
            "count": count,
            "results": devices,
        },
    )


def get_device(octox: OctoxLabs, args: Dict[str, Any]) -> CommandResults:
    device = octox.get_device_detail(
        hostname=args.get("hostname"), discovery_id=args.get("discovery_id", None)
    )
    return CommandResults(outputs_prefix="OctoxLabs.Device", outputs=device)


def get_queries(octox: OctoxLabs, args: Dict[str, Any]) -> CommandResults:
    count, queries = octox.get_queries(
        page=args.get("page", 1),
        search=args.get("search", ""),
        size=args.get("size", 20),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.Queries",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    q,
                    keys=[
                        "id",
                        "name",
                        "text",
                        "tags",
                        "count",
                        "is_public",
                        "created_at",
                        "updated_at",
                        "username",
                        "is_temporary",
                    ],
                )
                for q in queries
            ],
        },
    )


def get_query_by_id(octox: OctoxLabs, args: Dict[str, Any]) -> CommandResults:
    query = octox.get_query_by_id(query_id=args.get("query_id"))
    return CommandResults(
        outputs_prefix="OctoxLabs.Query",
        outputs=convert_to_json(
            obj=query,
            keys=[
                "id",
                "name",
                "text",
                "tags",
                "count",
                "is_public",
                "created_at",
                "updated_at",
                "username",
                "is_temporary",
            ],
        ),
    )


def get_query_by_name(octox: OctoxLabs, args: Dict[str, Any]) -> CommandResults:
    query = octox.get_query_by_name(query_name=args.get("query_name"))
    return CommandResults(
        outputs_prefix="OctoxLabs.Query",
        outputs=convert_to_json(
            obj=query,
            keys=[
                "id",
                "name",
                "text",
                "tags",
                "count",
                "is_public",
                "created_at",
                "updated_at",
                "username",
                "is_temporary",
            ],
        ),
    )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    ip = demisto.params().get("octox_ip")
    token = demisto.params().get("octox_token", {"password": ""}).get("password")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        octox = OctoxLabs(ip=ip, token=token)
        return_results(
            run_command(
                octox=octox, command_name=demisto.command(), args=demisto.args()
            )
        )

    # Log exceptions and return errors
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)} \nArgs:\n{demisto.args()}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
