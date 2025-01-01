from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from octoxlabs import OctoxLabs

import urllib3
from typing import Any
from collections.abc import Callable

# from Packs.Base.Scripts.CommonServerPython.CommonServerPython import CommandResults

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """
""" HELPER FUNCTIONS """


def convert_to_json(obj: object, keys: list[str]) -> dict[str, Any]:
    return {k: getattr(obj, k, None) for k in keys}


def run_command(
    octox: OctoxLabs, command_name: str, args: dict[str, Any]
) -> CommandResults:
    commands: dict[str, Callable] = {
        "test-module": test_module,
        "octoxlabs-get-adapters": get_adapters,
        "octoxlabs-get-connections": get_connections,
        "octoxlabs-get-discoveries": get_discoveries,
        "octoxlabs-get-last-discovery": get_last_discovery,
        "octoxlabs-search-devices": search_devices,
        "octoxlabs-search-users-inventory": search_users_inventory,
        "octoxlabs-search-applications": search_applications,
        "octoxlabs-search-avm": search_avm,
        "octoxlabs-get-device": get_device,
        "octoxlabs-get-user-inventory-detail": get_user_inventory_detail,
        "octoxlabs-get-application-detail": get_application_detail,
        "octoxlabs-get-queries": get_queries,
        "octoxlabs-get-query-by-id": get_query_by_id,
        "octoxlabs-get-query-by-name": get_query_by_name,
        "octoxlabs-get-companies": get_companies,
        "octoxlabs-get-company-by-id": get_company_by_id,
        "octoxlabs-get-company-by-name": get_company_by_name,
        "octoxlabs-get-domains": get_domains,
        "octoxlabs-get-domain-by-id": get_domain_by_id,
        "octoxlabs-get-domain-by-domain-name": get_domain_by_domain_name,
        "octoxlabs-get-users": get_users,
        "octoxlabs-get-user-by-id": get_user_by_id,
        "octoxlabs-get-user-by-username": get_user_by_username,
        "octoxlabs-get-groups": get_groups,
        "octoxlabs-get-permissions": get_permissions,
        "octoxlabs-search-scroll-devices": search_scroll_devices,
        "octoxlabs-search-scroll-users": search_scroll_users,
        "octoxlabs-search-scroll-applications": search_scroll_applications,
        "octoxlabs-search-scroll-avm": search_scroll_avm,
    }
    command_function: Callable | None = commands.get(command_name, None)
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


def get_connections(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
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


def get_discoveries(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
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


def search_devices(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
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


def get_device(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    device = octox.get_device_detail(
        hostname=args.get("hostname"), discovery_id=args.get("discovery_id", None)
    )
    return CommandResults(outputs_prefix="OctoxLabs.Device", outputs=device)


def get_queries(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
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


def get_query_by_id(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
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


def get_query_by_name(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
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


def get_companies(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    count, companies = octox.get_companies(
        page=args.get("page", 1),
        search=args.get("search", ""),
        size=args.get("size", 20),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.Companies",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    c,
                    keys=[
                        "id",
                        "name",
                        "domain",
                        "is_active",
                    ],
                )
                for c in companies
            ],
        },
    )


def get_company_by_id(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    company = octox.get_company_by_id(company_id=args.get("company_id"))

    return CommandResults(
        outputs_prefix="OctoxLabs.Company",
        outputs=convert_to_json(
            obj=company,
            keys=[
                "id",
                "name",
                "domain",
                "is_active",
            ],
        ),
    )


def get_company_by_name(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    company = octox.get_company_by_name(company_name=args.get("company_name"))

    return CommandResults(
        outputs_prefix="OctoxLabs.Company",
        outputs=convert_to_json(
            obj=company,
            keys=[
                "id",
                "name",
                "domain",
                "is_active",
            ],
        ),
    )


def get_domains(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    count, domains = octox.get_domains(
        page=args.get("page", 1),
        search=args.get("search", ""),
        size=args.get("size", 20),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.Domains",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    d,
                    keys=[
                        "id",
                        "domain",
                        "tenant_name",
                        "tenant",
                    ],
                )
                for d in domains
            ],
        },
    )


def get_domain_by_id(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    domain = octox.get_domain_by_id(domain_id=args.get("domain_id"))

    return CommandResults(
        outputs_prefix="OctoxLabs.Domain",
        outputs=convert_to_json(
            obj=domain,
            keys=[
                "id",
                "domain",
                "tenant_name",
                "tenant",
            ],
        ),
    )


def get_domain_by_domain_name(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    domain = octox.get_domains_by_domain_name(domain_name=args.get("domain_name"))

    return CommandResults(
        outputs_prefix="OctoxLabs.Domain",
        outputs=convert_to_json(
            obj=domain,
            keys=[
                "id",
                "domain",
                "tenant_name",
                "tenant",
                "is_primary",
            ],
        ),
    )


def get_users(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    count, users = octox.get_users(
        page=args.get("page", 1),
        search=args.get("search", ""),
        size=args.get("size", 20),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.Users",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    u,
                    keys=[
                        "id",
                        "name",
                        "email",
                        "username",
                        "first_name",
                        "last_name",
                        "is_active",
                        "is_ldap",
                        "groups",
                    ],
                )
                for u in users
            ],
        },
    )


def get_user_by_id(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    user = octox.get_user_by_id(user_id=args.get("user_id"))
    return CommandResults(
        outputs_prefix="OctoxLabs.User",
        outputs=convert_to_json(
            obj=user,
            keys=[
                "id",
                "name",
                "email",
                "username",
                "first_name",
                "last_name",
                "is_active",
                "is_ldap",
                "groups",
            ],
        ),
    )


def get_user_by_username(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    user = octox.get_user_by_username(username=args.get("username"))
    return CommandResults(
        outputs_prefix="OctoxLabs.User",
        outputs=convert_to_json(
            obj=user,
            keys=[
                "id",
                "name",
                "email",
                "username",
                "first_name",
                "last_name",
                "is_active",
                "is_ldap",
                "groups",
            ],
        ),
    )


def get_groups(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    count, groups = octox.get_groups(
        page=args.get("page", 1),
        search=args.get("search", ""),
        size=args.get("size", 20),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.Groups",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    g,
                    keys=["id", "name", "users_count"],
                )
                for g in groups
            ],
        },
    )


def get_permissions(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    count, permissions = octox.get_permissions(
        page=args.get("page", 1),
        search=args.get("search", ""),
        size=args.get("size", 20),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.Permissions",
        outputs={
            "count": count,
            "results": [
                convert_to_json(
                    p,
                    keys=["id", "name", "app"],
                )
                for p in permissions
            ],
        },
    )


def search_users_inventory(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    fields = args.get("fields", None)
    if isinstance(fields, str):
        fields = [f.strip() for f in fields.split(",")]

    count, users = octox.search_users(
        query=args.get("query", ""),
        fields=fields,
        page=args.get("page", 1),
        size=args.get("size", 50),
        discovery_id=args.get("discovery_id", None),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.UsersInventory",
        outputs={
            "count": count,
            "results": users,
        },
    )


def search_applications(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    fields = args.get("fields", None)
    if isinstance(fields, str):
        fields = [f.strip() for f in fields.split(",")]

    count, applications = octox.search_applications(
        query=args.get("query", ""),
        fields=fields,
        page=args.get("page", 1),
        size=args.get("size", 50),
        discovery_id=args.get("discovery_id", None),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.Applications",
        outputs={
            "count": count,
            "results": applications,
        },
    )


def search_avm(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    count, avm = octox.search_avm(
        query=args.get("query", ""),
        page=args.get("page", 1),
        size=args.get("size", 50),
        discovery_id=args.get("discovery_id", None),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.AVM",
        outputs={
            "count": count,
            "results": avm,
        },
    )


def get_user_inventory_detail(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    user = octox.get_user_inventory_detail(
        username=args.get("username"), discovery_id=args.get("discovery_id", None)
    )
    return CommandResults(outputs_prefix="OctoxLabs.UserInv", outputs=user)


def get_application_detail(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    application = octox.get_application_detail(
        application_id=args.get("application_id"),
        discovery_id=args.get("discovery_id", None),
    )
    return CommandResults(outputs_prefix="OctoxLabs.Application", outputs=application)


def search_scroll_devices(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    fields = args.get("fields", None)
    if isinstance(fields, str):
        fields = [f.strip() for f in fields.split(",")]

    count, scroll_id, devices = octox.search_scroll_devices(
        query=args.get("query", ""),
        fields=fields,
        scroll_id=args.get("scroll_id", None),
        size=args.get("size", 50),
        discovery_id=args.get("discovery_id", None),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.ScrolledDevices",
        outputs={
            "count": count,
            "scroll_id": scroll_id,
            "results": devices,
        },
    )


def search_scroll_users(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    fields = args.get("fields", None)
    if isinstance(fields, str):
        fields = [f.strip() for f in fields.split(",")]

    count, scroll_id, users = octox.search_scroll_users(
        query=args.get("query", ""),
        fields=fields,
        scroll_id=args.get("scroll_id", None),
        size=args.get("size", 50),
        discovery_id=args.get("discovery_id", None),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.ScrolledUsers",
        outputs={
            "count": count,
            "scroll_id": scroll_id,
            "results": users,
        },
    )


def search_scroll_applications(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    fields = args.get("fields", None)
    if isinstance(fields, str):
        fields = [f.strip() for f in fields.split(",")]

    count, scroll_id, applications = octox.search_scroll_applications(
        query=args.get("query", ""),
        fields=fields,
        scroll_id=args.get("scroll_id", None),
        size=args.get("size", 50),
        discovery_id=args.get("discovery_id", None),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.ScrolledApplications",
        outputs={
            "count": count,
            "scroll_id": scroll_id,
            "results": applications,
        },
    )


def search_scroll_avm(octox: OctoxLabs, args: dict[str, Any]) -> CommandResults:
    count, scroll_id, avm = octox.search_scroll_avm(
        query=args.get("query", ""),
        scroll_id=args.get("scroll_id", None),
        size=args.get("size", 50),
        discovery_id=args.get("discovery_id", None),
    )

    return CommandResults(
        outputs_prefix="OctoxLabs.ScrolledAVM",
        outputs={
            "count": count,
            "scroll_id": scroll_id,
            "results": avm,
        },
    )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    ip = demisto.params().get("octox_ip")
    token = demisto.params().get("octox_token", {"password": ""}).get("password")
    https_proxy = demisto.params().get("https_proxy", None)
    no_verify = demisto.params().get("no_verify", True)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        octox = OctoxLabs(ip=ip, token=token, https_proxy=https_proxy, no_verify=no_verify)
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
