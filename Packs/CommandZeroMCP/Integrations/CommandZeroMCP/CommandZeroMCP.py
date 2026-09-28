import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio


REGION_URLS = {
    "North America": "https://mcp.cmdzero.io/",
    "European Union": "https://mcp.eu.cmdzero.io/",
}
COMMAND_ZERO_AUTH_TYPE = AuthMethods.BEARER.value
ORG_ID_HEADER = "X-Org-ID"
SERVER_NAME = "Command Zero MCP"


def get_base_url(params: dict[str, Any]) -> str:
    """Returns the custom server URL when set, otherwise the URL of the selected region."""
    custom_url = (params.get("server_url") or "").strip()
    if custom_url:
        return custom_url

    region = params.get("region") or "North America"
    if region not in REGION_URLS:
        raise DemistoException(f"Unsupported region '{region}'. Supported regions: {', '.join(REGION_URLS)}.")
    return REGION_URLS[region]


def get_headers(params: dict[str, Any]) -> dict[str, str]:
    """Returns the custom headers, adding the organization ID header when an organization ID is set."""
    headers = parse_custom_headers(params.get("custom_headers") or "")
    org_id = (params.get("org_id") or "").strip()
    if org_id:
        headers[ORG_ID_HEADER] = org_id
    return headers


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client = None
    try:
        api_key = params.get("api_key", {}).get("password") or ""
        if not api_key:
            raise DemistoException("An API key is required. Enter your Command Zero API key in the instance configuration.")

        client = Client(
            base_url=get_base_url(params),
            auth_type=COMMAND_ZERO_AUTH_TYPE,
            token=api_key,
            custom_headers=get_headers(params),
            verify=not argToBoolean(params.get("insecure") or False),
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            result = await client.test_connection()
            return_results(result)

        elif command == "list-tools":
            result = await client.list_tools(SERVER_NAME)
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args["name"], args.get("arguments", ""))
            return_results(result)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except BaseException as eg:
        root_msg = extract_root_error_message(eg)
        return_error(f"Failed to execute {command} command.\nError:\n{root_msg}")

    finally:
        if client:
            demisto.debug(f"Closing client connection for {command}")
            await client.close()


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
