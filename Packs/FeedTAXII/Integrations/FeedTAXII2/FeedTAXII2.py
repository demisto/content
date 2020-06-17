import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Any

""" CONSTANT VARIABLES """


CONTEXT_PREFIX = "TAXII2"
INTEGRATION_CONTEXT_TIME_KEY = "last_run"


""" HELPER FUNCTIONS """


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


""" COMMAND FUNCTIONS """


def test_module(client):
    if client.collections:
        demisto.results("ok")
    else:
        return_error("Could not connect to server")


def fetch_indicators_command(client):
    # TODO: Add back fetch from
    iterator = client.build_iterator()
    indicators = []
    for item in iterator:
        indicator = item.get("indicator")
        if indicator:
            item["value"] = indicator
            indicators.append(
                {"value": indicator, "type": item.get("type"), "rawJSON": item,}
            )
    return indicators


def get_indicators_command(client, raw="false", limit=10, added_after=None):
    limit = try_parse_integer(limit, "Please provide a valid limit (positive integer)")
    if added_after:
        added_after, _ = parse_date_range(added_after, date_format=TAXII_TIME_FORMAT)
    raw = raw == "true"

    indicators = client.build_iterator(limit=limit, added_after=added_after)

    if raw:
        demisto.results({"indicators": [x.get("rawJSON") for x in indicators]})
        return

    md = f"Found {len(indicators)} results:\n" + tableToMarkdown(
        "", indicators, ["value", "type"]
    )
    if indicators:
        return CommandResults(
            outputs_prefix=CONTEXT_PREFIX,
            outputs_key_field="value",
            outputs=indicators,
            readable_output=md,
        )
    return md


def get_collections_command(client):
    """
    Get the available collections in the TAXII server
    :param client: FeedClient
    :return: available collections
    """
    collections = list()
    for collection in client.collections:
        collections.append({"Name": collection.title, "ID": collection.id})
    md = tableToMarkdown("TAXII2 Server Collections:", collections, ["Name", "ID"])
    return CommandResults(
        outputs_prefix=CONTEXT_PREFIX + ".Collections",
        outputs_key_field="ID",
        outputs=collections,
        readable_output=md,
    )


def main():
    params = demisto.params()
    args = demisto.args()
    url = params.get("url")
    collection_to_fetch = params.get("collection_to_fetch")
    credentials = params.get("credentials") or {}
    username = credentials.get("identifier")
    password = credentials.get("password")
    proxies = handle_proxy()
    verify_certificate = not params.get("insecure", False)

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client = Taxii2FeedClient(
            url, collection_to_fetch, proxies, verify_certificate, username, password
        )
        client.initialise()
        commands = {
            "taxii2-get-indicators": get_indicators_command,
            "taxii2-get-collections": get_collections_command,
        }

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            test_module(client)

        elif demisto.command() == "fetch-indicators":
            indicators = fetch_indicators_command(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            return_results(commands[command](client, **args))

    # Log exceptions
    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error: {str(e)}\n\ntraceback: {traceback.format_exc()}"
        )

# from Packs.ApiModules.Scripts.TAXII2ApiModule.TAXII2ApiModule import *  # noqa: E402
from TAXII2ApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
