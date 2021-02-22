import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Any, Tuple

""" CONSTANT VARIABLES """


CONTEXT_PREFIX = "TAXII2"
COMPLEX_OBSERVATION_MODE_SKIP = "Skip indicators with more than a single observation"
COMPLEX_OBSERVATION_MODE_CREATE_ALL = "Create indicator for each observation"

""" HELPER FUNCTIONS """


def try_parse_integer(
    int_to_parse: Any, err_msg: str = "Please provide a valid limit (positive integer)"
) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    if not int_to_parse:
        return int_to_parse
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


""" COMMAND FUNCTIONS """


def module_test_command(client, limit, fetch_full_feed):
    if client.collections:
        if fetch_full_feed:
            if limit and limit != -1:
                return_error(
                    "Configuration Error - Max Indicators Per Fetch is disabled when Full Feed Fetch is enabled"
                )
        demisto.results("ok")
    else:
        return_error("Could not connect to server")


def fetch_indicators_command(
    client,
    initial_interval,
    limit,
    last_run_ctx,
    fetch_full_feed: bool = False,
) -> Tuple[list, dict]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param initial_interval: initial interval in parse_date_range format
    :param limit: upper limit of indicators to fetch
    :param last_run_ctx: last run dict with {collection_id: last_run_time string}
    :param fetch_full_feed: when set to true, will ignore last run, and try to fetch the entire feed
    :return: indicators in cortex TIM format
    """
    if initial_interval:
        initial_interval, _ = parse_date_range(
            initial_interval, date_format=TAXII_TIME_FORMAT
        )

    last_fetch_time = (
        last_run_ctx.get(client.collection_to_fetch.id)
        if client.collection_to_fetch
        else None
    )

    # add filter for indicator types by default
    filter_args = {"type": "indicator"}

    if client.collection_to_fetch is None:
        # fetch all collections
        if client.collections is None:
            raise DemistoException(ERR_NO_COLL)
        indicators: list = []
        for collection in client.collections:
            client.collection_to_fetch = collection
            filter_args["added_after"] = get_added_after(
                fetch_full_feed, initial_interval, last_run_ctx.get(collection.id)
            )
            fetched_iocs = client.build_iterator(limit, **filter_args)
            indicators.extend(fetched_iocs)
            if limit >= 0:
                limit -= len(fetched_iocs)
                if limit <= 0:
                    break
            last_run_ctx[collection.id] = client.last_fetched_indicator__modified
    else:
        # fetch from a single collection
        filter_args["added_after"] = get_added_after(fetch_full_feed, initial_interval, last_fetch_time)
        indicators = client.build_iterator(limit, **filter_args)
        last_run_ctx[client.collection_to_fetch.id] = (
            client.last_fetched_indicator__modified
            if client.last_fetched_indicator__modified
            else filter_args.get("added_after")
        )
    return indicators, last_run_ctx


def get_added_after(
    fetch_full_feed, initial_interval, last_fetch_time=None
):
    """
    Creates the added_after param, or extracts it from the filter_args
    :param fetch_full_feed: when set to true, will limit added_after
    :param initial_interval: initial_interval if no
    :param last_fetch_time: last_fetch time value (str)
    :return: added_after
    """
    if fetch_full_feed:
        return initial_interval

    return last_fetch_time or initial_interval


def get_indicators_command(
    client, raw="false", limit=10, added_after=None
):
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param raw: When set to "true" will return only rawJSON
    :param limit: upper limit of indicators to fetch
    :param (Optional) added_after: added after time string in parse_date_range format
    :return: indicators in cortex TIM format
    """

    # add filter for indicator types by default
    filter_args = {"type": "indicator"}

    limit = try_parse_integer(limit)
    if added_after:
        added_after, _ = parse_date_range(added_after, date_format=TAXII_TIME_FORMAT)
        filter_args["added_after"] = added_after
    raw = argToBoolean(raw)

    if client.collection_to_fetch is None:
        # fetch all collections
        if client.collections is None:
            raise DemistoException(ERR_NO_COLL)
        indicators: list = []
        for collection in client.collections:
            client.collection_to_fetch = collection
            fetched_iocs = client.build_iterator(limit, **filter_args)
            indicators.extend(fetched_iocs)
            if limit >= 0:
                limit -= len(fetched_iocs)
                if limit <= 0:
                    break

    else:
        indicators = client.build_iterator(limit=limit, **filter_args)

    if raw:
        demisto.results({"indicators": [x.get("rawJSON") for x in indicators]})
        return

    md = f"Found {len(indicators)} results:\n" + tableToMarkdown(
        "", indicators, ["value", "type"]
    )
    if indicators:
        return CommandResults(
            outputs_prefix=CONTEXT_PREFIX + ".Indicators",
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


def reset_fetch_command(client):
    """
    Reset the last fetch from the integration context
    """
    demisto.setIntegrationContext({})
    return (
        "Fetch was reset successfully. Your next indicator fetch will collect indicators from "
        'the configured "First Fetch Time"'
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
    skip_complex_mode = COMPLEX_OBSERVATION_MODE_SKIP == params.get(
        "observation_operator_mode"
    )
    feed_tags = argToList(params.get("feedTags"))
    tlp_color = params.get('tlp_color', '')

    initial_interval = params.get("initial_interval")
    fetch_full_feed = params.get("fetch_full_feed") or False
    limit = try_parse_integer(params.get("limit") or -1)
    limit_per_request = try_parse_integer(params.get("limit_per_request"))

    command = demisto.command()
    demisto.info(f"Command being called in {CONTEXT_PREFIX} is {command}")
    try:
        client = Taxii2FeedClient(
            url=url,
            collection_to_fetch=collection_to_fetch,
            proxies=proxies,
            verify=verify_certificate,
            skip_complex_mode=skip_complex_mode,
            username=username,
            password=password,
            tags=feed_tags,
            limit_per_request=limit_per_request,
            tlp_color=tlp_color
        )
        client.initialise()
        commands = {
            "taxii2-reset-fetch-indicators": reset_fetch_command,
            "taxii2-get-indicators": get_indicators_command,
            "taxii2-get-collections": get_collections_command,
        }

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            module_test_command(client, limit, fetch_full_feed)

        elif demisto.command() == "fetch-indicators":
            if fetch_full_feed:
                limit = -1
            integration_ctx = demisto.getIntegrationContext() or {}
            (indicators, integration_ctx) = fetch_indicators_command(
                client,
                initial_interval,
                limit,
                integration_ctx,
                fetch_full_feed,
            )
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            demisto.setIntegrationContext(integration_ctx)
        else:
            return_results(commands[command](client, **args))  # type: ignore[operator]

    except Exception as e:
        err_msg = f"Failed to execute {command} command. Error: {str(e)}\n\ntraceback: {traceback.format_exc()}"
        if isinstance(e, requests.exceptions.SSLError):
            LOG(err_msg)
            err_msg = (
                "Encountered an HTTPS certificate error. This error can be ignored by enabling "
                '"Trust any certificate (not secure)" in the instance configuration.'
            )
        return_error(err_msg)


from TAXII2ApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
