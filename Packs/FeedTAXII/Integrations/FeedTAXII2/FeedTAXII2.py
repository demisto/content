import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any
from urllib.parse import urlparse

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


def assert_incremental_feed_params(fetch_full_feed, is_incremental_feed):
    if fetch_full_feed == is_incremental_feed:
        toggle_value = 'enabled' if fetch_full_feed else 'disabled'
        raise DemistoException(f"'Full Feed Fetch' cannot be {toggle_value} when 'Incremental Feed' is {toggle_value}.")


""" COMMAND FUNCTIONS """


def module_test_command(client, limit, fetch_full_feed):
    if client.collections:
        if fetch_full_feed and limit and limit != -1:
            return_error(
                "Configuration Error - Max Indicators Per Fetch is disabled when Full Feed Fetch is enabled"
            )
        demisto.results("ok")
    else:
        return_error("Could not connect to server")


def filter_previously_fetched_indicators(indicators: list, last_run: dict) -> list:
    """
    Filter the indicators returned from the taxii server, by taking out indicators that we're ingested in the previous fetch
    call and their modified date was not updated,
    """
    last_indicators = last_run.get("latest_indicators")  # indicators from prev fetch
    new_indicators: list = []
    skipped_indicators: list = []
    if not last_indicators:    # first fetch
        last_run["latest_indicators"] = [{obj.get('rawJSON', {}).get("id"): obj.get('rawJSON', {}).get("modified")}
                                         if obj.get("value") != "$$DummyIndicator$$" else obj
                                         for obj in indicators]
        demisto.debug("with first fetch, updated the latest_indicators")
        return indicators
    for indicator in indicators:
        indicator_id = indicator.get("rawJSON", {}).get("id")

        # check if the indicator is stored in latest_indicators
        saved_indicator = list(filter(lambda ind: indicator_id in ind, last_indicators))

        # if the indicator is stored in latest_indicators -> check if it was modified
        if saved_indicator:
            saved_modified_date = saved_indicator[0].get(indicator_id)
            new_modified_date = indicator.get('rawJSON', {}).get('modified')

            # if indicator stored in saved indicators but does not have modified field -> add to new_indicators
            if not saved_modified_date or not new_modified_date:
                demisto.debug(f"saved indicator's modified value: {saved_modified_date}, "
                              f"new indicator's modified value is: {new_modified_date}")
                new_indicators.append(indicator)
            # the indicator is stored in latest_indicators, but got modified -> add to new_indicators
            elif new_modified_date > saved_modified_date:
                new_indicators.append(indicator)
            else:
                skipped_indicators.append(indicator_id)

        # the indicator is not stored in latest_indicators -> add to new_indicators
        else:
            new_indicators.append(indicator)

    if skipped_indicators:
        demisto.info(f"{len(skipped_indicators)} indicators were already ingested in the previous fetch...skipping.")
        demisto.debug(f"Skipped indicators: {skipped_indicators}")

    demisto.debug(f"found {len(new_indicators)} new indicators from {len(indicators)} fetched indicators")

    # updated lastrun with the indicators fetched in the current round
    last_run["latest_indicators"] = [{obj.get('rawJSON', {}).get("id"): obj.get('rawJSON', {}).get("modified")}
                                     if obj.get("value") != "$$DummyIndicator$$" else obj
                                     for obj in indicators]

    return new_indicators


def fetch_indicators_command(
    client,
    initial_interval,
    limit,
    last_run_ctx,
    fetch_full_feed: bool = False,
) -> tuple[list, dict]:
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

    if not client.collection_to_fetch:
        # fetch all collections
        if client.collections is None:
            raise DemistoException(ERR_NO_COLL)
        indicators: list = []
        for collection in client.collections:
            client.collection_to_fetch = collection
            added_after = get_added_after(
                fetch_full_feed, initial_interval, last_run_ctx.get(collection.id)
            )
            fetched_iocs = client.build_iterator(limit, added_after=added_after)
            demisto.debug(f"fetched {len(fetched_iocs)} iocs from {collection} collection")
            indicators.extend(fetched_iocs)
            last_run_ctx[collection.id] = client.last_fetched_indicator__modified \
                if client.last_fetched_indicator__modified \
                else added_after
            if limit >= 0:
                limit -= len(fetched_iocs)
                if limit <= 0:
                    break
    else:
        # fetch from a single collection
        added_after = get_added_after(fetch_full_feed, initial_interval, last_fetch_time)
        indicators = client.build_iterator(limit, added_after=added_after)
        demisto.debug(f"fetched {len(indicators)} iocs")
        last_run_ctx[client.collection_to_fetch.id] = (
            client.last_fetched_indicator__modified
            if client.last_fetched_indicator__modified
            else added_after
        )

    indicators = filter_previously_fetched_indicators(indicators, last_run_ctx)
    demisto.debug(f'{indicators=}')
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

    limit = try_parse_integer(limit)
    if added_after:
        added_after, _ = parse_date_range(added_after, date_format=TAXII_TIME_FORMAT)
    raw = argToBoolean(raw)

    if not client.collection_to_fetch:
        # fetch all collections
        if client.collections is None:
            raise DemistoException(ERR_NO_COLL)
        indicators: list = []
        for collection in client.collections:
            client.collection_to_fetch = collection
            fetched_iocs = client.build_iterator(limit, added_after=added_after)
            indicators.extend(fetched_iocs)
            if limit >= 0:
                limit -= len(fetched_iocs)
                if limit <= 0:
                    break

    else:
        indicators = client.build_iterator(limit=limit, added_after=added_after)
    relationships_list: list = []
    parsed_relationships: str = ""
    if indicators and indicators[-1].get('value', ) == "$$DummyIndicator$$":
        relationships_list = indicators[-1].get('relationships', )
        parsed_relationships = f"\n\n\nRelations ships:\n{tableToMarkdown('', relationships_list)}"
        md = f"Found {len(indicators) - 1} results:\n" \
             f"{tableToMarkdown('', indicators[:-1], ['value', 'type'])}{parsed_relationships}"
    else:
        md = f"Found {len(indicators)} results:\n{tableToMarkdown('', indicators, ['value', 'type'])}{parsed_relationships}"

    if raw:
        demisto.results({"indicators": [x.get("rawJSON") for x in indicators]})
        return None

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
    collections = []
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


def is_valid_taxii_url(url: Optional[str]):
    """
    Checks the correctness of the url.
    :param url: str
    :return: boolean whether the url valid or not.
    """
    if url and (parse_result := urlparse(url)):
        path = parse_result.path
        if path.endswith(("taxii", "taxii2", "taxii2/", "taxii/")):
            return True
    return False


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    url = params.get("url")
    if not is_valid_taxii_url(url):
        demisto.debug("ERROR: Discovery Service URL is NOT VALID, The URL suffix should be taxii or taxii2.")
    collection_to_fetch = params.get("collection_to_fetch")
    credentials = params.get("credentials") or {}
    username = credentials.get("identifier")
    password = credentials.get("password")
    proxies = handle_proxy()
    verify_certificate = not params.get("insecure", False)
    skip_complex_mode = params.get(
        "observation_operator_mode"
    ) == COMPLEX_OBSERVATION_MODE_SKIP
    feed_tags = argToList(params.get("feedTags"))
    tlp_color = params.get('tlp_color', '')

    initial_interval = params.get("initial_interval")
    fetch_full_feed = params.get("fetch_full_feed") or False
    is_incremental_feed = params.get('feedIncremental') or False
    limit = try_parse_integer(params.get("limit") or -1)
    limit_per_request = try_parse_integer(params.get("limit_per_request"))
    certificate = (replace_spaces_in_credential(params.get('creds_certificate', {}).get('identifier'))
                   or params.get('certificate', None))
    key = params.get('creds_certificate', {}).get('password') or params.get('key', None)
    objects_to_fetch = argToList(params.get('objects_to_fetch') or [])
    default_api_root = params.get('default_api_root')
    update_custom_fields = params.get('update_custom_fields') or False
    enrichment_excluded = (argToBoolean(params.get('enrichmentExcluded', False))
                           or (params.get('tlp_color') == 'RED' and is_xsiam_or_xsoar_saas()))

    demisto.info(f'{objects_to_fetch=}')

    command = demisto.command()
    demisto.info(f"Command being called in {CONTEXT_PREFIX} is {command}")
    try:
        assert_incremental_feed_params(fetch_full_feed, is_incremental_feed)
        client = Taxii2FeedClient(
            url=url,
            collection_to_fetch=collection_to_fetch,
            proxies=proxies,
            verify=verify_certificate,
            objects_to_fetch=objects_to_fetch,
            skip_complex_mode=skip_complex_mode,
            username=username,
            password=password,
            tags=feed_tags,
            limit_per_request=limit_per_request,
            tlp_color=tlp_color,
            certificate=certificate,
            key=key,
            default_api_root=default_api_root,
            update_custom_fields=update_custom_fields,
            enrichment_excluded=enrichment_excluded,
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

            last_run_indicators = get_feed_last_run()
            demisto.debug(f'Before fetch command last run: {last_run_indicators}')
            (indicators, last_run_indicators) = fetch_indicators_command(
                client,
                initial_interval,
                limit,
                last_run_indicators,
                fetch_full_feed,
            )
            demisto.debug(f'After fetch command last run: {last_run_indicators}')
            demisto.debug(f"returning {len(indicators)} indicators")
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            set_feed_last_run(last_run_indicators)
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
