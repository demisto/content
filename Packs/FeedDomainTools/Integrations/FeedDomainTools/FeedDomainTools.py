import demistomock as demisto  # noqa: F401
import urllib3
import json

from CommonServerPython import *  # noqa: F401
from collections.abc import Callable, Iterator
from domaintools import API

# disable insecure warnings
urllib3.disable_warnings()

RISK_THRESHOLD = 70


class DomainToolsClient:
    """
    Client to use in the DomainTools Feed integration.
    """

    APP_PARTNER = "cortex_xsoar_feed"
    APP_NAME = "feed-plugin"
    APP_VERSION = "1.0.2"

    NOD_FEED = "nod"
    NAD_FEED = "nad"
    NOH_FEED = "noh"
    DOMAINRDAP = "domainrdap"
    DOMAINDISCOVERY = "domaindiscovery"
    DOMAINRISK = "domainrisk"
    DOMAINHOTLIST = "domainhotlist"
    IPHOTLIST = "iphotlist"
    IPRISK = "iprisk"

    FEED_METHOD_MAP = {
        "nod": "nod",
        "nad": "nad",
        "noh": "noh",
        "domainrdap": "domainrdap",
        "domaindiscovery": "domaindiscovery",
        "domainrisk": "realtime_domain_risk",
        "domainhotlist": "domainhotlist",
        "iphotlist": "iphotlist",
        "iprisk": "iprisk",
    }

    def __init__(
        self,
        api_username: str,
        api_key: str,
        verify_ssl: bool = True,
        proxy: bool = False,
        tags: str = "",
        tlp_color: str | None = None,
    ):
        if not (api_username and api_key):
            raise DemistoException("The 'API Username' and 'API Key' parameters are required.")

        self.tags = tags
        self.tlp_color = tlp_color

        proxy_url = None
        if proxy:
            proxies = handle_proxy()
            proxy_url = proxies.get("https") or proxies.get("http") or None

        self._api = API(
            api_username,
            api_key,
            app_partner=self.APP_PARTNER,
            app_name=self.APP_NAME,
            app_version=self.APP_VERSION,
            proxy_url=proxy_url,
            verify_ssl=verify_ssl,
            always_sign_api_key=False,
        )

    def _get_dt_feeds(
        self,
        feed_type: str,
        session_id: str | None = None,
        domain: str | None = None,
        after: str | None = None,
        before: str | None = None,
        top: int | None = None,
        pdns_resolutions_min: int | None = None,
        bad_pdns_resolutions_min: int | None = None,
        total_domains_max: int | None = None,
        third_party_threats_min: int | None = None,
        all_threats_combined_percent_min: int | None = None,
        combined_phishing_percent_min: int | None = None,
        combined_malware_percent_min: int | None = None,
        combined_spam_percent_min: int | None = None,
        asn: int | None = None,
        organization: str | None = None,
        country_code: str | None = None,
        percent_phishing_min: int | None = None,
        percent_malware_min: int | None = None,
        percent_spam_min: int | None = None,
        all_threats_percent_min: int | None = None,
    ) -> list[str]:
        feed_type = feed_type.lower()
        method_name = self.FEED_METHOD_MAP.get(feed_type)
        if not method_name:
            raise DemistoException(f"Unsupported feed type: '{feed_type}'. Valid types: {list(self.FEED_METHOD_MAP)}")
        api_method = getattr(self._api, method_name)

        base_params: dict[str, Any] = {
            "sessionID": session_id,
            "domain": domain,
            "after": after,
            "before": before,
            "top": top,
        }

        ip_feed_params: dict[str, Any] = {}
        if feed_type in (self.IPHOTLIST, self.IPRISK):
            ip_feed_params = {
                "pdns_resolutions_min": pdns_resolutions_min,
                "bad_pdns_resolutions_min": bad_pdns_resolutions_min,
                "total_domains_max": total_domains_max,
                "third_party_threats_min": third_party_threats_min,
                "all_threats_combined_percent_min": all_threats_combined_percent_min,
                "combined_phishing_percent_min": combined_phishing_percent_min,
                "combined_malware_percent_min": combined_malware_percent_min,
                "combined_spam_percent_min": combined_spam_percent_min,
                "asn": asn,
                "organization": organization,
                "country_code": country_code,
                "percent_phishing_min": percent_phishing_min,
                "percent_malware_min": percent_malware_min,
                "percent_spam_min": percent_spam_min,
            }
            if feed_type == self.IPRISK:
                ip_feed_params["all_threats_percent_min"] = all_threats_percent_min

        kwargs: dict[str, Any] = {k: v for k, v in {**base_params, **ip_feed_params}.items() if v is not None}

        demisto.info(f"Fetching DomainTools {feed_type.upper()} feed type with params: {kwargs}")

        return list(api_method(**kwargs).response())

    def _format_parameter(self, key: str, value: Any) -> Any:
        """Format the parameter value based on the given key

        Args:
            key (str): The parameter key.
            value (Any): The value of the parameter

        Returns:
            Any: The formatted value.
        """
        if key in ("after", "before") and "-" not in value:
            value = "-" + value

        return value

    def build_iterator(self, feed_type: str = "nod", dt_feed_kwargs: dict = {}) -> Iterator:
        """
        Retrieves all entries from the feed.

        Args:
            feed_type (str): The feed type to fetch. (e.g: "nod", "nad")
        Raises:
            ValueError

        Returns:
            list:  A list of objects, containing the indicators.
        """
        # DomainTools feeds optional arguments
        session_id = dt_feed_kwargs.get("session_id", "dt-cortex-feeds")
        top = int(dt_feed_kwargs.get("top") or "5000")
        domain = dt_feed_kwargs.get("domain")
        after = dt_feed_kwargs.get("after")
        before = dt_feed_kwargs.get("before")
        pdns_resolutions_min = dt_feed_kwargs.get("pdns_resolutions_min")
        bad_pdns_resolutions_min = dt_feed_kwargs.get("bad_pdns_resolutions_min")
        total_domains_max = dt_feed_kwargs.get("total_domains_max")
        third_party_threats_min = dt_feed_kwargs.get("third_party_threats_min")
        all_threats_combined_percent_min = dt_feed_kwargs.get("all_threats_combined_percent_min")
        combined_phishing_percent_min = dt_feed_kwargs.get("combined_phishing_percent_min")
        combined_malware_percent_min = dt_feed_kwargs.get("combined_malware_percent_min")
        combined_spam_percent_min = dt_feed_kwargs.get("combined_spam_percent_min")
        asn = dt_feed_kwargs.get("asn")
        organization = dt_feed_kwargs.get("organization")
        country_code = dt_feed_kwargs.get("country_code")
        percent_phishing_min = dt_feed_kwargs.get("percent_phishing_min")
        percent_malware_min = dt_feed_kwargs.get("percent_malware_min")
        percent_spam_min = dt_feed_kwargs.get("percent_spam_min")
        all_threats_percent_min = dt_feed_kwargs.get("all_threats_percent_min")

        demisto.info(f"Start building list of indicators for {feed_type} feed.")

        limit_counter = 0
        processed_feeds = 0

        try:
            # format the after parameter first make sure to append "-" if not given
            if after:
                after = self._format_parameter(key="after", value=after)

            if before:
                before = self._format_parameter(key="before", value=before)

            dt_feeds = self._get_dt_feeds(
                feed_type=feed_type,
                session_id=session_id,
                domain=domain,
                after=after,
                before=before,
                top=top,
                pdns_resolutions_min=pdns_resolutions_min,
                bad_pdns_resolutions_min=bad_pdns_resolutions_min,
                total_domains_max=total_domains_max,
                third_party_threats_min=third_party_threats_min,
                all_threats_combined_percent_min=all_threats_combined_percent_min,
                combined_phishing_percent_min=combined_phishing_percent_min,
                combined_malware_percent_min=combined_malware_percent_min,
                combined_spam_percent_min=combined_spam_percent_min,
                asn=asn,
                organization=organization,
                country_code=country_code,
                percent_phishing_min=percent_phishing_min,
                percent_malware_min=percent_malware_min,
                percent_spam_min=percent_spam_min,
                all_threats_percent_min=all_threats_percent_min,
            )

            total_dt_feeds = len(dt_feeds)
            demisto.info(f"Fetched {total_dt_feeds} of {feed_type} feeds.")

            ud_tags = [tag.strip() for tag in self.tags.split(",")]

            for feed in dt_feeds:
                if top and limit_counter >= top:
                    break

                json_feed = json.loads(feed)

                timestamp = json_feed.get("timestamp", "")

                if feed_type in (self.IPHOTLIST, self.IPRISK):
                    indicator = json_feed.get("ip")
                    indicator_type = "DomainToolsFeed IP"
                else:
                    indicator = json_feed.get("domain")
                    indicator_type = FeedIndicatorType.Domain

                # for `domainrdap` feed, we have more data to display including the parsed data.
                parsed_record = json_feed.get("parsed_record", {})
                overall_risk_score = json_feed.get("overall_risk", None)
                risk_score_details = None

                dt_feed_data = {
                    "value": indicator,
                    "type": indicator_type,
                    "timestamp": timestamp,
                    "tags": ["DomainToolsFeeds", feed_type] + ud_tags,
                    "tlp_color": self.tlp_color,
                    "parsed_record": parsed_record,
                    "overall_risk_score": overall_risk_score,
                }

                # for domainhotlist & domainrisk feed, we will be returning the risk scores
                if feed_type in (self.DOMAINRISK, self.DOMAINHOTLIST):
                    risk_score_details = {
                        "phishing_risk": json_feed.get("phishing_risk"),
                        "malware_risk": json_feed.get("malware_risk"),
                        "spam_risk": json_feed.get("spam_risk"),
                        "proximity_risk": json_feed.get("proximity_risk"),
                        "overall_risk": json_feed.get("overall_risk"),
                    }

                    if feed_type == self.DOMAINHOTLIST:
                        risk_score_details["expires"] = json_feed.get("expires")

                    # update the parsed dt feed data
                    dt_feed_data["risk_score_details"] = risk_score_details

                if feed_type in (self.IPHOTLIST, self.IPRISK):
                    ip_threat_data = {
                        "asn": json_feed.get("asn"),
                        "organization": json_feed.get("organization"),
                        "city": json_feed.get("city"),
                        "country": json_feed.get("country"),
                        "latitude": json_feed.get("latitude"),
                        "longitude": json_feed.get("longitude"),
                        "pdns_resolutions": json_feed.get("pdns_resolutions"),
                        "bad_pdns_resolutions": json_feed.get("bad_pdns_resolutions"),
                        "total_domains": json_feed.get("total_domains"),
                        "zerolist_domains": json_feed.get("zerolist_domains"),
                        "zerolist_ip": json_feed.get("zerolist_ip"),
                        "third_party_threats": json_feed.get("third_party_threats"),
                        "all_threats_combined_count": json_feed.get("all_threats_combined_count"),
                        "all_threats_combined_percent": json_feed.get("all_threats_combined_percent"),
                        "all_threats_percent": json_feed.get("all_threats_percent"),
                        "combined_phishing_percent": json_feed.get("combined_phishing_percent"),
                        "combined_malware_percent": json_feed.get("combined_malware_percent"),
                        "combined_spam_percent": json_feed.get("combined_spam_percent"),
                        "malicious_phishing": json_feed.get("malicious_phishing"),
                        "malicious_malware": json_feed.get("malicious_malware"),
                        "malicious_spam": json_feed.get("malicious_spam"),
                        "percent_phishing": json_feed.get("percent_phishing"),
                        "percent_malware": json_feed.get("percent_malware"),
                        "percent_spam": json_feed.get("percent_spam"),
                        "compromised_phishing": json_feed.get("compromised_phishing"),
                        "compromised_malware": json_feed.get("compromised_malware"),
                        "compromised_spam": json_feed.get("compromised_spam"),
                        "predicted_phishing": json_feed.get("predicted_phishing"),
                        "predicted_malware": json_feed.get("predicted_malware"),
                        "predicted_spam": json_feed.get("predicted_spam"),
                    }
                    dt_feed_data["ip_threat_data"] = ip_threat_data

                if indicator and indicator_type:
                    yield dt_feed_data

                    limit_counter += 1
                    processed_feeds += 1

            demisto.info(f"Done processing {processed_feeds} out of {total_dt_feeds} {feed_type} feeds.")
        except Exception as err:
            demisto.debug(str(err))
            raise ValueError(f"Could not parse returned data as indicator. \n\nError massage: {str(err)}")


def get_dbot_score(overall_risk_score: int | None = None):
    """
    Gets the DBot score
    score info:
        NONE = 0
        GOOD = 1
        SUSPICIOUS = 2
        BAD = 3
    Args:
        overall_risk_score: The overall riskscore. Defaults to None.

    Returns: DBot Score

    """
    # Unknown scores
    if overall_risk_score is None:
        return Common.DBotScore.NONE

    # check for the 'BAD' condition then return.
    if overall_risk_score >= RISK_THRESHOLD:
        return Common.DBotScore.BAD

    # check for 'SUSPICIOUS' conditions as we know both scores will be lower.
    if 50 <= overall_risk_score <= 69:
        return Common.DBotScore.SUSPICIOUS

    # If the domain is not BAD and not SUSPICIOUS, then return GOOD.
    return Common.DBotScore.GOOD


def batch_create_indicators(indicators: list[dict[str, Any]], batch_size: int = 2000):
    """Creates the indicators in batches of the given size.

    Args:
        indicators (list[dict[str, Any]]): The list of indicators.
        batch_size (int, optional): The batch size. Defaults to 2000.
    """
    for iter_ in batch(indicators, batch_size=batch_size):
        demisto.createIndicators(iter_)


def fetch_indicators(client: DomainToolsClient, feed_type: str = "nod", dt_feed_kwargs: dict[str, Any] = {}) -> list[dict]:
    """Retrieves indicators from the feed

    Args:
        client (DomainToolsClient): DomainToolsClient object with request.
        feed_type (str): The feed type to fetch.

    Returns:
        list: indicators.
    """
    indicators = []
    try:
        # extract values from iterator
        for idx, item in enumerate(client.build_iterator(feed_type=feed_type, dt_feed_kwargs=dt_feed_kwargs), start=1):
            value_ = item.get("value")
            type_ = item.get("type")
            timestamp_ = item.get("timestamp")
            tags_ = item.get("tags", [])
            tlp_color_ = item.get("tlp_color")
            parsed_record_ = item.get("parsed_record")
            overall_risk_score_ = item.get("overall_risk_score")
            risk_score_details_ = item.get("risk_score_details")
            ip_threat_data_ = item.get("ip_threat_data")

            indicator_tags = ",".join(tags_).rstrip(",")

            raw_data = {
                "value": value_,
                "type": type_,
                "timestamp": timestamp_,
            }

            if parsed_record_:
                raw_data["parsed_record"] = parsed_record_

            if risk_score_details_:
                raw_data["risk_score_details"] = risk_score_details_

            if ip_threat_data_:
                raw_data["ip_threat_data"] = ip_threat_data_

            # Create indicator object for each value.
            indicator_obj = {
                "value": value_,
                "type": type_,
                "fields": {
                    "tags": indicator_tags,
                    "service": "DomainTools Feeds",
                    "firstseenbysource": timestamp_,
                    "sourcebrands": "FeedDomainTools",
                },
                "rawJSON": raw_data,
            }

            if timestamp_:
                if type_ == "DomainToolsFeed IP":
                    indicator_obj["fields"]["domaintoolsfeedipfeedtimestamp"] = timestamp_

            if tlp_color_:
                indicator_obj["fields"]["trafficlightprotocol"] = tlp_color_

            if ip_threat_data_:
                indicator_obj["fields"]["domaintoolsfeedipasn"] = ip_threat_data_.get("asn")
                indicator_obj["fields"]["domaintoolsfeediporganization"] = ip_threat_data_.get("organization")
                indicator_obj["fields"]["domaintoolsfeedipcity"] = ip_threat_data_.get("city")
                indicator_obj["fields"]["domaintoolsfeedipcountry"] = ip_threat_data_.get("country")
                indicator_obj["fields"]["domaintoolsfeediplatitude"] = ip_threat_data_.get("latitude")
                indicator_obj["fields"]["domaintoolsfeediplongitude"] = ip_threat_data_.get("longitude")
                indicator_obj["fields"]["domaintoolsfeedippdnsresolutions"] = ip_threat_data_.get("pdns_resolutions")
                indicator_obj["fields"]["domaintoolsfeedipbadpdnsresolutions"] = ip_threat_data_.get("bad_pdns_resolutions")
                indicator_obj["fields"]["domaintoolsfeediptotaldomains"] = ip_threat_data_.get("total_domains")
                indicator_obj["fields"]["domaintoolsfeedipzerolistdomains"] = ip_threat_data_.get("zerolist_domains")
                indicator_obj["fields"]["domaintoolsfeedipzerolistip"] = ip_threat_data_.get("zerolist_ip")
                indicator_obj["fields"]["domaintoolsfeedipthirdpartythreats"] = ip_threat_data_.get("third_party_threats")
                indicator_obj["fields"]["domaintoolsfeedipallthreatscombinedcount"] = ip_threat_data_.get("all_threats_combined_count")
                indicator_obj["fields"]["domaintoolsfeedipallthreatscombinedpercent"] = ip_threat_data_.get("all_threats_combined_percent")
                indicator_obj["fields"]["domaintoolsfeedipallthreatsperecent"] = ip_threat_data_.get("all_threats_percent")
                indicator_obj["fields"]["domaintoolsfeedipcombinedphishingpercent"] = ip_threat_data_.get("combined_phishing_percent")
                indicator_obj["fields"]["domaintoolsfeedipcombinedmalwarepercent"] = ip_threat_data_.get("combined_malware_percent")
                indicator_obj["fields"]["domaintoolsfeedipcombinedspampercent"] = ip_threat_data_.get("combined_spam_percent")
                indicator_obj["fields"]["domaintoolsfeedipmaliciousphishing"] = ip_threat_data_.get("malicious_phishing")
                indicator_obj["fields"]["domaintoolsfeedipmaliciousmalware"] = ip_threat_data_.get("malicious_malware")
                indicator_obj["fields"]["domaintoolsfeedipmaliciousspam"] = ip_threat_data_.get("malicious_spam")
                indicator_obj["fields"]["domaintoolsfeedippercentphishing"] = ip_threat_data_.get("percent_phishing")
                indicator_obj["fields"]["domaintoolsfeedippercentmalware"] = ip_threat_data_.get("percent_malware")
                indicator_obj["fields"]["domaintoolsfeedippercentspam"] = ip_threat_data_.get("percent_spam")
                indicator_obj["fields"]["domaintoolsfeedipcompromisedphishing"] = ip_threat_data_.get("compromised_phishing")
                indicator_obj["fields"]["domaintoolsfeedipcompromisedmalware"] = ip_threat_data_.get("compromised_malware")
                indicator_obj["fields"]["domaintoolsfeedipcompromisedspam"] = ip_threat_data_.get("compromised_spam")
                indicator_obj["fields"]["domaintoolsfeedippredictedphishing"] = ip_threat_data_.get("predicted_phishing")
                indicator_obj["fields"]["domaintoolsfeedippredictedmalware"] = ip_threat_data_.get("predicted_malware")
                indicator_obj["fields"]["domaintoolsfeedippredictedspam"] = ip_threat_data_.get("predicted_spam")

            if overall_risk_score_:
                indicator_obj["score"] = get_dbot_score(overall_risk_score=overall_risk_score_)

            indicators.append(indicator_obj)

            if idx % 1000 == 0 or (idx < 1000 and idx % 100 == 0):
                demisto.info(f"Processed {idx} indicator obj from {feed_type.upper()} feeds.")
    except Exception as e:
        raise Exception(f"Unable to fetch feeds from DomainTools. Reason: {str(e)}")

    return indicators


def get_indicators_command(client: DomainToolsClient, args: dict[str, str], params: dict[str, str]) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: DomainToolsClient object with request
        args: demisto.args()
    Returns:
        CommandResults.
    """
    feed_type = args.get("feed_type", "nod")
    session_id = args.get("session_id")
    domain = args.get("domain")
    after = args.get("after")
    before = args.get("before")
    top = args.get("top")

    dt_feeds_kwargs = {
        "session_id": session_id,
        "after": after,
        "before": before,
        "domain": domain,
        "top": top,
        "pdns_resolutions_min": arg_to_number(args.get("pdns_resolutions_min")),
        "bad_pdns_resolutions_min": arg_to_number(args.get("bad_pdns_resolutions_min")),
        "total_domains_max": arg_to_number(args.get("total_domains_max")),
        "third_party_threats_min": arg_to_number(args.get("third_party_threats_min")),
        "all_threats_combined_percent_min": arg_to_number(args.get("all_threats_combined_percent_min")),
        "combined_phishing_percent_min": arg_to_number(args.get("combined_phishing_percent_min")),
        "combined_malware_percent_min": arg_to_number(args.get("combined_malware_percent_min")),
        "combined_spam_percent_min": arg_to_number(args.get("combined_spam_percent_min")),
        "asn": arg_to_number(args.get("asn")),
        "organization": args.get("organization"),
        "country_code": args.get("country_code"),
        "percent_phishing_min": arg_to_number(args.get("percent_phishing_min")),
        "percent_malware_min": arg_to_number(args.get("percent_malware_min")),
        "percent_spam_min": arg_to_number(args.get("percent_spam_min")),
        "all_threats_percent_min": arg_to_number(args.get("all_threats_percent_min")),
    }

    demisto.debug(f"Fetching feed indicators by feed_type: {feed_type}")
    indicators = fetch_indicators(client, feed_type=feed_type, dt_feed_kwargs=dt_feeds_kwargs)

    human_readable = tableToMarkdown(
        f"Indicators from DomainTools {feed_type.upper()} Feed:",
        indicators,
        headers=["value", "type", "fields", "rawJSON"],
        removeNull=True,
    )

    batch_create_indicators(indicators, batch_size=100)

    return CommandResults(readable_output=human_readable, raw_response=indicators, ignore_auto_extract=True)


def fetch_indicators_command(client: DomainToolsClient, params: dict[str, Any] = {}) -> list[dict]:
    """
    Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: DomainToolsClient object with request
    Returns:
        list: indicators.
    """

    session_id = params.get("session_id")
    after = params.get("after")
    top = params.get("top")

    feed_type_ = params.get("feed_type", "ALL")

    FEEDS_TO_PROCESS = [
        client.NOD_FEED,
        client.NAD_FEED,
        client.NOH_FEED,
        client.DOMAINRDAP,
        client.DOMAINDISCOVERY,
        client.DOMAINRISK,
        client.DOMAINHOTLIST,
        client.IPHOTLIST,
        client.IPRISK,
    ]

    dt_feed_kwargs = {"top": top, "after": after, "session_id": session_id}

    fetched_indicators = []

    for feed_type in FEEDS_TO_PROCESS:
        indicators = []
        if feed_type_ == "ALL":
            indicators = fetch_indicators(client, feed_type=feed_type, dt_feed_kwargs=dt_feed_kwargs)
        if feed_type_.upper() == feed_type.upper():
            indicators = fetch_indicators(client, feed_type=feed_type, dt_feed_kwargs=dt_feed_kwargs)

        fetched_indicators.extend(indicators)

    return fetched_indicators


def test_module(client: DomainToolsClient, args: dict[str, str], params: dict[str, str]) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: DomainToolsClient object.
    Returns:
        str.
    """
    dt_feed_kwargs = {"top": 1, "after": None}

    feed_type_ = params.get("feed_type", "nod")
    feed_type_ = "nod" if feed_type_ == "ALL" else feed_type_
    try:
        next(client.build_iterator(feed_type=feed_type_, dt_feed_kwargs=dt_feed_kwargs))
    except Exception as e:
        raise Exception(
            "Could not fetch DomainTools Feed\n"
            f"\nCheck your API username/key and your connection to DomainTools. \nReason: {str(e)}"
        )

    return "ok"


def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    commands: dict[str, Callable] = {
        "test-module": test_module,
        "domaintools-get-indicators": get_indicators_command,
    }

    api_username = params.get("credentials", {}).get("identifier", "")
    api_key = params.get("credentials", {}).get("password", "")
    insecure = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    user_defined_tags = params.get("feedTags", "")
    tlp_color = params.get("tlp_color")

    try:
        client = DomainToolsClient(
            api_username=api_username,
            api_key=api_key,
            verify_ssl=insecure,
            proxy=proxy,
            tags=user_defined_tags,
            tlp_color=tlp_color,
        )

        demisto.debug(f"Command being called is {command}")
        if command in commands:
            return_results(commands[command](client, args, params))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            batch_create_indicators(indicators)
        else:
            raise NotImplementedError(f"Command {command} is not supported")

    except Exception as e:
        # Log exceptions and return errors
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
