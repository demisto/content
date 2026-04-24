import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
import traceback
from typing import Any
import re
from json.decoder import JSONDecodeError

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
MESSAGES: dict[str, str] = {
    "BAD_REQUEST_ERROR": "An error occurred while fetching the data.",
    "AUTHORIZATION_ERROR": "Authorization Error: make sure API Key is correctly set.",
    "RATE_LIMIT_EXCEED_ERROR": "Rate limit has been exceeded. Please check your API key's rate limit.",
}
INTEGRATION_NAME = "SOCRadar IoC Enrichment"

# Fields to request (excluding AI insight for performance)
DEFAULT_FIELDS = ["indicator_details", "indicator_history", "indicator_relations"]

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the SOCRadar IoC Enrichment API"""

    def __init__(self, base_url, api_key, verify, proxy, include_ai_insights=False):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self.include_ai_insights = include_ai_insights

    def get_indicator_enrichment(self, indicator: str, fields: list[str] | None = None):
        """Get indicator enrichment from SOCRadar IoC Enrichment API

        Args:
            indicator: The indicator value (IP, domain, URL, or hash)
            fields: List of fields to include (defaults to all except AI insight)

        Returns:
            API response with enrichment data
        """
        suffix = "/ioc_enrichment/get/indicator_details"

        if fields is None:
            if self.include_ai_insights:
                fields = DEFAULT_FIELDS + ["indicator_ai_insight"]
            else:
                fields = DEFAULT_FIELDS

        request_body = {"indicator": indicator, "fields": fields}

        headers = {"Api-Key": self.api_key, "Content-Type": "application/json"}

        response = self._http_request(
            method="POST",
            url_suffix=suffix,
            json_data=request_body,
            headers=headers,
            timeout=60,
            error_handler=self.handle_error_response,
            resp_type="json",
        )
        return response

    def check_auth(self):
        """Check API authentication by making a test request"""
        try:
            demisto.debug("Testing API authentication...")
            # Use a well-known IP for testing
            response = self.get_indicator_enrichment("8.8.8.8")
            demisto.debug(f"Auth test response: {response}")
            return response
        except Exception as e:
            demisto.error(f"Authentication test failed: {str(e)}")
            raise DemistoException(f"Authentication failed: {str(e)}")

    @staticmethod
    def handle_error_response(response) -> None:
        """Handles API response errors"""
        error_reason = ""
        try:
            json_resp = response.json()
            error_reason = json_resp.get("error") or json_resp.get("message", "")
        except JSONDecodeError:
            pass

        status_code_messages = {
            400: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            401: MESSAGES["AUTHORIZATION_ERROR"],
            404: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            429: MESSAGES["RATE_LIMIT_EXCEED_ERROR"],
        }

        if response.status_code in status_code_messages:
            demisto.debug(f"Response Code: {response.status_code}, Reason: {status_code_messages[response.status_code]}")
            raise DemistoException(status_code_messages[response.status_code])
        else:
            try:
                response.raise_for_status()
            except Exception as e:
                raise DemistoException(f"Error in API call [{response.status_code}] - {response.text}\n{e}")


""" HELPER FUNCTIONS """


def calculate_dbot_score(score: float) -> int:
    """Calculate DBot score from SOCRadar enrichment data.

    SOCRadar score ranges:
        0       → Unknown  (0)
        1–50    → Medium   → Suspicious (2)
        51–75   → High     → Malicious (3)
        76–100  → Critical → Malicious (3)

    Returns:
        DBot score (0=Unknown, 2=Suspicious, 3=Malicious)
    """
    if isinstance(score, list):
        score = score[0] if score else 0
    elif score is None:
        score = 0

    try:
        score = float(score)
    except (ValueError, TypeError):
        score = 0

    if score == 0:
        return 0  # Unknown
    elif score <= 50:
        return 2  # Medium → Suspicious
    else:
        return 3  # High / Critical → Malicious


class Validator:
    @staticmethod
    def validate_domain(domain_to_validate):
        if not isinstance(domain_to_validate, str) or len(domain_to_validate) > 255:
            return False
        if domain_to_validate.endswith("."):
            domain_to_validate = domain_to_validate[:-1]
        domain_regex = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(domain_regex.match(x) for x in domain_to_validate.split("."))

    @staticmethod
    def validate_ipv4(ip_to_validate):
        return is_ip_valid(ip_to_validate)

    @staticmethod
    def validate_ipv6(ip_to_validate):
        return is_ipv6_valid(ip_to_validate)

    @staticmethod
    def validate_hash(hash_to_validate):
        return get_hash_type(hash_to_validate) != "Unknown"

    @staticmethod
    def validate_url(url_to_validate):
        """Validate URL format"""
        url_regex = re.compile(
            r"^https?://"
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
            r"localhost|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"(?::\d+)?"
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        return url_regex.match(url_to_validate) is not None

    @staticmethod
    def raise_if_ip_not_valid(ip: str):
        if not Validator.validate_ipv4(ip) and not Validator.validate_ipv6(ip):
            raise ValueError(f'IP "{ip}" is not a valid IPv4 or IPv6 address')

    @staticmethod
    def raise_if_domain_not_valid(domain: str):
        if not Validator.validate_domain(domain):
            raise ValueError(f'Domain "{domain}" is not a valid domain address')

    @staticmethod
    def raise_if_hash_not_valid(file_hash: str):
        if not Validator.validate_hash(file_hash):
            raise ValueError(f'Hash "{file_hash}" is not a valid hash')

    @staticmethod
    def raise_if_url_not_valid(url: str):
        if not Validator.validate_url(url):
            raise ValueError(f'URL "{url}" is not a valid URL')


def build_entry_context(raw_response: dict, indicator: str) -> dict:
    """Build context entry from API response"""

    # Extract main components
    details = raw_response.get("details", {})
    summary = raw_response.get("summary", {})
    categorization = raw_response.get("categorization", {})
    classifications = raw_response.get("top_classifications", {})  # Changed to top_classifications
    history = raw_response.get("history", {})
    activity_labels = raw_response.get("activity_label_dict", {})
    premium_feeds = raw_response.get("premium_feeds", [])
    relations = raw_response.get("relations", [])

    # Extract score - API returns it as array, take first value and round to 2 decimals
    score_value = details.get("score")
    if isinstance(score_value, list) and len(score_value) > 0:
        score = score_value[0]
    else:
        score = score_value

    # Round score to 2 decimal places for readability
    if score is not None:
        score = round(float(score), 2)

    context_entry = {
        "Indicator": indicator,
        "Score": score,
        "Name": details.get("name"),
        "Country": summary.get("country") or details.get("country_name"),
        "ASN": summary.get("asn_name"),
        "ASNCode": summary.get("asn_code") or details.get("asn_code"),
        "CIDR": details.get("cidr"),
        "FirstSeen": details.get("first_seen_date"),
        "LastSeen": details.get("last_seen_date"),
        "SignalStrength": details.get("ioc_signal_strength") or raw_response.get("ioc_signal_strength"),
        "Confidence": details.get("cross_source_confidence") or raw_response.get("cross_source_confidence"),
        "IsWhitelisted": details.get("is_whitelisted", False),
        # Activity labels
        "Activity": {
            "Last1Day": activity_labels.get("last_1_day"),
            "Last7Days": activity_labels.get("last_7_days"),
            "Last30Days": activity_labels.get("last_30_days"),
            "Last90Days": activity_labels.get("last_90_days"),
        },
        # Categorization flags
        "Categorization": {
            "CDN": categorization.get("cdn", False),
            "Cloud": categorization.get("cloud", False),
            "Cryptocurrency": categorization.get("cryptocurrency", False),
            "Honeypot": categorization.get("honeypot", False),
            "Hosting": categorization.get("hosting", False),
            "Malware": categorization.get("malware", False),
            "Proxy": categorization.get("proxy", False),
            "Scanner": categorization.get("scanner", False),
            "ThreatActor": categorization.get("threat_actor", False),
            "Tor": categorization.get("tor", False),
            "VPN": categorization.get("vpn", False),
        },
        # Classifications
        "Classifications": {
            "Campaign": classifications.get("campaign"),
            "Country": classifications.get("country"),
            "Industries": classifications.get("industries", []),
            "Malwares": classifications.get("malwares", []),
            "Region": classifications.get("region"),
            "TargetCountries": classifications.get("target_country_list", []),
            "ThreatActors": classifications.get("threat_actors", []),
        },
        # Premium Feeds
        "PremiumFeeds": [
            {
                "Name": feed.get("name"),
                "Category": feed.get("category"),
                "Description": feed.get("description"),
            }
            for feed in premium_feeds
        ],
        # Relations (limited to 10)
        "Relations": [
            {
                "Name": rel.get("name"),
                "Type": rel.get("relation_type"),
                "Source": rel.get("relation_source"),
                "FirstSeen": rel.get("first_seen_date"),
            }
            for rel in relations[:10]
        ],
        # History (limited to last 10 events)
        "History": [],
    }

    # Process history
    indicator_history = history.get("indicator_history", [])
    # Ensure indicator_history is a list before slicing
    if isinstance(indicator_history, list):
        for event in indicator_history[:10]:  # Limit to 10 most recent events
            if isinstance(event, dict):  # Ensure event is a dict
                context_entry["History"].append(
                    {
                        "Event": event.get("event"),
                        "FeedSource": event.get("feed_source"),
                        "Date": event.get("insert_date"),
                    }
                )

    # AI Insight (only if present in response)
    ai_insight = raw_response.get("socradar_copilot:ioc_agent")
    if ai_insight:
        context_entry["AIInsight"] = ai_insight

    return context_entry


def detect_indicator_type(indicator: str) -> str:
    """Detect indicator type"""
    indicator = indicator.strip()

    if indicator.startswith(("http://", "https://")):
        return "url"

    if Validator.validate_ipv4(indicator) or Validator.validate_ipv6(indicator):
        return "ip"

    if Validator.validate_hash(indicator):
        return "file"

    if Validator.validate_domain(indicator):
        return "domain"

    raise ValueError(f"Unable to determine indicator type for: {indicator}")


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    try:
        demisto.debug("Starting test_module...")
        response = client.check_auth()
        demisto.debug(f"Test response received: {response}")

        if response:
            demisto.debug("Test successful")
            return "ok"
        else:
            demisto.error("Test failed: No response")
            raise DemistoException("API test failed: No response from API")
    except DemistoException:
        raise
    except Exception as e:
        demisto.error(f"Test module exception: {str(e)}")
        error_details = f"Connection failed: {str(e)}\n\n"
        error_details += "Please check:\n"
        error_details += "1. API Key is correct\n"
        error_details += "2. Network connectivity to platform.socradar.com\n"
        error_details += "3. Firewall allows HTTPS outbound connections"
        raise DemistoException(error_details)


def ip_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Returns SOCRadar IoC enrichment for IP addresses"""
    ips = args.get("ip", "")
    ip_list: list = argToList(ips)

    command_results_list: list[CommandResults] = []

    for ip in ip_list:
        try:
            Validator.raise_if_ip_not_valid(ip)

            raw_response = client.get_indicator_enrichment(ip)

            if raw_response:
                details = raw_response.get("details", {})
                score = details.get("score", 0)

                dbot_score_value = calculate_dbot_score(score)

                title = f"SOCRadar IoC Enrichment - Analysis for IP: {ip}"

                context_entry = build_entry_context(raw_response, ip)
                human_readable = tableToMarkdown(title, context_entry)

                dbot_score = Common.DBotScore(
                    indicator=ip,
                    indicator_type=DBotScoreType.IP,
                    integration_name=INTEGRATION_NAME,
                    score=dbot_score_value,
                    reliability=reliability,
                )

                ip_object = Common.IP(ip=ip, dbot_score=dbot_score)

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarIoCEnrichment.IP",
                        outputs_key_field="Indicator",
                        readable_output=human_readable,
                        raw_response=raw_response,
                        outputs=context_entry,
                        indicator=ip_object,
                    )
                )
            else:
                message = f"No enrichment data found for IP: {ip}"
                command_results_list.append(CommandResults(readable_output=message))
        except ValueError as e:
            command_results_list.append(CommandResults(readable_output=str(e)))
        except Exception as e:
            command_results_list.append(CommandResults(readable_output=f"Error processing IP {ip}: {str(e)}"))

    return command_results_list


def domain_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Returns SOCRadar IoC enrichment for domains"""
    domains = args.get("domain", "")
    domain_list: list = argToList(domains)

    command_results_list: list[CommandResults] = []

    for domain in domain_list:
        try:
            Validator.raise_if_domain_not_valid(domain)

            raw_response = client.get_indicator_enrichment(domain)

            if raw_response:
                details = raw_response.get("details", {})
                score = details.get("score", 0)

                dbot_score_value = calculate_dbot_score(score)

                title = f"SOCRadar IoC Enrichment - Analysis for Domain: {domain}"

                context_entry = build_entry_context(raw_response, domain)
                human_readable = tableToMarkdown(title, context_entry)

                dbot_score = Common.DBotScore(
                    indicator=domain,
                    indicator_type=DBotScoreType.DOMAIN,
                    integration_name=INTEGRATION_NAME,
                    score=dbot_score_value,
                    reliability=reliability,
                )

                domain_object = Common.Domain(domain=domain, dbot_score=dbot_score)

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarIoCEnrichment.Domain",
                        outputs_key_field="Indicator",
                        readable_output=human_readable,
                        raw_response=raw_response,
                        outputs=context_entry,
                        indicator=domain_object,
                    )
                )
            else:
                message = f"No enrichment data found for domain: {domain}"
                command_results_list.append(CommandResults(readable_output=message))
        except ValueError as e:
            command_results_list.append(CommandResults(readable_output=str(e)))
        except Exception as e:
            command_results_list.append(CommandResults(readable_output=f"Error processing domain {domain}: {str(e)}"))

    return command_results_list


def url_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Returns SOCRadar IoC enrichment for URLs"""
    urls = args.get("url", "")
    url_list: list = argToList(urls)

    command_results_list: list[CommandResults] = []

    for url in url_list:
        try:
            Validator.raise_if_url_not_valid(url)

            raw_response = client.get_indicator_enrichment(url)

            if raw_response:
                details = raw_response.get("details", {})
                score = details.get("score", 0)

                dbot_score_value = calculate_dbot_score(score)

                title = f"SOCRadar IoC Enrichment - Analysis for URL: {url}"

                context_entry = build_entry_context(raw_response, url)
                human_readable = tableToMarkdown(title, context_entry)

                dbot_score = Common.DBotScore(
                    indicator=url,
                    indicator_type=DBotScoreType.URL,
                    integration_name=INTEGRATION_NAME,
                    score=dbot_score_value,
                    reliability=reliability,
                )

                url_object = Common.URL(url=url, dbot_score=dbot_score)

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarIoCEnrichment.URL",
                        outputs_key_field="Indicator",
                        readable_output=human_readable,
                        raw_response=raw_response,
                        outputs=context_entry,
                        indicator=url_object,
                    )
                )
            else:
                message = f"No enrichment data found for URL: {url}"
                command_results_list.append(CommandResults(readable_output=message))
        except ValueError as e:
            command_results_list.append(CommandResults(readable_output=str(e)))
        except Exception as e:
            command_results_list.append(CommandResults(readable_output=f"Error processing URL {url}: {str(e)}"))

    return command_results_list


def file_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Returns SOCRadar IoC enrichment for file hashes"""
    file_hashes = args.get("file", "")
    file_hash_list: list = argToList(file_hashes)

    command_results_list: list[CommandResults] = []

    for hash_value in file_hash_list:
        try:
            Validator.raise_if_hash_not_valid(hash_value)
            hash_type = get_hash_type(hash_value)

            raw_response = client.get_indicator_enrichment(hash_value)

            if raw_response:
                details = raw_response.get("details", {})
                score = details.get("score", 0)

                dbot_score_value = calculate_dbot_score(score)

                title = f"SOCRadar IoC Enrichment - Analysis for Hash: {hash_value}"

                context_entry = build_entry_context(raw_response, hash_value)
                human_readable = tableToMarkdown(title, context_entry)

                dbot_score = Common.DBotScore(
                    indicator=hash_value,
                    indicator_type=DBotScoreType.FILE,
                    integration_name=INTEGRATION_NAME,
                    score=dbot_score_value,
                    reliability=reliability,
                )

                file_object = Common.File(dbot_score=dbot_score)

                if hash_type == "sha256":
                    file_object.sha256 = hash_value
                elif hash_type == "sha1":
                    file_object.sha1 = hash_value
                elif hash_type == "md5":
                    file_object.md5 = hash_value

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarIoCEnrichment.File",
                        outputs_key_field="Indicator",
                        readable_output=human_readable,
                        raw_response=raw_response,
                        outputs=context_entry,
                        indicator=file_object,
                    )
                )
            else:
                message = f"No enrichment data found for hash: {hash_value}"
                command_results_list.append(CommandResults(readable_output=message))
        except ValueError as e:
            command_results_list.append(CommandResults(readable_output=str(e)))
        except Exception as e:
            command_results_list.append(CommandResults(readable_output=f"Error processing hash {hash_value}: {str(e)}"))

    return command_results_list


def socradar_ioc_enrichment_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Generic enrichment command for any indicator type with auto-detection"""
    indicator = args.get("indicator", "").strip()

    if not indicator:
        return [CommandResults(readable_output="Indicator parameter is required.")]

    command_results_list: list[CommandResults] = []

    try:
        # Detect indicator type
        indicator_type = detect_indicator_type(indicator)

        # Get enrichment data
        raw_response = client.get_indicator_enrichment(indicator)

        if raw_response:
            details = raw_response.get("details", {})

            # Extract score
            score_value = details.get("score")
            if isinstance(score_value, list) and len(score_value) > 0:
                score = score_value[0]
            else:
                score = score_value or 0

            dbot_score_value = calculate_dbot_score(score)

            # Initialize common_object
            common_object: Common.IP | Common.Domain | Common.URL | Common.File | None = None

            # Determine DBot type based on detected type
            if indicator_type == "ip":
                dbot_type = DBotScoreType.IP
                output_prefix = "SOCRadarIoCEnrichment.IP"
                common_object = Common.IP(
                    ip=indicator,
                    dbot_score=Common.DBotScore(
                        indicator=indicator,
                        indicator_type=dbot_type,
                        integration_name=INTEGRATION_NAME,
                        score=dbot_score_value,
                        reliability=reliability,
                    ),
                )
            elif indicator_type == "domain":
                dbot_type = DBotScoreType.DOMAIN
                output_prefix = "SOCRadarIoCEnrichment.Domain"
                common_object = Common.Domain(
                    domain=indicator,
                    dbot_score=Common.DBotScore(
                        indicator=indicator,
                        indicator_type=dbot_type,
                        integration_name=INTEGRATION_NAME,
                        score=dbot_score_value,
                        reliability=reliability,
                    ),
                )
            elif indicator_type == "url":
                dbot_type = DBotScoreType.URL
                output_prefix = "SOCRadarIoCEnrichment.URL"
                common_object = Common.URL(
                    url=indicator,
                    dbot_score=Common.DBotScore(
                        indicator=indicator,
                        indicator_type=dbot_type,
                        integration_name=INTEGRATION_NAME,
                        score=dbot_score_value,
                        reliability=reliability,
                    ),
                )
            else:  # file/hash
                dbot_type = DBotScoreType.FILE
                output_prefix = "SOCRadarIoCEnrichment.File"
                hash_type = get_hash_type(indicator)

                dbot_score = Common.DBotScore(
                    indicator=indicator,
                    indicator_type=dbot_type,
                    integration_name=INTEGRATION_NAME,
                    score=dbot_score_value,
                    reliability=reliability,
                )

                common_object = Common.File(dbot_score=dbot_score)
                if hash_type == "sha256":
                    common_object.sha256 = indicator
                elif hash_type == "sha1":
                    common_object.sha1 = indicator
                elif hash_type == "md5":
                    common_object.md5 = indicator

            title = f"SOCRadar IoC Enrichment - {indicator_type.upper()}: {indicator}"
            context_entry = build_entry_context(raw_response, indicator)
            human_readable = tableToMarkdown(title, context_entry)

            command_results_list.append(
                CommandResults(
                    outputs_prefix=output_prefix,
                    outputs_key_field="Indicator",
                    readable_output=human_readable,
                    raw_response=raw_response,
                    outputs=context_entry,
                    indicator=common_object,
                )
            )
        else:
            message = f"No enrichment data found for indicator: {indicator}"
            command_results_list.append(CommandResults(readable_output=message))

    except ValueError as e:
        command_results_list.append(CommandResults(readable_output=f"Error: {str(e)}"))
    except Exception as e:
        command_results_list.append(CommandResults(readable_output=f"Error processing indicator {indicator}: {str(e)}"))

    return command_results_list


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions"""

    params = demisto.params()
    api_key = params.get("apikey")
    base_url = SOCRADAR_API_ENDPOINT
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    reliability = params.get("integrationReliability")
    include_ai_insights = params.get("include_ai_insights", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
            include_ai_insights=include_ai_insights,
        )
        command = demisto.command()

        if command == "test-module":
            demisto.debug("Executing test-module command")
            result = test_module(client)
            demisto.debug(f"Test module result: {result}")
            return_results(result)
        elif command == "ip":
            demisto.debug("Executing ip command")
            return_results(ip_command(client, demisto.args(), reliability))
        elif command == "domain":
            demisto.debug("Executing domain command")
            return_results(domain_command(client, demisto.args(), reliability))
        elif command == "url":
            demisto.debug("Executing url command")
            return_results(url_command(client, demisto.args(), reliability))
        elif command == "file":
            demisto.debug("Executing file command")
            return_results(file_command(client, demisto.args(), reliability))
        elif command == "socradar-ioc-enrichment":
            demisto.debug("Executing socradar-ioc-enrichment command")
            return_results(socradar_ioc_enrichment_command(client, demisto.args(), reliability))
        else:
            demisto.debug(f"Unknown command: {command}")
            return_error(f"Command {command} is not supported")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
