import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
import traceback
from typing import Any
import re
from json.decoder import JSONDecodeError
import time

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
MESSAGES: dict[str, str] = {
    "BAD_REQUEST_ERROR": "An error occurred while fetching the data.",
    "AUTHORIZATION_ERROR": "Authorization Error: make sure API Key is correctly set.",
    "RATE_LIMIT_EXCEED_ERROR": "Rate limit has been exceeded. Please make sure your API key's rate limit is adequate.",
}
INTEGRATION_NAME = "SOCRadar Rapid Reputation"
MAX_BULK_CHECK_INDICATORS = 100  # Maximum indicators per bulk check to avoid XSOAR limits

""" CLIENT CLASS """


class Client(ContentClient):
    """
    Client class to interact with the SOCRadar Rapid Reputation API
    """

    def __init__(self, base_url, api_key, verify, proxy):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.api_key = api_key

    def get_entity_reputation(self, entity_value: str, entity_type: str):
        """Get entity reputation from SOCRadar Rapid Reputation API

        Args:
            entity_value: The value of the entity (IP, domain, URL, or hash)
            entity_type: The type of entity (ip, hostname, url, hash)

        Returns:
            API response with reputation data
        """
        suffix = "/threatfeed/rapid/reputation"
        api_params = {"entity_value": entity_value, "entity_type": entity_type}
        headers = {"Api-Key": self.api_key}

        response = self._http_request(
            method="GET",
            url_suffix=suffix,
            params=api_params,
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
            response = self.get_entity_reputation("8.8.8.8", "ip")
            demisto.debug(f"Auth test response: {response}")
            return response
        except Exception as e:
            demisto.error(f"Authentication test failed: {str(e)}")
            raise DemistoException(f"Authentication failed: {str(e)}")

    @staticmethod
    def handle_error_response(response) -> None:
        """Handles API response to display descriptive error messages based on status code"""
        error_reason = ""
        try:
            json_resp = response.json()
            error_reason = json_resp.get("exception") or json_resp.get("message")
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
    """Transforms reputation score from SOCRadar API to DBot Score.

    Args:
        score: Reputation score from SOCRadar API (0-100 range typically)

    Returns:
        Score representation in DBot (0=Unknown, 1=Good, 2=Suspicious, 3=Malicious)
    """
    return_score = 0
    if score is None:
        return_score = 0  # Unknown
    # Malicious
    elif score > 80:
        return_score = 3
    # Suspicious
    elif score > 40:
        return_score = 2
    # Good
    elif score > 0:
        return_score = 1
    # Unknown
    return return_score


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
            r"^https?://"  # http:// or https://
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain
            r"localhost|"  # localhost
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # or IP
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        return url_regex.match(url_to_validate) is not None

    @staticmethod
    def raise_if_ip_not_valid(ip: str):
        """Raises an error if ip is not valid"""
        if not Validator.validate_ipv4(ip) and not Validator.validate_ipv6(ip):
            raise ValueError(f'IP "{ip}" is not a type of IPv4 or IPv6')

    @staticmethod
    def raise_if_domain_not_valid(domain: str):
        """Raises an error if domain is not valid"""
        if not Validator.validate_domain(domain):
            raise ValueError(f'Domain "{domain}" is not a valid domain address')

    @staticmethod
    def raise_if_hash_not_valid(file_hash: str):
        """Raises an error if file_hash is not valid"""
        if not Validator.validate_hash(file_hash):
            raise ValueError(f'Hash "{file_hash}" is not a valid hash')

    @staticmethod
    def raise_if_url_not_valid(url: str):
        """Raises an error if URL is not valid"""
        if not Validator.validate_url(url):
            raise ValueError(f'URL "{url}" is not a valid URL')


def build_entry_context(raw_response: dict, entity_value: str, entity_type: str) -> dict:
    """Build context entry from API response"""
    data = raw_response.get("data", {})

    # Get and round score to 2 decimal places
    score = data.get("score")
    if score is not None:
        score = round(float(score), 2)

    context_entry = {
        "Entity": entity_value,
        "EntityType": entity_type,
        "Score": score,
        "IsWhitelisted": data.get("is_whitelisted", False),
        "FindingSources": [],
    }

    # Process finding sources
    finding_sources = data.get("finding_sources", [])
    for source in finding_sources:
        source_entry = {
            "SourceName": source.get("source_name"),
            "MainCategory": source.get("main_category"),
            "MaintainerName": source.get("maintainer_name"),
            "FirstSeenDate": source.get("first_seen_date"),
            "LastSeenDate": source.get("last_seen_date"),
            "SeenCount": source.get("seen_count"),
        }
        context_entry["FindingSources"].append(source_entry)

    return context_entry


def detect_entity_type(entity: str) -> str:
    """Automatically detect the type of an entity"""
    entity = entity.strip()

    # Check if it's a URL (starts with http:// or https://)
    if entity.startswith(("http://", "https://")):
        return "url"

    # Check if it's an IP address
    if Validator.validate_ipv4(entity) or Validator.validate_ipv6(entity):
        return "ip"

    # Check if it's a hash
    if Validator.validate_hash(entity):
        return "hash"

    # Check if it's a domain
    if Validator.validate_domain(entity):
        return "hostname"

    # If nothing matches, raise an error
    raise ValueError(f"Unable to determine entity type for: {entity}")


def process_entity_by_type(client: Client, entity: str, entity_type: str) -> dict:
    """Process a single entity based on its type"""
    raw_response = client.get_entity_reputation(entity, entity_type)

    if raw_response.get("is_success"):
        data = raw_response.get("data", {})

        if data.get("is_whitelisted"):
            score = 1
        elif (api_score := data.get("score")) is not None:
            score = calculate_dbot_score(api_score)
        else:
            score = 0

        context_entry = build_entry_context(raw_response, entity, entity_type)
        context_entry["DetectedType"] = entity_type

        return {
            "entity": entity,
            "entity_type": entity_type,
            "success": True,
            "context": context_entry,
            "raw_response": raw_response,
            "dbot_score": score,
        }
    else:
        return {
            "entity": entity,
            "entity_type": entity_type,
            "success": False,
            "error": raw_response.get("message", "Unknown error"),
            "raw_response": raw_response,
        }


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    try:
        demisto.debug("Starting test_module...")
        response = client.check_auth()
        demisto.debug(f"Test response received: {response}")

        if response and response.get("is_success"):
            demisto.debug("Test successful")
            return "ok"
        else:
            error_msg = response.get("message", "Unknown error") if response else "No response from API"
            demisto.error(f"Test failed: {error_msg}")
            raise DemistoException(f"API test failed: {error_msg}")
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
    """Returns SOCRadar reputation details for the given IP entity."""
    ips = args.get("ip", "")
    ip_list: list = argToList(ips)

    command_results_list: list[CommandResults] = []

    for ip_to_score in ip_list:
        try:
            Validator.raise_if_ip_not_valid(ip_to_score)

            raw_response = client.get_entity_reputation(ip_to_score, "ip")

            if raw_response.get("is_success"):
                data = raw_response.get("data", {})

                if data.get("is_whitelisted"):
                    score = 1
                elif (api_score := data.get("score")) is not None:
                    score = calculate_dbot_score(api_score)
                else:
                    score = 0

                title = f"SOCRadar Rapid Reputation - Analysis results for IP: {ip_to_score}"

                context_entry = build_entry_context(raw_response, ip_to_score, "ip")
                human_readable = tableToMarkdown(title, context_entry)

                dbot_score = Common.DBotScore(
                    indicator=ip_to_score,
                    indicator_type=DBotScoreType.IP,
                    integration_name=INTEGRATION_NAME,
                    score=score,
                    reliability=reliability,
                )

                ip_object = Common.IP(ip=ip_to_score, dbot_score=dbot_score)

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarRapidReputation.IP",
                        outputs_key_field="Entity",
                        readable_output=human_readable,
                        raw_response=raw_response,
                        outputs=context_entry,
                        indicator=ip_object,
                    )
                )
            else:
                message = f"Error at scoring IP {ip_to_score}: {raw_response.get('message', 'Unknown error')}"
                command_results_list.append(CommandResults(readable_output=message))
        except ValueError as e:
            command_results_list.append(CommandResults(readable_output=str(e)))
        except Exception as e:
            command_results_list.append(CommandResults(readable_output=f"Error processing IP {ip_to_score}: {str(e)}"))

    if not command_results_list:
        command_results_list = [
            CommandResults(readable_output="SOCRadar Rapid Reputation could not find any results for the given IP(s).")
        ]

    return command_results_list


def domain_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Returns SOCRadar reputation details for the given domain entity."""
    domains = args.get("domain", "")
    domain_list: list = argToList(domains)

    command_results_list: list[CommandResults] = []

    for domain_to_score in domain_list:
        try:
            Validator.raise_if_domain_not_valid(domain_to_score)

            raw_response = client.get_entity_reputation(domain_to_score, "hostname")

            if raw_response.get("is_success"):
                data = raw_response.get("data", {})

                if data.get("is_whitelisted"):
                    score = 1
                elif (api_score := data.get("score")) is not None:
                    score = calculate_dbot_score(api_score)
                else:
                    score = 0

                title = f"SOCRadar Rapid Reputation - Analysis results for Domain: {domain_to_score}"

                context_entry = build_entry_context(raw_response, domain_to_score, "hostname")
                human_readable = tableToMarkdown(title, context_entry)

                dbot_score = Common.DBotScore(
                    indicator=domain_to_score,
                    indicator_type=DBotScoreType.DOMAIN,
                    integration_name=INTEGRATION_NAME,
                    score=score,
                    reliability=reliability,
                )

                domain_object = Common.Domain(domain=domain_to_score, dbot_score=dbot_score)

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarRapidReputation.Domain",
                        outputs_key_field="Entity",
                        readable_output=human_readable,
                        raw_response=raw_response,
                        outputs=context_entry,
                        indicator=domain_object,
                    )
                )
            else:
                message = f"Error at scoring domain {domain_to_score}: {raw_response.get('message', 'Unknown error')}"
                command_results_list.append(CommandResults(readable_output=message))
        except ValueError as e:
            command_results_list.append(CommandResults(readable_output=str(e)))
        except Exception as e:
            command_results_list.append(CommandResults(readable_output=f"Error processing domain {domain_to_score}: {str(e)}"))

    if not command_results_list:
        command_results_list = [
            CommandResults(readable_output="SOCRadar Rapid Reputation could not find any results for the given domain(s).")
        ]

    return command_results_list


def url_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Returns SOCRadar reputation details for the given URL entity."""
    urls = args.get("url", "")
    url_list: list = argToList(urls)

    command_results_list: list[CommandResults] = []

    for url_to_score in url_list:
        try:
            Validator.raise_if_url_not_valid(url_to_score)

            raw_response = client.get_entity_reputation(url_to_score, "url")

            if raw_response.get("is_success"):
                data = raw_response.get("data", {})

                if data.get("is_whitelisted"):
                    score = 1
                elif (api_score := data.get("score")) is not None:
                    score = calculate_dbot_score(api_score)
                else:
                    score = 0

                title = f"SOCRadar Rapid Reputation - Analysis results for URL: {url_to_score}"

                context_entry = build_entry_context(raw_response, url_to_score, "url")
                human_readable = tableToMarkdown(title, context_entry)

                dbot_score = Common.DBotScore(
                    indicator=url_to_score,
                    indicator_type=DBotScoreType.URL,
                    integration_name=INTEGRATION_NAME,
                    score=score,
                    reliability=reliability,
                )

                url_object = Common.URL(url=url_to_score, dbot_score=dbot_score)

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarRapidReputation.URL",
                        outputs_key_field="Entity",
                        readable_output=human_readable,
                        raw_response=raw_response,
                        outputs=context_entry,
                        indicator=url_object,
                    )
                )
            else:
                message = f"Error at scoring URL {url_to_score}: {raw_response.get('message', 'Unknown error')}"
                command_results_list.append(CommandResults(readable_output=message))
        except ValueError as e:
            command_results_list.append(CommandResults(readable_output=str(e)))
        except Exception as e:
            command_results_list.append(CommandResults(readable_output=f"Error processing URL {url_to_score}: {str(e)}"))

    if not command_results_list:
        command_results_list = [
            CommandResults(readable_output="SOCRadar Rapid Reputation could not find any results for the given URL(s).")
        ]

    return command_results_list


def file_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Returns SOCRadar reputation details for the given file hash entity."""
    file_hashes = args.get("file", "")
    file_hash_list: list = argToList(file_hashes)

    command_results_list: list[CommandResults] = []

    for hash_to_score in file_hash_list:
        try:
            Validator.raise_if_hash_not_valid(hash_to_score)
            hash_type = get_hash_type(hash_to_score)

            raw_response = client.get_entity_reputation(hash_to_score, "hash")

            if raw_response.get("is_success"):
                data = raw_response.get("data", {})

                if data.get("is_whitelisted"):
                    score = 1
                elif (api_score := data.get("score")) is not None:
                    score = calculate_dbot_score(api_score)
                else:
                    score = 0

                title = f"SOCRadar Rapid Reputation - Analysis results for Hash: {hash_to_score}"

                context_entry = build_entry_context(raw_response, hash_to_score, "hash")
                human_readable = tableToMarkdown(title, context_entry)

                dbot_score = Common.DBotScore(
                    indicator=hash_to_score,
                    indicator_type=DBotScoreType.FILE,
                    integration_name=INTEGRATION_NAME,
                    score=score,
                    reliability=reliability,
                )

                file_object = Common.File(dbot_score=dbot_score)

                # Set hash based on type
                if hash_type == "sha256":
                    file_object.sha256 = hash_to_score
                elif hash_type == "sha1":
                    file_object.sha1 = hash_to_score
                elif hash_type == "md5":
                    file_object.md5 = hash_to_score

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarRapidReputation.File",
                        outputs_key_field="Entity",
                        readable_output=human_readable,
                        raw_response=raw_response,
                        outputs=context_entry,
                        indicator=file_object,
                    )
                )
            else:
                message = f"Error at scoring file hash {hash_to_score}: {raw_response.get('message', 'Unknown error')}"
                command_results_list.append(CommandResults(readable_output=message))
        except ValueError as e:
            command_results_list.append(CommandResults(readable_output=str(e)))
        except Exception as e:
            command_results_list.append(CommandResults(readable_output=f"Error processing hash {hash_to_score}: {str(e)}"))

    if not command_results_list:
        command_results_list = [
            CommandResults(readable_output="SOCRadar Rapid Reputation could not find any results for the given file hash(es).")
        ]

    return command_results_list


def socradar_bulk_check_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Check reputation for a mixed list of indicators with automatic type detection."""
    indicators = args.get("indicators", "")
    indicator_list: list = argToList(indicators)

    if not indicator_list:
        return [CommandResults(readable_output="No indicators provided.")]

    # Check maximum limit to avoid XSOAR argument/output size limits
    if len(indicator_list) > MAX_BULK_CHECK_INDICATORS:
        error_msg = (
            f"⚠️ **Too Many Indicators!**\n\n"
            f"**Maximum allowed:** {MAX_BULK_CHECK_INDICATORS} indicators\n"
            f"**You provided:** {len(indicator_list)} indicators\n\n"
            f"**Why this limit?**\n"
            f"- XSOAR has command argument size limits (~10KB)\n"
            f"- War Room output size limits (~500KB)\n"
            f"- Context data size limits (~1MB)\n"
            f"- Rate limit: 1 request/second = {MAX_BULK_CHECK_INDICATORS} seconds (~{MAX_BULK_CHECK_INDICATORS/60:.1f} min)\n\n"
            f"**Solution:** Split into batches of {MAX_BULK_CHECK_INDICATORS} or less\n\n"
            f"**Example:**\n"
            f"```\n"
            f'Batch 1: !socradar-bulk-check indicators="[first {MAX_BULK_CHECK_INDICATORS} indicators]"\n'
            f'Batch 2: !socradar-bulk-check indicators="[next {MAX_BULK_CHECK_INDICATORS} indicators]"\n'
            f"```\n\n"
            f"**Recommended:** Use 10-20 indicators per batch for best performance."
        )
        return [CommandResults(readable_output=error_msg)]

    command_results_list: list[CommandResults] = []

    # Warning for large batches (over 50 indicators)
    if len(indicator_list) > 50:
        warning_msg = (
            f"⚠️ **Large Batch Detected**\n\n"
            f"Indicators: {len(indicator_list)}\n"
            f"Estimated time: ~{len(indicator_list)} seconds ({len(indicator_list) / 60:.1f} minutes)\n"
            f"Rate limit: 1 request/second\n\n"
            f"💡 **Tip:** For faster results, use smaller batches (10-20 indicators)."
        )
        command_results_list.append(CommandResults(readable_output=warning_msg))

    summary_data: dict[str, Any] = {
        "total": len(indicator_list),
        "processed": 0,
        "failed": 0,
        "failed_details": [],
        "by_type": {"ip": 0, "hostname": 0, "url": 0, "hash": 0},
        "by_score_range": {"0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0, "whitelisted": 0},
    }

    for idx, indicator in enumerate(indicator_list):
        try:
            # Detect entity type
            entity_type = detect_entity_type(indicator)
            summary_data["by_type"][entity_type] += 1

            # Process the entity
            result = process_entity_by_type(client, indicator, entity_type)

            if result["success"]:
                summary_data["processed"] += 1
                context = result["context"]
                score = context.get("Score", 0) or 0

                # Score range classification
                if context.get("IsWhitelisted"):
                    summary_data["by_score_range"]["whitelisted"] += 1
                    score_range = "Whitelisted"
                elif score >= 76:
                    summary_data["by_score_range"]["76-100"] += 1
                    score_range = "76-100"
                elif score >= 51:
                    summary_data["by_score_range"]["51-75"] += 1
                    score_range = "51-75"
                elif score >= 26:
                    summary_data["by_score_range"]["26-50"] += 1
                    score_range = "26-50"
                else:
                    summary_data["by_score_range"]["0-25"] += 1
                    score_range = "0-25"

                title = f"SOCRadar - {entity_type.upper()}: {indicator}"
                summary_dict = {
                    "Entity": indicator,
                    "Type": entity_type,
                    "Score": score,
                    "ScoreRange": score_range,
                    "IsWhitelisted": context.get("IsWhitelisted", False),
                    "Sources": len(context.get("FindingSources", [])),
                }

                human_readable = tableToMarkdown(title, summary_dict)

                command_results_list.append(
                    CommandResults(
                        outputs_prefix="SOCRadarRapidReputation.BulkCheck",
                        outputs_key_field="Entity",
                        readable_output=human_readable,
                        raw_response=result["raw_response"],
                        outputs=context,
                    )
                )
            else:
                summary_data["failed"] += 1
                error_reason = result.get("error", "Unknown error")
                summary_data["failed_details"].append({"Entity": indicator, "Reason": error_reason})
                error_msg = f"❌ Failed: {indicator} - {error_reason}"
                command_results_list.append(CommandResults(readable_output=error_msg))

        except Exception as e:
            summary_data["failed"] += 1
            error_reason = str(e)
            summary_data["failed_details"].append({"Entity": indicator, "Reason": error_reason})
            error_msg = f"❌ Error: {indicator} - {error_reason}"
            command_results_list.append(CommandResults(readable_output=error_msg))

        # Rate limiting: 1 request per second
        # Sleep after each request except the last one
        if idx < len(indicator_list) - 1:
            time.sleep(1)

    # Build summary with score ranges
    summary_table_data = [
        {"Metric": "Total Indicators", "Count": summary_data["total"]},
        {"Metric": "Successfully Processed", "Count": summary_data["processed"]},
        {"Metric": "Failed", "Count": summary_data["failed"]},
        {"Metric": "─" * 20, "Count": "─" * 5},
        {"Metric": "Score 76-100", "Count": summary_data["by_score_range"]["76-100"]},
        {"Metric": "Score 51-75", "Count": summary_data["by_score_range"]["51-75"]},
        {"Metric": "Score 26-50", "Count": summary_data["by_score_range"]["26-50"]},
        {"Metric": "Score 0-25", "Count": summary_data["by_score_range"]["0-25"]},
        {"Metric": "Whitelisted", "Count": summary_data["by_score_range"]["whitelisted"]},
    ]

    summary_table = tableToMarkdown("📊 Bulk Check Summary", summary_table_data)

    # Add failed details if any
    if summary_data["failed_details"]:
        failed_table = tableToMarkdown("❌ Failed Indicators", summary_data["failed_details"], headers=["Entity", "Reason"])
        summary_table += "\n\n" + failed_table

    command_results_list.insert(
        0,
        CommandResults(
            outputs_prefix="SOCRadarRapidReputation.BulkCheckSummary", readable_output=summary_table, outputs=summary_data
        ),
    )

    return command_results_list


def socradar_reputation_command(client: Client, args: dict[str, Any], reliability: str = None) -> list[CommandResults]:
    """Generic reputation check for any entity type."""
    entity_value = args.get("entity_value")
    entity_type = args.get("entity_type")

    if not entity_value or not entity_type:
        return [CommandResults(readable_output="Both entity_value and entity_type are required.")]

    command_results_list: list[CommandResults] = []

    try:
        raw_response = client.get_entity_reputation(entity_value, entity_type)

        if raw_response.get("is_success"):
            data = raw_response.get("data", {})

            if data.get("is_whitelisted"):
                score = 1
            elif (api_score := data.get("score")) is not None:
                score = calculate_dbot_score(api_score)
            else:
                score = 0

            title = f"SOCRadar Rapid Reputation - Analysis for {entity_type.upper()}: {entity_value}"

            context_entry = build_entry_context(raw_response, entity_value, entity_type)
            human_readable = tableToMarkdown(title, context_entry)

            # Determine DBot type based on entity_type
            if entity_type == "ip":
                dbot_type = DBotScoreType.IP
            elif entity_type == "hostname":
                dbot_type = DBotScoreType.DOMAIN
            elif entity_type == "url":
                dbot_type = DBotScoreType.URL
            elif entity_type == "hash":
                dbot_type = DBotScoreType.FILE
            else:
                dbot_type = DBotScoreType.IP  # default

            dbot_score = Common.DBotScore(
                indicator=entity_value,
                indicator_type=dbot_type,
                integration_name=INTEGRATION_NAME,
                score=score,
                reliability=demisto.params().get("integrationReliability"),
            )

            # Initialize indicator_object with Union type
            indicator_object: Common.IP | Common.Domain | Common.URL | Common.File | None = None

            # Create appropriate indicator object based on entity type
            if entity_type == "ip":
                indicator_object = Common.IP(ip=entity_value, dbot_score=dbot_score)
            elif entity_type == "hostname":
                indicator_object = Common.Domain(domain=entity_value, dbot_score=dbot_score)
            elif entity_type == "url":
                indicator_object = Common.URL(url=entity_value, dbot_score=dbot_score)
            elif entity_type == "hash":
                indicator_object = Common.File(dbot_score=dbot_score)
                hash_type = get_hash_type(entity_value)
                if hash_type == "sha256":
                    indicator_object.sha256 = entity_value
                elif hash_type == "sha1":
                    indicator_object.sha1 = entity_value
                elif hash_type == "md5":
                    indicator_object.md5 = entity_value
            else:
                indicator_object = None

            command_results_list.append(
                CommandResults(
                    outputs_prefix="SOCRadarRapidReputation.Reputation",
                    outputs_key_field="Entity",
                    readable_output=human_readable,
                    raw_response=raw_response,
                    outputs=context_entry,
                    indicator=indicator_object,
                )
            )
        else:
            message = f"Error checking {entity_type} {entity_value}: {raw_response.get('message', 'Unknown error')}"
            command_results_list.append(CommandResults(readable_output=message))
    except Exception as e:
        command_results_list.append(CommandResults(readable_output=f"Error: {str(e)}"))

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

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy)
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
        elif command == "socradar-reputation":
            demisto.debug("Executing socradar-reputation command")
            return_results(socradar_reputation_command(client, demisto.args(), reliability))
        elif command == "socradar-bulk-check":
            demisto.debug("Executing socradar-bulk-check command")
            return_results(socradar_bulk_check_command(client, demisto.args()))
        else:
            demisto.debug(f"Unknown command: {command}")
            return_error(f"Command {command} is not supported")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
