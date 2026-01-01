import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

""" IMPORTS """

import json
import traceback
from collections.abc import Callable, Collection
from typing import Any

import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

# Integration information
INTEGRATION_NAME = "Analyst1"
INTEGRATION_CONTEXT_BRAND = "Analyst1"
MALICIOUS_DATA: dict[str, str] = {
    "Vendor": "Analyst1",
    "Description": "Analyst1 advises assessing the Indicator attributes for malicious context.",
}

# XSOAR Verdict mappings
XSOAR_VERDICT_SCORES: dict[str, int] = {
    "Unknown": 0,
    "Benign": 1,
    "Suspicious": 2,
    "Malicious": 3,
}

# Default Risk Score to XSOAR Verdict mappings
DEFAULT_RISK_SCORE_MAPPINGS: dict[str, str] = {
    "Lowest": "Benign",
    "Low": "Unknown",
    "Moderate": "Suspicious",
    "High": "Suspicious",
    "Critical": "Malicious",
    "Unknown": "Unknown",
}

# Entity type to XSOAR tag mappings for batchCheck (using entity.key values)
ENTITY_TYPE_TAGS: dict[str, str] = {
    "ASSET": "Analyst1: Asset",
    "IN_SYSTEM_RANGE": "Analyst1: In System Range",
    "IN_HOME_RANGE": "Analyst1: In Home Range",
    "IN_PRIVATE_RANGE": "Analyst1: In Private Range",
    "IGNORED_INDICATOR": "Analyst1: Ignored Indicator",
    "IGNORED_ASSET": "Analyst1: Ignored Asset",
    "INDICATOR": "Analyst1: Indicator",
}

# Benign entity keys for verdict calculation
BENIGN_ENTITY_KEYS: list[str] = [
    "ASSET",
    "IN_SYSTEM_RANGE",
    "IN_HOME_RANGE",
    "IN_PRIVATE_RANGE",
    "IGNORED_INDICATOR",
    "IGNORED_ASSET",
]

# Analyst1 indicator type to XSOAR indicator type mappings
ANALYST1_TO_XSOAR_TYPE: dict[str, str] = {
    "domain": "domain",
    "ip": "ip",
    "ipv6": "ipv6",
    "email": "email",
    "file": "file",
    "url": "url",
    "string": "string",
    "mutex": "mutex",
    "httpRequest": "url",  # Map httpRequest to url in XSOAR
    "stixPattern": "string",  # Map stixPattern to string in XSOAR
    "commandLine": "string",  # Map commandLine to string in XSOAR
}

""" HELPER FUNCTIONS """


def get_risk_score_mappings(params: dict) -> dict[str, int]:
    """
    Retrieves risk score to XSOAR verdict score mappings from integration configuration.

    Args:
        params: Integration configuration parameters from demisto.params()

    Returns:
        Dictionary mapping Analyst1 risk score names to XSOAR verdict scores (0-3)
    """
    mappings = {}

    for risk_level in ["Lowest", "Low", "Moderate", "High", "Critical", "Unknown"]:
        param_name = f"riskScore{risk_level}"
        verdict_name = params.get(param_name, DEFAULT_RISK_SCORE_MAPPINGS[risk_level])
        mappings[risk_level] = XSOAR_VERDICT_SCORES.get(verdict_name, 0)

    return mappings


def calculate_verdict_from_risk_score(risk_score: str | None, benign_value: bool | None, params: dict) -> int:
    """
    Calculates XSOAR verdict score based on Analyst1 risk score and benign flag.

    Priority logic:
    1. If benign=True, always return Benign (1)
    2. If risk score is available, map it using configuration
    3. Otherwise return Unknown (0)

    Args:
        risk_score: Analyst1 risk score value (Lowest, Low, Moderate, High, Critical, Unknown)
        benign_value: Analyst1 benign flag value
        params: Integration configuration parameters

    Returns:
        XSOAR verdict score: 0=Unknown, 1=Benign, 2=Suspicious, 3=Malicious
    """
    # Priority 1: benign=True always results in Benign verdict
    if benign_value is True:
        return 1  # Benign

    # Priority 2: Map risk score to verdict using configuration
    if risk_score:
        mappings = get_risk_score_mappings(params)
        return mappings.get(risk_score, 0)  # Default to Unknown if risk_score not recognized

    # Priority 3: No risk score available, return Unknown
    return 0  # Unknown


def get_nested_value(data: dict, key: str, nested_key: str) -> Any | None:
    """
    Safely retrieves a nested value from a dictionary.

    Args:
        data: The dictionary to search
        key: Top-level key
        nested_key: Nested key within the top-level value

    Returns:
        The nested value if found, otherwise None
    """
    top_level = data.get(key)
    if isinstance(top_level, dict):
        return top_level.get(nested_key)
    return None


def get_analyst1_tags_for_batch_result(results_for_indicator: list[dict]) -> list[str]:
    """
    Determines which Analyst1 tags should be applied to an indicator based on batch check results.

    An indicator can have multiple entity types (e.g., both "Asset" and "In Home Range"),
    so this function collects all applicable tags from all results for the same indicator.

    Args:
        results_for_indicator: List of batch check result objects for a single indicator

    Returns:
        List of tag strings that should be applied (e.g., ["Analyst1: Asset", "Analyst1: Indicator"])
    """
    tags = set()

    for result in results_for_indicator:
        entity = result.get("entity", {})
        entity_key = entity.get("key") if isinstance(entity, dict) else None
        if entity_key and entity_key in ENTITY_TYPE_TAGS:
            tags.add(ENTITY_TYPE_TAGS[entity_key])

    return list(tags)


def get_xsoar_indicator_type_from_batch_result(result: dict) -> str:
    """
    Determines the XSOAR indicator type from a batch check result.

    Args:
        result: A single batch check result object

    Returns:
        XSOAR indicator type string (e.g., "email", "ip", "domain")
        Returns "unknown" if the type cannot be determined
    """
    analyst1_type = get_nested_value(result, "type", "key")
    if analyst1_type and analyst1_type in ANALYST1_TO_XSOAR_TYPE:
        return ANALYST1_TO_XSOAR_TYPE[analyst1_type]
    return "unknown"


def calculate_batch_check_verdict(entity_key: str | None, risk_score: str | None, benign_value: bool | None, params: dict) -> int:
    """
    Calculates XSOAR verdict score for batchCheck results based on entity.key, risk score, and benign flag.

    Priority logic:
    1. If benign=True, always return Benign (1)
    2. If entity.key is ASSET/IN_SYSTEM_RANGE/IN_HOME_RANGE/IN_PRIVATE_RANGE/IGNORED_INDICATOR/IGNORED_ASSET → Benign (1)
    3. If entity.key is INDICATOR and risk score exists, map it using configuration
    4. If risk score is null, return Unknown (0)

    Args:
        entity_key: Analyst1 entity.key value from batchCheck response
        risk_score: Analyst1 risk score value (Lowest, Low, Moderate, High, Critical, Unknown)
        benign_value: Analyst1 benign flag value
        params: Integration configuration parameters

    Returns:
        XSOAR verdict score: 0=Unknown, 1=Benign, 2=Suspicious, 3=Malicious
    """
    # Priority 1: benign=True always results in Benign verdict
    if benign_value is True:
        return 1  # Benign

    # Priority 2: Check entity.key for benign categories
    if entity_key and entity_key in BENIGN_ENTITY_KEYS:
        return 1  # Benign

    # Priority 3: If entity.key is "INDICATOR", use risk score mapping
    if entity_key and entity_key == "INDICATOR":
        if risk_score:
            mappings = get_risk_score_mappings(params)
            return mappings.get(risk_score, 0)  # Default to Unknown if risk_score not recognized
        else:
            # If indicatorRiskScore is null, return Unknown
            return 0  # Unknown

    # Priority 4: Default to Unknown for any other case
    return 0  # Unknown


def find_indicator_in_batch_results(results_for_search_value: list[dict], expected_type: str) -> dict | None:
    """
    Finds an INDICATOR entity in batch check results that matches the expected indicator type.

    Args:
        results_for_search_value: All batch check results for a single search value
        expected_type: Expected Analyst1 indicator type (e.g., "domain", "email", "ip", "file")

    Returns:
        The batch check result dict for the matching INDICATOR, or None if not found
    """
    for result in results_for_search_value:
        entity_key = get_nested_value(result, "entity", "key")
        type_key = get_nested_value(result, "type", "key")

        if entity_key == "INDICATOR" and type_key == expected_type:
            return result

    return None


def has_benign_entity_type(results_for_search_value: list[dict]) -> bool:
    """
    Checks if ANY result for a search value has a benign entity type.

    Args:
        results_for_search_value: All batch check results for a single search value

    Returns:
        True if any result has a benign entity type, False otherwise
    """
    for result in results_for_search_value:
        # Check benign=True (handle both dict and direct boolean)
        benign_data = result.get("benign")
        if isinstance(benign_data, dict):
            benign_value = benign_data.get("value")
        else:
            benign_value = benign_data

        if benign_value is True:
            return True

        # Check benign entity types
        entity_key = get_nested_value(result, "entity", "key")
        if entity_key and entity_key in BENIGN_ENTITY_KEYS:
            return True

    return False


def process_batch_check_results(results_list: list[dict]) -> list[dict]:
    """
    Processes batch check results by grouping by searchedValue, calculating verdicts,
    and adding DBotScore and tags to each result.

    This is the shared logic used by both analyst1_batch_check_command and analyst1_batch_check_post
    to process batch check API responses consistently.

    Args:
        results_list: List of raw batch check result objects from the API

    Returns:
        The same list of results with DBotScore and Tags fields added to each result
    """
    # Group results by searchedValue (the actual value searched) to handle multiple entity types per indicator
    # Note: matchedValue can be a regex pattern, searchedValue is always the literal searched value
    # We ONLY group by searchedValue - never fall back to matchedValue as it would be incorrect
    results_by_indicator: dict[str, list[dict]] = {}
    for result in results_list:
        searched_value = result.get("searchedValue")
        if searched_value:  # Only process results with searchedValue
            if searched_value not in results_by_indicator:
                results_by_indicator[searched_value] = []
            results_by_indicator[searched_value].append(result)

    # Process each unique indicator
    for matched_value, indicator_results in results_by_indicator.items():
        # Determine tags for this indicator across all its entity types
        tags = get_analyst1_tags_for_batch_result(indicator_results)

        # Calculate verdict (use first result - they should have same verdict logic per indicator)
        first_result = indicator_results[0]
        risk_score = get_nested_value(first_result, "indicatorRiskScore", "title")

        # Handle benign field - can be either a dict with "value" key or a direct boolean
        benign_data = first_result.get("benign")
        if isinstance(benign_data, dict):
            benign_value = benign_data.get("value")
        else:
            benign_value = benign_data

        entity_key = get_nested_value(first_result, "entity", "key")

        # Calculate verdict score based on entity.key and risk score
        verdict_score = calculate_batch_check_verdict(entity_key, risk_score, benign_value, demisto.params())

        # Get the XSOAR indicator type from the batch check result
        indicator_type = get_xsoar_indicator_type_from_batch_result(first_result)

        # Create DBotScore and indicator context with tags
        dbot_score = {
            "Indicator": matched_value,
            "Score": verdict_score,
            "Type": indicator_type,
            "Vendor": INTEGRATION_NAME,
            "Reliability": demisto.params().get("integrationReliability"),
        }

        # Add DBotScore and tags to all results for this indicator
        for result in indicator_results:
            result["DBotScore"] = dbot_score
            result["Tags"] = tags

    return results_list


def enrich_with_batch_check(
    client: "Client",
    indicator_value: str,
    indicator_type: str,
    primary_key: str,
    reputation_key: str,
    extra_context: dict | None = None,
) -> "EnrichmentOutput":
    """
    Unified enrichment with batch-check-first approach for standard reputation commands.

    Handles three scenarios based on batch check results (batch check is authoritative):
    1. No batch results → indicator doesn't exist, return empty EnrichmentOutput
    2. Batch results + INDICATOR entity → full enrichment with risk scores + batch tags
    3. Batch results + non-INDICATOR entities → minimal benign context + entity tags

    Args:
        client: Analyst1 API client
        indicator_value: The indicator value to enrich (e.g., "user@example.com")
        indicator_type: Analyst1 indicator type (e.g., "email", "ip", "domain", "file", "url")
        primary_key: Key for reputation context (e.g., "From", "Address", "Name", "Data", hash type)
        reputation_key: XSOAR reputation key (e.g., "Email", "IP", "Domain", "URL", "File")
        extra_context: Additional context to add to reputation (optional, used for domain DNS resolution)

    Returns:
        EnrichmentOutput with tags and reputation context properly set
    """
    # Step 1: Call batch check to determine if indicator exists and get entity classification
    batch_raw_data = client.post_batch_search(indicator_value)

    # DEBUG: Log what we got from batch check
    demisto.debug(
        f"enrich_with_batch_check: indicator_value={indicator_value}, batch_raw_data keys={list(batch_raw_data.keys())}"
    )

    # Step 2: Get all results from batch check
    all_results = batch_raw_data.get("results", [])

    # Step 3: Filter by searchedValue to prevent tag pollution from regex matches
    # (matchedValue can be regex like "*@company.com", searchedValue is the literal searched value)
    # If searchedValue doesn't exist in results, use all results (for backwards compatibility)
    results_for_indicator = [r for r in all_results if r.get("searchedValue") == indicator_value]

    # If no results matched by searchedValue but we have results, check if searchedValue field exists
    # If it doesn't exist in the API response, fall back to using all results
    if not results_for_indicator and all_results:
        # Check if searchedValue field exists in any result
        has_searched_value_field = any("searchedValue" in r for r in all_results)
        if not has_searched_value_field:
            # Field doesn't exist in API response - use all results
            results_for_indicator = all_results

    # CASE 1: No batch results → indicator doesn't exist in Analyst1
    if not results_for_indicator:
        # Return empty EnrichmentOutput (no indicator found)
        return EnrichmentOutput({}, {}, indicator_type, indicator_value)

    # Step 3: Collect tags from all entity types for this indicator (only if tagging is enabled)
    apply_tags = demisto.params().get("applyTags", False)
    tags = get_analyst1_tags_for_batch_result(results_for_indicator) if apply_tags else []

    # Step 4: Check if ANY entity is a benign type (ASSET, IN_HOME_RANGE, etc.)
    has_benign = has_benign_entity_type(results_for_indicator)

    # Step 5: Find INDICATOR entity matching the expected type
    indicator_result = find_indicator_in_batch_results(results_for_indicator, indicator_type)

    # CASE 2: INDICATOR entity exists → get full enrichment details
    if indicator_result:
        enrichment_data = client.enrich_indicator(indicator_value, indicator_type)

        # Log if enrichment data is unexpectedly empty for debugging
        if not enrichment_data.has_context_data():
            demisto.debug(
                f"WARNING: Batch check found INDICATOR but enrichment returned no data: "
                f"indicator_value={indicator_value}, indicator_type={indicator_type}, "
                f"raw_data keys={list(enrichment_data.raw_data.keys())}"
            )

        # If benign entities exist alongside INDICATOR, override verdict to Benign
        # This handles cases where an indicator is both a threat indicator AND an asset/private range
        verdict_override = 1 if has_benign else None  # 1 = Benign

        # ALWAYS generate reputation context for INDICATOR entities, even if enrichment data is empty
        # This ensures DBotScore and tags are set properly from batch check results
        if enrichment_data.has_context_data():
            # Full enrichment available - use it
            enrichment_data.generate_reputation_context(
                primary_key,
                indicator_value,
                indicator_type,
                reputation_key,
                extra_context=extra_context,
                verdict_score_override=verdict_override,
                tags_override=tags if apply_tags else None,
            )
        else:
            # No enrichment data but indicator exists in batch check - create minimal indicator with verdict from batch
            # Calculate verdict from batch check result
            risk_score = get_nested_value(indicator_result, "indicatorRiskScore", "title")
            benign_data = indicator_result.get("benign")
            if isinstance(benign_data, dict):
                benign_value = benign_data.get("value")
            else:
                benign_value = benign_data

            entity_key = get_nested_value(indicator_result, "entity", "key")
            verdict_score = calculate_batch_check_verdict(entity_key, risk_score, benign_value, demisto.params())
            if verdict_override is not None:
                verdict_score = verdict_override

            # Set verdict and tags manually
            enrichment_data.verdict_score = verdict_score
            enrichment_data.indicator_value = indicator_value
            enrichment_data.tags = tags if (apply_tags and len(tags) > 0) else ["Analyst1: Indicator"]

            # Create reputation context
            reputation_context = {primary_key: indicator_value}
            if extra_context:
                reputation_context.update(extra_context)
            enrichment_data.add_reputation_context(
                f"{reputation_key}(val.{primary_key} && val.{primary_key} === obj.{primary_key})", reputation_context
            )

        return enrichment_data

    # CASE 3: Non-INDICATOR entities only (ASSET, ranges, etc.) → create minimal benign indicator
    # Get entity type names for human-readable classification
    entity_types = []
    for result in results_for_indicator:
        entity_key = get_nested_value(result, "entity", "key")
        if entity_key and entity_key in ENTITY_TYPE_TAGS:
            # Extract just the classification name (e.g., "Ignored Indicator" from "Analyst1: Ignored Indicator")
            entity_type_name = ENTITY_TYPE_TAGS[entity_key].replace("Analyst1: ", "")
            if entity_type_name not in entity_types:
                entity_types.append(entity_type_name)

    # If no recognizable entity types found, treat as non-existent (return empty like CASE 1)
    if not entity_types:
        return EnrichmentOutput({}, {}, indicator_type, indicator_value)

    # Create minimal analyst1_context_data for human-readable output
    minimal_context = {"Indicator": indicator_value, "Classification": ", ".join(entity_types)}
    enrichment_data = EnrichmentOutput(minimal_context, {}, indicator_type, indicator_value)

    # Always set enrichment_data.tags to enable proper output (even if empty list)
    # This ensures the indicator appears in the war room
    enrichment_data.tags = tags if apply_tags else []

    # Create DBotScore and reputation context for non-INDICATOR entities
    # These should appear as benign indicators in XSOAR with entity-type tags
    verdict_score = 1  # Benign

    # Store verdict score for Common.Indicator creation
    enrichment_data.verdict_score = verdict_score

    # Create reputation context
    reputation_context = {primary_key: indicator_value}
    if extra_context:
        reputation_context.update(extra_context)

    # DO NOT add Tags to reputation_context - tags are ONLY in the Common.Indicator object
    # Adding them here causes XSOAR to create a duplicate indicator entry

    enrichment_data.add_reputation_context(
        f"{reputation_key}(val.{primary_key} && val.{primary_key} === obj.{primary_key})", reputation_context
    )

    return enrichment_data


class IdNamePair:
    def __init__(self, unique_id: int, name: str):
        self.id = unique_id
        self.name = name

    def __str__(self):
        return f"id = {self.id}, name = {self.name}"


class EnrichmentOutput:
    def __init__(
        self, analyst1_context_data: dict, raw_data: dict, indicator_type: str, indicator_value: str | None = None
    ) -> None:
        self.analyst1_context_data = analyst1_context_data
        self.raw_data = raw_data
        self.indicator_type = indicator_type
        self.indicator_value = indicator_value
        self.reputation_context: dict = {}
        self.tags: list[str] | None = None
        self.verdict_score: int | None = None  # Store verdict score for Common.Indicator creation

    def get_human_readable_output(self) -> str:
        human_readable_data = self.analyst1_context_data.copy()

        # Only process Actors and Malwares if they exist in the data
        if "Actors" in human_readable_data:
            human_readable_data["Actors"] = [IdNamePair(d["id"], d["name"]) for d in human_readable_data["Actors"]]
        if "Malwares" in human_readable_data:
            human_readable_data["Malwares"] = [IdNamePair(d["id"], d["name"]) for d in human_readable_data["Malwares"]]

        # Add tags to human-readable output if they exist
        if self.tags:
            human_readable_data["XSOAR Tags"] = ", ".join(self.tags)

        return tableToMarkdown(
            t=human_readable_data, name=f"{INTEGRATION_NAME} {self.indicator_type.capitalize()} Information", removeNull=True
        )

    def build_analyst1_context(self) -> dict:
        return {
            f"{INTEGRATION_CONTEXT_BRAND}.{self.indicator_type.capitalize()}(val.ID && val.ID === obj.ID)":  # type: ignore
            self.analyst1_context_data
        }

    def generate_reputation_context(
        self,
        primary_key: str,
        indicator_value: str,
        indicator_type: str,
        reputation_key: str,
        extra_context: dict | None = None,
        verdict_score_override: int | None = None,
        tags_override: list[str] | None = None,
    ):
        if self.has_context_data():
            reputation_context: dict[str, Any] = {primary_key: indicator_value}

            if extra_context is not None:
                reputation_context.update(extra_context)

            # Use verdict override if provided, otherwise calculate from indicator data
            if verdict_score_override is not None:
                verdict_score = verdict_score_override
            else:
                # Calculate verdict using risk score-based logic from indicator/match response
                risk_score = Client.get_nested_data_key(self.raw_data, "indicatorRiskScore", "name")
                benign_value = Client.get_nested_data_key(self.raw_data, "benign", "value")
                verdict_score = calculate_verdict_from_risk_score(risk_score, benign_value, demisto.params())

            # Store verdict score AND indicator_value for Common.Indicator creation
            self.verdict_score = verdict_score
            self.indicator_value = indicator_value  # Store for _create_common_indicator_with_tags()

            # Use tags override if provided (and not empty), otherwise use default "Analyst1: Indicator" tag
            tags = tags_override if (tags_override is not None and len(tags_override) > 0) else ["Analyst1: Indicator"]

            # Store tags for human-readable output and Common.Indicator creation
            self.tags = tags

            # DO NOT add Tags to reputation_context - tags are ONLY in the Common.Indicator object
            # Adding them here causes XSOAR to create a duplicate indicator entry

            # Only add Malicious context if verdict is Malicious (score 3)
            if verdict_score == 3:
                reputation_context["Malicious"] = MALICIOUS_DATA

            self.add_reputation_context(
                f"{reputation_key}(val.{primary_key} && val.{primary_key} === obj.{primary_key})", reputation_context
            )

    def build_all_context(self) -> dict:
        all_context = {}
        all_context.update(self.build_analyst1_context())
        if len(self.reputation_context) > 0:
            all_context.update(self.reputation_context)

        return all_context

    def return_outputs(self):
        # CASE 1: No reputation context means indicator doesn't exist
        if len(self.reputation_context) == 0:
            if self.indicator_value:
                message = f'{self.indicator_type.capitalize()} "{self.indicator_value}" was not found in Analyst1.'
            else:
                message = ""
            return_results(CommandResults(readable_output=message))
            return

        # CASE 2: Always use CommandResults with Common.Indicator (like VirusTotal V3)
        # DBotScore is ONLY embedded in the Common.Indicator object, never in reputation_context
        indicator_obj = self._create_common_indicator_with_tags()
        if indicator_obj:
            # For standard indicators (Email, IP, Domain, URL, File): include outputs context
            results = CommandResults(
                indicator=indicator_obj,
                readable_output=self.get_human_readable_output(),
                outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.{self.indicator_type.capitalize()}",
                outputs_key_field="ID",
                outputs=self.analyst1_context_data if self.has_context_data() else None,
                raw_response=self.raw_data,
            )
            return_results(results)
        else:
            # Fallback if Common.Indicator creation fails - should never happen
            entry = {
                "Type": entryTypes["note"],
                "HumanReadable": self.get_human_readable_output(),
                "ContentsFormat": formats["json"],
                "Contents": self.raw_data,
                "EntryContext": self.build_all_context(),
                "IgnoreAutoExtract": True,
            }
            demisto.results(entry)

    def _create_common_indicator_with_tags(self) -> Common.Indicator | None:
        """
        Creates a Common indicator object with tags to properly set indicator tags in XSOAR.

        Returns:
            A Common indicator object (IP, Domain, Email, URL, or File) with tags, or None if creation fails
        """
        # Use stored verdict_score and indicator_value
        if self.verdict_score is None or not self.indicator_value:
            return None

        indicator_value = self.indicator_value

        # Map indicator type string to DBotScoreType enum
        # Note: IPv6 uses DBotScoreType.IP (there is no separate IPV6 type in XSOAR)
        indicator_type_str = self.indicator_type.lower()
        type_map = {
            "email": DBotScoreType.EMAIL,
            "ip": DBotScoreType.IP,
            "ipv6": DBotScoreType.IP,  # IPv6 uses the same IP type as IPv4
            "domain": DBotScoreType.DOMAIN,
            "url": DBotScoreType.URL,
            "file": DBotScoreType.FILE,
        }

        dbot_type = type_map.get(indicator_type_str, DBotScoreType.IP)

        # Create DBotScore object using stored verdict_score
        dbot_score = Common.DBotScore(
            indicator=indicator_value,
            indicator_type=dbot_type,
            score=self.verdict_score,
            integration_name=INTEGRATION_NAME,
            reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                demisto.params().get("integrationReliability", "B - Usually reliable")
            ),
        )

        # Create the appropriate Common indicator object based on type with tags
        indicator_type = self.indicator_type.lower()

        # Pass tags as list (like Anomali ThreatStream v3)
        # Use self.tags if it exists and is not None (even if empty list)
        tags_list = self.tags if self.tags is not None else None

        if indicator_type == "email":
            return Common.EMAIL(address=indicator_value, dbot_score=dbot_score, tags=tags_list)

        elif indicator_type == "ip" or indicator_type == "ipv6":
            return Common.IP(ip=indicator_value, dbot_score=dbot_score, tags=tags_list)

        elif indicator_type == "domain":
            return Common.Domain(domain=indicator_value, dbot_score=dbot_score, tags=tags_list)

        elif indicator_type == "url":
            return Common.URL(url=indicator_value, dbot_score=dbot_score, tags=tags_list)

        elif indicator_type == "file":
            # Determine hash type and create File object accordingly
            hash_type = get_hash_type(indicator_value)
            if hash_type == "md5":
                return Common.File(md5=indicator_value, dbot_score=dbot_score, tags=tags_list)
            elif hash_type == "sha1":
                return Common.File(sha1=indicator_value, dbot_score=dbot_score, tags=tags_list)
            elif hash_type == "sha256":
                return Common.File(sha256=indicator_value, dbot_score=dbot_score, tags=tags_list)

        # Custom indicator types (string, mutex, httprequest) are now handled by separate commands
        # that return CommandResults directly, so they should never reach this method
        return None

    def add_analyst1_context(self, key: str, data: Any):
        self.analyst1_context_data[key] = data

    def add_reputation_context(self, key: str, context: dict):
        self.reputation_context[key] = context

    def has_context_data(self):
        return len(self.analyst1_context_data) > 0


class Client(BaseClient):
    def __init__(self, server: str, username: str, password: str, insecure: bool, proxy: bool):
        super().__init__(base_url=f"https://{server}/api/1_0/", verify=not insecure, proxy=proxy, auth=(username, password))

    def indicator_search(self, indicator_type: str, indicator: str) -> dict:
        params = {"type": indicator_type, "value": indicator}
        return self._http_request(method="GET", url_suffix="indicator/match", params=params)

    def post_evidence(
        self, fileName: str, fileContent: str, fileEntryId: str, evidenceFileClassification: str, tlp: str, sourceId: str
    ) -> dict:
        data_to_submit = {"evidenceFileClassification": evidenceFileClassification, "tlp": tlp, "sourceId": sourceId}

        evidence_to_submit = None
        if fileContent is not None and fileContent and str(fileContent):
            # encode as UTF-8 to follow Python coding best practices; it works without the encode command
            evidence_to_submit = {"evidenceFile": (fileName, str(fileContent).encode("utf-8"))}
        elif fileEntryId is not None and fileEntryId:
            try:
                filePathToUploadToA1 = demisto.getFilePath(fileEntryId)
                evidenceOpened = open(filePathToUploadToA1["path"], "rb")
                # rb for read binary is default
                evidence_to_submit = {"evidenceFile": (fileName, evidenceOpened.read())}
                # close what was read into the submission to allow good file system management
                evidenceOpened.close()
            except ValueError as vale:
                raise DemistoException("Possibly invalid File.EntryID provided to submission: " + fileEntryId, vale)

        if evidence_to_submit is None:
            raise DemistoException("either fileContent or fileEntryId must be specified to submit Evidence")

        x = requests.post(self._base_url + "evidence", files=evidence_to_submit, data=data_to_submit, auth=self._auth)
        if x is not None and x.status_code == 200:
            return x.json()
        elif x is None:
            return {"message": "Empty response"}
        else:
            return {"message": "Error occurred. Status Code: " + str(x.status_code) + " Text: " + x.text}

    def get_evidence_status(self, uuid: str) -> dict:
        x = requests.get(self._base_url + "evidence/uploadStatus/" + uuid, auth=self._auth)
        if x is None:
            return {"message": "Empty response"}
        elif x.status_code == 404:
            # convert general {"message":"Process not found."} to a better message
            return {"message": "UUID " + uuid + " not known to this Analyst1 instance"}
        elif x.status_code == 200:
            return x.json()
        else:
            return {"message": "Error occurred. Status Code: " + str(x.status_code) + " Text: " + x.text}

    def get_batch_search(self, indicator_values_as_csv: str) -> dict:
        params = {"values": indicator_values_as_csv}
        return self._http_request(method="GET", url_suffix="batchCheck", params=params)

    def post_batch_search(self, indicator_values_as_file: str) -> dict:
        values_to_submit = {"values": indicator_values_as_file}
        # more data here for future maintainers: https://www.w3schools.com/python/module_requests.asp
        x = requests.post(self._base_url + "batchCheck", files=values_to_submit, auth=self._auth)
        # need to check status here or error
        if x is not None and x.status_code == 200:
            return x.json()
        elif x is None:
            return {"message": "Empty response"}
        else:
            return {"message": "Error occurred. Status Code: " + str(x.status_code) + " Text: " + x.text}

    def get_sensors(self, page: int, pageSize: int):
        raw_data: dict = self._http_request(method="GET", url_suffix="sensors?page=" + str(page) + "&pageSize=" + str(pageSize))
        return raw_data

    def get_sensor_taskings(self, sensor: str, timeout_input: int):
        if timeout_input is None:
            timeout_input = 500
        raw_data: dict = self._http_request(
            method="GET", timeout=int(timeout_input), url_suffix="sensors/" + sensor + "/taskings"
        )
        return raw_data

    def get_sensor_config(self, sensor: str) -> str:
        return self._http_request(method="GET", resp_type="text", url_suffix="sensors/" + sensor + "/taskings/config")

    def get_sensor_diff(self, sensor: str, version: str, timeout_input: int):
        if timeout_input is None:
            timeout_input = 500
        raw_data: dict = self._http_request(
            method="GET", timeout=int(timeout_input), url_suffix="sensors/" + sensor + "/taskings/diff/" + version
        )
        # if raw_data is not None:
        return raw_data

    def perform_test_request(self):
        data: dict = self._http_request(method="GET", url_suffix="")
        if data.get("links") is None:
            raise DemistoException("Invalid URL or Credentials. JSON structure not recognized.")

    def enrich_indicator(self, indicator: str, indicator_type: str) -> EnrichmentOutput:
        raw_data: dict = self.indicator_search(indicator_type, indicator)
        if raw_data is None:
            return EnrichmentOutput({}, {}, indicator_type, indicator)

        context_data = self.get_context_from_response(raw_data)
        return EnrichmentOutput(context_data, raw_data, indicator_type)

    def get_indicator(self, ioc_id: str):
        if ioc_id is not None and ioc_id and type(ioc_id) is str:
            # remove unnwanted suffix for hash ids
            ioc_id = ioc_id.split("-")[0].split("_")[0]
        return self._http_request(method="GET", url_suffix="indicator/" + str(ioc_id))

    @staticmethod
    def get_data_key(data: dict, key: str) -> Any | None:
        return data.get(key, None)

    @staticmethod
    def get_nested_data_key(data: dict, key: str, nested_key: str) -> Any | None:
        top_level = Client.get_data_key(data, key)
        return None if top_level is None or nested_key not in top_level else top_level[nested_key]

    @staticmethod
    def get_data_key_as_list(data: dict, key: str) -> list[Any]:
        data_list = Client.get_data_key(data, key)
        return [] if data_list is None or not isinstance(data[key], list) else data_list

    @staticmethod
    def get_data_key_as_list_of_values(data: dict, key: str, value_key: str) -> list[Any]:
        data_list = Client.get_data_key_as_list(data, key)
        return [value_data[value_key] for value_data in data_list]

    @staticmethod
    def get_data_key_as_list_of_dicts(data: dict, key: str, dict_creator: Callable) -> Collection[Any]:
        data_list = Client.get_data_key_as_list(data, key)
        return {} if len(data_list) == 0 else [dict_creator(value_data) for value_data in data_list]

    @staticmethod
    def get_context_from_response(data: dict) -> dict:
        result_dict = {
            "ID": Client.get_data_key(data, "id"),
            "Indicator": Client.get_nested_data_key(data, "value", "name"),
            "EvidenceCount": Client.get_data_key(data, "reportCount"),
            "Active": Client.get_data_key(data, "active"),
            "HitCount": Client.get_data_key(data, "hitCount"),
            "ConfidenceLevel": Client.get_nested_data_key(data, "confidenceLevel", "value"),
            "FirstHit": Client.get_data_key(data, "firstHit"),
            "LastHit": Client.get_data_key(data, "lastHit"),
            "ReportedDates": Client.get_data_key_as_list_of_values(data, "reportedDates", "date"),
            "ActivityDates": Client.get_data_key_as_list_of_values(data, "activityDates", "date"),
            "Malwares": Client.get_data_key_as_list_of_dicts(data, "malwares", lambda d: {"id": d["id"], "name": d["name"]}),
            "Actors": Client.get_data_key_as_list_of_dicts(data, "actors", lambda d: {"id": d["id"], "name": d["name"]}),
            "Benign": Client.get_nested_data_key(data, "benign", "value"),
            "RiskScore": Client.get_nested_data_key(data, "indicatorRiskScore", "name"),
            "Analyst1Link": None,
        }

        links_list = Client.get_data_key_as_list(data, "links")
        result_dict["Analyst1Link"] = next(
            (
                link["href"].replace("api/1_0/indicator/", "indicators/")
                for link in links_list
                if "rel" in link and link["rel"] == "self" and "href" in link
            ),
            None,
        )

        return result_dict


def build_client(demisto_params: dict) -> Client:
    server: str = str(demisto_params.get("server"))
    proxy: bool = demisto_params.get("proxy", False)
    insecure: bool = demisto_params.get("insecure", False)
    credentials: dict = demisto_params.get("credentials", {})
    username: str = str(credentials.get("identifier"))
    password: str = str(credentials.get("password"))

    return Client(server, username, password, insecure, proxy)


""" COMMAND EXECUTION """


def perform_test_module(client: Client):
    client.perform_test_request()


def domain_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    domains: list[str] = argToList(args.get("domain"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for domain in domains:
        enrichment_data = enrich_with_batch_check(client, domain, "domain", "Name", "Domain")

        # Add IP resolution to Analyst1 context if available (only for full enrichment)
        if enrichment_data.has_context_data():
            ip_resolution = Client.get_nested_data_key(enrichment_data.raw_data, "ipResolution", "name")
            if ip_resolution:
                enrichment_data.add_analyst1_context("IpResolution", ip_resolution)

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def email_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    return [enrich_with_batch_check(client, email, "email", "From", "Email") for email in argToList(args.get("email"))]


def ip_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    """
    Handles both IPv4 and IPv6 addresses from the !ip command.
    XSOAR uses the !ip command for both IPv4 and IPv6 auto-enrichment.
    """
    import ipaddress

    enrichment_data_list: list[EnrichmentOutput] = []

    for ip in argToList(args.get("ip")):
        # Validate IP address format (accepts both IPv4 and IPv6)
        if not is_ip_valid(ip, accept_v6_ips=True):
            raise ValueError(f'Invalid IP address format: "{ip}"')

        # Detect if IP is IPv4 or IPv6
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                # IPv6 address
                enrichment_data = enrich_with_batch_check(client, ip, "ipv6", "Address", "IP")
            else:
                # IPv4 address
                enrichment_data = enrich_with_batch_check(client, ip, "ip", "Address", "IP")
            enrichment_data_list.append(enrichment_data)
        except ValueError:
            # Invalid IP address - treat as IPv4 for backwards compatibility
            enrichment_data = enrich_with_batch_check(client, ip, "ip", "Address", "IP")
            enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def file_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    return [
        enrich_with_batch_check(client, file, "file", get_hash_type(file).upper(), "File") for file in argToList(args.get("file"))
    ]


def analyst1_enrich_string_command(client: Client, args: dict) -> list[CommandResults]:
    strings: list[str] = argToList(args.get("string"))
    results_list: list[CommandResults] = []

    for string in strings:
        raw_data = client.indicator_search("string", string)

        if raw_data and len(raw_data) > 0:
            context_data = client.get_context_from_response(raw_data)
            results = CommandResults(
                outputs_prefix="Analyst1.String",
                outputs_key_field="ID",
                outputs=context_data,
                readable_output=tableToMarkdown("Analyst1 String Information", context_data, removeNull=True),
                raw_response=raw_data,
            )
        else:
            results = CommandResults(readable_output=f'String "{string}" was not found in Analyst1.')

        results_list.append(results)

    return results_list


def analyst1_enrich_ipv6_command(client: Client, args: dict) -> list[CommandResults]:
    ips: list[str] = argToList(args.get("ip"))
    results_list: list[CommandResults] = []

    for ip in ips:
        # Validate IPv6 address format
        if not is_ip_valid(ip, accept_v6_ips=True):
            raise ValueError(f'Invalid IPv6 address format: "{ip}"')

        raw_data = client.indicator_search("ipv6", ip)

        if raw_data and len(raw_data) > 0:
            context_data = client.get_context_from_response(raw_data)
            results = CommandResults(
                outputs_prefix="Analyst1.Ipv6",
                outputs_key_field="ID",
                outputs=context_data,
                readable_output=tableToMarkdown("Analyst1 IPv6 Information", context_data, removeNull=True),
                raw_response=raw_data,
            )
        else:
            results = CommandResults(readable_output=f'IPv6 address "{ip}" was not found in Analyst1.')

        results_list.append(results)

    return results_list


def analyst1_enrich_mutex_command(client: Client, args: dict) -> list[CommandResults]:
    mutexes: list[str] = argToList(args.get("mutex"))
    results_list: list[CommandResults] = []

    for mutex in mutexes:
        raw_data = client.indicator_search("mutex", mutex)

        if raw_data and len(raw_data) > 0:
            context_data = client.get_context_from_response(raw_data)
            results = CommandResults(
                outputs_prefix="Analyst1.Mutex",
                outputs_key_field="ID",
                outputs=context_data,
                readable_output=tableToMarkdown("Analyst1 Mutex Information", context_data, removeNull=True),
                raw_response=raw_data,
            )
        else:
            results = CommandResults(readable_output=f'Mutex "{mutex}" was not found in Analyst1.')

        results_list.append(results)

    return results_list


def analyst1_enrich_http_request_command(client: Client, args: dict) -> list[CommandResults]:
    http_requests: list[str] = argToList(args.get("http-request"))
    results_list: list[CommandResults] = []

    for http_request in http_requests:
        raw_data = client.indicator_search("httpRequest", http_request)

        if raw_data and len(raw_data) > 0:
            context_data = client.get_context_from_response(raw_data)
            results = CommandResults(
                outputs_prefix="Analyst1.HTTPRequest",
                outputs_key_field="ID",
                outputs=context_data,
                readable_output=tableToMarkdown("Analyst1 HTTP Request Information", context_data, removeNull=True),
                raw_response=raw_data,
            )
        else:
            results = CommandResults(readable_output=f'HTTP Request "{http_request}" was not found in Analyst1.')

        results_list.append(results)

    return results_list


def url_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    return [enrich_with_batch_check(client, url, "url", "Data", "URL") for url in argToList(args.get("url"))]


def argsToStr(args: dict, key: str) -> str:
    arg: Any | None = args.get(key)
    if arg is None:
        return ""
    return str(arg)


def argsToInt(args: dict, key: str, default: int) -> int:
    arg: Any | None = args.get(key)
    if arg is None:
        return default
    return int(arg)


def analyst1_get_indicator(client: Client, args) -> CommandResults | None:
    raw_data = client.get_indicator(argsToStr(args, "indicator_id"))
    if len(raw_data) > 0:
        command_results = CommandResults(outputs_prefix="Analyst1.Indicator", outputs=raw_data)
        return_results(command_results)
        return command_results
    return None


def analyst1_batch_check_command(client: Client, args) -> CommandResults | None:
    raw_data = client.get_batch_search(argsToStr(args, "values"))
    # assume succesful result or client will have errored
    if len(raw_data["results"]) > 0:
        # Process batch check results using shared helper function
        processed_results = process_batch_check_results(raw_data["results"])

        command_results = CommandResults(
            outputs_prefix="Analyst1.BatchResults", outputs_key_field="ID", outputs=processed_results
        )
        return_results(command_results)
        return command_results
    return None


def analyst1_batch_check_post(client: Client, args: dict) -> dict | None:
    runpath = "values"
    values = args.get("values")
    if values is None or not values:
        val_array = args.get("values_array")
        runpath = "val_array_base"
        # process all possible inbound value array combinations
        if isinstance(val_array, str):
            # if a string, assume it is a viable string to become an array
            # have to check if it is a "false string" with quotes around it to hand some input flows
            val_array = val_array.strip()
            if not val_array.startswith("["):
                val_array = "[" + val_array
            if not val_array.endswith("]"):
                val_array = val_array + "]"
            val_array = '{"values": ' + val_array + "}"
            val_array = json.loads(val_array)
            runpath = "val_array_str"
        elif isinstance(val_array, list):
            # if already an list, accept it
            val_array = {"values": val_array}
            runpath = "val_array_list"
        # if none of the above assume it is json matching this format
        # pull values regardless of input form to newline text for acceptable submission
        values = "\n".join(str(val) for val in val_array["values"])

    output_check_data = {
        "values": str(args.get("values")),
        "val_array": str(args.get("values_array")),
        "type": str(type(args.get("values_array"))),
        "runpath": runpath,
    }

    # Support both comma and newline delimiters for values parameter
    # POST API expects newline-separated format (file upload)
    if values and "," in values and "\n" not in values:
        # Comma-delimited input - split and convert to newline-delimited
        values = "\n".join(val.strip() for val in values.split(","))

    raw_data = client.post_batch_search(values)
    # assume succesful result or client will have errored
    if len(raw_data["results"]) > 0:
        # Process batch check results using shared helper function
        processed_results = process_batch_check_results(raw_data["results"])

        command_results = CommandResults(
            outputs_prefix="Analyst1.BatchResults", outputs_key_field="ID", outputs=processed_results
        )
        return_results(command_results)
        output_check: dict = {"command_results": command_results, "submitted_values": values, "original_data": output_check_data}
        return output_check
    return None


def analyst1_evidence_submit(client: Client, args: dict) -> CommandResults | None:
    raw_data = client.post_evidence(
        argsToStr(args, "fileName"),
        argsToStr(args, "fileContent"),
        argsToStr(args, "fileEntryId"),
        argsToStr(args, "fileClassification"),
        argsToStr(args, "tlp"),
        argsToStr(args, "sourceId"),
    )
    command_results = CommandResults(outputs_prefix="Analyst1.EvidenceSubmit", outputs_key_field="uuid", outputs=raw_data)
    return_results(command_results)
    return command_results


def analyst1_evidence_status(client: Client, args: dict) -> CommandResults | None:
    raw_data = client.get_evidence_status(argsToStr(args, "uuid"))

    if not raw_data or raw_data is None:
        raw_data = {"message": "UUID unknown"}
    elif "id" in raw_data and raw_data.get("id") is not None and raw_data.get("id"):
        raw_data["processingComplete"] = True
    elif "message" in raw_data and raw_data.get("message") is not None:
        raw_data["processingComplete"] = False
    else:
        raw_data["processingComplete"] = False

    command_results = CommandResults(outputs_prefix="Analyst1.EvidenceStatus", outputs_key_field="id", outputs=raw_data)
    return_results(command_results)
    return command_results


def a1_tasking_array_from_indicators(indicatorsJson: dict) -> list:
    taskings_list: list[dict] = []
    for ioc in indicatorsJson:
        # each IOC or each HASH gets insertd for outward processing
        # convert ID to STR to make output consistent
        listIoc: dict = {}
        if ioc.get("type") == "File" and len(ioc.get("fileHashes")) > 0:
            for key, value in ioc.get("fileHashes").items():
                # hash algorithm is the key, so use it to create output
                listIoc = {"category": "indicator", "id": str(ioc.get("id")) + "-" + key, "type": "File-" + key, "value": value}
                taskings_list.append(listIoc)
        else:
            listIoc = {"category": "indicator", "id": str(ioc.get("id")), "type": ioc.get("type"), "value": ioc.get("value")}
            taskings_list.append(listIoc)
    return taskings_list


def a1_tasking_array_from_rules(rulesJson: dict) -> list:
    taskings_list: list[dict] = []
    # convert ID to STR to make output consistent
    for rule in rulesJson:
        listRule = {"category": "rule", "id": str(rule.get("id")), "signature": rule.get("signature")}
        taskings_list.append(listRule)
    return taskings_list


def analyst1_get_sensor_taskings_command(client: Client, args: dict) -> list[CommandResults]:
    raw_data = client.get_sensor_taskings(argsToStr(args, "sensor_id"), argsToInt(args, "timeout", 200))

    simplified_data: dict = raw_data.copy()
    if "links" in simplified_data:
        del simplified_data["links"]

    indicators_taskings: list = []
    if "indicators" in simplified_data:
        indicators_taskings = a1_tasking_array_from_indicators(simplified_data["indicators"])
        del simplified_data["indicators"]

    rules_taskings: list = []
    if "rules" in simplified_data:
        rules_taskings = a1_tasking_array_from_rules(simplified_data["rules"])
        del simplified_data["rules"]

    command_results_list: list[CommandResults] = []

    command_results = CommandResults(outputs_prefix="Analyst1.SensorTaskings", outputs=simplified_data, raw_response=raw_data)
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix="Analyst1.SensorTaskings.Indicators", outputs_key_field="id", outputs=indicators_taskings
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix="Analyst1.SensorTaskings.Rules", outputs_key_field="id", outputs=rules_taskings
    )
    return_results(command_results)
    command_results_list.append(command_results)

    return command_results_list


def analyst1_get_sensors_command(client: Client, args: dict) -> CommandResults | None:
    sensor_raw_data = client.get_sensors(argsToInt(args, "page", 1), argsToInt(args, "pageSize", 50))
    command_results = CommandResults(
        outputs_prefix="Analyst1.SensorList",
        outputs_key_field="id",
        outputs=sensor_raw_data["results"],
        raw_response=sensor_raw_data,
    )
    return_results(command_results)
    return command_results


def analyst1_get_sensor_diff(client: Client, args: dict) -> list[CommandResults]:
    raw_data = client.get_sensor_diff(argsToStr(args, "sensor_id"), argsToStr(args, "version"), argsToInt(args, "timeout", 200))
    # CommandResults creates both "outputs" and "human readable" in one go using updated XSOAR capabilities

    simplified_data = raw_data.copy()
    if "links" in simplified_data:
        del simplified_data["links"]

    indicators_added: list = []
    if "indicatorsAdded" in simplified_data:
        indicators_added = a1_tasking_array_from_indicators(simplified_data["indicatorsAdded"])
        del simplified_data["indicatorsAdded"]

    indicators_removed: list = []
    if "indicatorsRemoved" in simplified_data:
        indicators_removed = a1_tasking_array_from_indicators(simplified_data["indicatorsRemoved"])
        del simplified_data["indicatorsRemoved"]

    rules_added: list = []
    if "rulesAdded" in simplified_data:
        rules_added = a1_tasking_array_from_rules(simplified_data["rulesAdded"])
        del simplified_data["rulesAdded"]

    rules_removed: list = []
    if "rulesRemoved" in simplified_data:
        rules_removed = a1_tasking_array_from_rules(simplified_data["rulesRemoved"])
        del simplified_data["rulesRemoved"]

    command_results_list: list[CommandResults] = []

    command_results = CommandResults(outputs_prefix="Analyst1.SensorTaskings", outputs=simplified_data, raw_response=raw_data)
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix="Analyst1.SensorTaskings.IndicatorsAdded", outputs_key_field="id", outputs=indicators_added
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix="Analyst1.SensorTaskings.IndicatorsRemoved", outputs_key_field="id", outputs=indicators_removed
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix="Analyst1.SensorTaskings.RulesAdded", outputs_key_field="id", outputs=rules_added
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix="Analyst1.SensorTaskings.RulesRemoved", outputs_key_field="id", outputs=rules_removed
    )
    return_results(command_results)
    command_results_list.append(command_results)

    return command_results_list


def analyst1_get_sensor_config_command(client: Client, args):
    sensor_id = argsToStr(args, "sensor_id")
    raw_data = client.get_sensor_config(sensor_id)
    warRoomEntry = fileResult("sensor" + str(sensor_id) + "Config.txt", raw_data)
    outputOptions = {"warRoomEntry": warRoomEntry, "config_text": raw_data}

    command_results = CommandResults(outputs_prefix="Analyst1.SensorTaskings.ConfigFile", outputs=outputOptions)
    return_results(command_results)
    return command_results


""" EXECUTION """


def main():
    # Commands that return EnrichmentOutput (use .return_outputs())
    enrichment_commands = {
        "domain": domain_command,
        "email": email_command,
        "file": file_command,
        "ip": ip_command,
        "url": url_command,
    }

    # Commands that return CommandResults (use return_results())
    command_result_commands = {
        "analyst1-enrich-string": analyst1_enrich_string_command,
        "analyst1-enrich-ipv6": analyst1_enrich_ipv6_command,
        "analyst1-enrich-mutex": analyst1_enrich_mutex_command,
        "analyst1-enrich-http-request": analyst1_enrich_http_request_command,
    }

    command: str = demisto.command()
    LOG(f"command is {command}")

    try:
        client = build_client(demisto.params())

        if command == "test-module":
            perform_test_module(client)
            demisto.results("ok")
        # do not set demisto.results() because caller invokes updated command_results() internally
        if command == "analyst1-evidence-submit":
            analyst1_evidence_submit(client, demisto.args())
        if command == "analyst1-evidence-status":
            analyst1_evidence_status(client, demisto.args())
        if command == "analyst1-get-sensor-taskings":
            analyst1_get_sensor_taskings_command(client, demisto.args())
        if command == "analyst1-get-sensor-config":
            analyst1_get_sensor_config_command(client, demisto.args())
        if command == "analyst1-batch-check":
            analyst1_batch_check_command(client, demisto.args())
        if command == "analyst1-batch-check-post":
            analyst1_batch_check_post(client, demisto.args())
        if command == "analyst1-get-sensors":
            analyst1_get_sensors_command(client, demisto.args())
        if command == "analyst1-get-sensor-diff":
            # do not set demisto.results() because caller invokes updated command_results() internally
            analyst1_get_sensor_diff(client, demisto.args())
        if command == "analyst1-indicator-by-id":
            analyst1_get_indicator(client, demisto.args())
        elif command in enrichment_commands:
            enrichment_outputs: list[EnrichmentOutput] = enrichment_commands[command](client, demisto.args())
            [e.return_outputs() for e in enrichment_outputs]
        elif command in command_result_commands:
            command_results: list[CommandResults] = command_result_commands[command](client, demisto.args())
            [return_results(r) for r in command_results]
    except DemistoException as e:
        if "[404]" in str(e):
            demisto.results("No Results")
            return
        err_msg = f"Error in {INTEGRATION_NAME} Integration [{e}]\nTrace:\n{traceback.format_exc()}"
        return_error(err_msg, error=e)
    return


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
