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
        entity_key = Client.get_nested_data_key(result, "entity", "key")
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
    analyst1_type = Client.get_nested_data_key(result, "type", "key")
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
    benign_entity_keys = ["ASSET", "IN_SYSTEM_RANGE", "IN_HOME_RANGE", "IN_PRIVATE_RANGE", "IGNORED_INDICATOR", "IGNORED_ASSET"]
    if entity_key and entity_key in benign_entity_keys:
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


def calculate_enrichment_verdict_from_batch_results(results_for_search_value: list[dict], params: dict) -> int:
    """
    Calculates XSOAR verdict for enrichment commands based on ALL entity types returned for a search value.

    Priority logic:
    1. If ANY result has benign=True, return Benign (1)
    2. If ANY result has entity.key in [ASSET, IN_SYSTEM_RANGE, IN_HOME_RANGE, IN_PRIVATE_RANGE, IGNORED_INDICATOR, IGNORED_ASSET], return Benign (1)
    3. Otherwise, find the INDICATOR result and use risk score mapping
    4. If no INDICATOR or no risk score, return Unknown (0)

    Args:
        results_for_search_value: All batch check results for a single search value
        params: Integration configuration parameters

    Returns:
        XSOAR verdict score: 0=Unknown, 1=Benign, 2=Suspicious, 3=Malicious
    """
    benign_entity_keys = ["ASSET", "IN_SYSTEM_RANGE", "IN_HOME_RANGE", "IN_PRIVATE_RANGE", "IGNORED_INDICATOR", "IGNORED_ASSET"]

    # Priority 1: Check if ANY result has benign=True
    for result in results_for_search_value:
        benign_value = Client.get_nested_data_key(result, "benign", "value")
        if benign_value is True:
            return 1  # Benign

    # Priority 2: Check if ANY result has a benign entity type
    for result in results_for_search_value:
        entity_key = Client.get_nested_data_key(result, "entity", "key")
        if entity_key and entity_key in benign_entity_keys:
            return 1  # Benign

    # Priority 3: Find INDICATOR result and use risk score mapping
    for result in results_for_search_value:
        entity_key = Client.get_nested_data_key(result, "entity", "key")
        if entity_key == "INDICATOR":
            risk_score = Client.get_nested_data_key(result, "indicatorRiskScore", "title")
            if risk_score:
                mappings = get_risk_score_mappings(params)
                return mappings.get(risk_score, 0)
            else:
                return 0  # Unknown - INDICATOR but no risk score

    # Priority 4: No INDICATOR found, return Unknown
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
        entity_key = Client.get_nested_data_key(result, "entity", "key")
        type_key = Client.get_nested_data_key(result, "type", "key")

        if entity_key == "INDICATOR" and type_key == expected_type:
            return result

    return None


class IdNamePair:
    def __init__(self, unique_id: int, name: str):
        self.id = unique_id
        self.name = name

    def __str__(self):
        return f"id = {self.id}, name = {self.name}"


class EnrichmentOutput:
    def __init__(self, analyst1_context_data: dict, raw_data: dict, indicator_type: str) -> None:
        self.analyst1_context_data = analyst1_context_data
        self.raw_data = raw_data
        self.indicator_type = indicator_type
        self.reputation_context: dict = {}

    def get_human_readable_output(self) -> str:
        human_readable_data = self.analyst1_context_data.copy()
        human_readable_data["Actors"] = [IdNamePair(d["id"], d["name"]) for d in human_readable_data["Actors"]]
        human_readable_data["Malwares"] = [IdNamePair(d["id"], d["name"]) for d in human_readable_data["Malwares"]]

        return tableToMarkdown(
            t=human_readable_data, name=f"{INTEGRATION_NAME} {self.indicator_type.capitalize()} Information", removeNull=True
        )

    def build_analyst1_context(self) -> dict:
        return {
            f"{INTEGRATION_CONTEXT_BRAND}.{self.indicator_type.capitalize()}(val.ID && val.ID === obj.ID)":  # type: ignore
            self.analyst1_context_data
        }

    def generate_reputation_context(
        self, primary_key: str, indicator_value: str, indicator_type: str, reputation_key: str, extra_context: dict | None = None
    ):
        if self.has_context_data():
            reputation_context: dict[str, Any] = {primary_key: indicator_value}

            if extra_context is not None:
                reputation_context.update(extra_context)

            # Calculate verdict using new risk score-based logic
            risk_score = Client.get_nested_data_key(self.raw_data, "indicatorRiskScore", "name")
            benign_value = Client.get_nested_data_key(self.raw_data, "benign", "value")
            verdict_score = calculate_verdict_from_risk_score(risk_score, benign_value, demisto.params())

            # Only add Malicious context if verdict is Malicious (score 3)
            if verdict_score == 3:
                reputation_context["Malicious"] = MALICIOUS_DATA

            self.add_reputation_context(
                f"{reputation_key}(val.{primary_key} && val.{primary_key} === obj.{primary_key})", reputation_context
            )

            self.add_reputation_context(
                "DBotScore",
                {
                    "Indicator": indicator_value,
                    "Score": verdict_score,
                    "Type": indicator_type,
                    "Vendor": INTEGRATION_NAME,
                    "Reliability": demisto.params().get("integrationReliability"),
                },
            )

            # Add "Analyst1: Indicator" tag for all enrichment commands
            self.add_reputation_context(
                "Common.Indicator(val.Value && val.Value === obj.Value)",
                {
                    "Value": indicator_value,
                    "Tags": ["Analyst1: Indicator"],
                },
            )

    def build_all_context(self) -> dict:
        all_context = {}
        all_context.update(self.build_analyst1_context())
        if len(self.reputation_context) > 0:
            all_context.update(self.reputation_context)

        return all_context

    def return_outputs(self):
        # We need to use the underlying demisto.results function call rather than using return_outputs because
        # we need to add the IgnoreAutoExtract key to ensure that our analyst1 links are not marked as indicators
        entry = {
            "Type": entryTypes["note"],
            "HumanReadable": self.get_human_readable_output(),
            "ContentsFormat": formats["json"],
            "Contents": self.raw_data,
            "EntryContext": self.build_all_context(),
            "IgnoreAutoExtract": True,
        }

        demisto.results(entry)

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
        # warRoomFileId: str, may want to be added in as a future capability
        # but access from those files were inconsistent, so current scope is only content or file entry
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
            raise DemistoException("either fileContent, fileEntryId, or warRoomFileId must be specified to submit Evidence")

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
            return EnrichmentOutput({}, {}, indicator_type)

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
    def get_data_key_as_date(data: dict, key: str, fmt: str) -> str | None:
        value = Client.get_data_key(data, key)
        return None if value is None else datetime.fromtimestamp(value / 1000.0).strftime(fmt)

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
        enrichment_data: EnrichmentOutput = client.enrich_indicator(domain, "domain")
        if enrichment_data.has_context_data():
            extra_context = {}

            ip_resolution = Client.get_nested_data_key(enrichment_data.raw_data, "ipResolution", "name")
            if ip_resolution is not None:
                enrichment_data.add_analyst1_context("IpResolution", ip_resolution)
                extra_context["DNS"] = ip_resolution

            enrichment_data.generate_reputation_context("Name", domain, "domain", "Domain", extra_context)

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def email_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    emails: list[str] = argToList(args.get("email"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for email in emails:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(email, "email")

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context("From", email, "email", "Email")

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def ip_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    ips: list[str] = argToList(args.get("ip"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for ip in ips:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(ip, "ip")

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context("Address", ip, "ip", "IP")

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def file_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    files: list[str] = argToList(args.get("file"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for file in files:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(file, "file")

        if enrichment_data.has_context_data():
            hash_type = get_hash_type(file)
            if hash_type != "Unknown":
                enrichment_data.generate_reputation_context(hash_type.upper(), file, "file", "File")

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def analyst1_enrich_string_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    strings: list[str] = argToList(args.get("string"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for string in strings:
        enrichment_data_list.append(client.enrich_indicator(string, "string"))

    return enrichment_data_list


def analyst1_enrich_ipv6_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    ips: list[str] = argToList(args.get("ip"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for ip in ips:
        enrichment_data_list.append(client.enrich_indicator(ip, "ipv6"))

    return enrichment_data_list


def analyst1_enrich_mutex_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    mutexes: list[str] = argToList(args.get("mutex"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for mutex in mutexes:
        enrichment_data_list.append(client.enrich_indicator(mutex, "mutex"))

    return enrichment_data_list


def analyst1_enrich_http_request_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    http_requests: list[str] = argToList(args.get("http-request"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for http_request in http_requests:
        enrichment_data_list.append(client.enrich_indicator(http_request, "httpRequest"))

    return enrichment_data_list


def url_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    urls: list[str] = argToList(args.get("url"))
    enrichment_data_list: list[EnrichmentOutput] = []

    for url in urls:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(url, "url")

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context("Data", url, "url", "URL")

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


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
        # Group results by matchedValue to handle multiple entity types per indicator
        results_by_indicator: dict[str, list[dict]] = {}
        for result in raw_data["results"]:
            matched_value = result.get("matchedValue")
            if matched_value:
                if matched_value not in results_by_indicator:
                    results_by_indicator[matched_value] = []
                results_by_indicator[matched_value].append(result)

        # Process each unique indicator
        for matched_value, indicator_results in results_by_indicator.items():
            # Determine tags for this indicator across all its entity types
            tags = get_analyst1_tags_for_batch_result(indicator_results)

            # Calculate verdict (use first result - they should have same verdict logic per indicator)
            first_result = indicator_results[0]
            risk_score = Client.get_nested_data_key(first_result, "indicatorRiskScore", "title")
            benign_value = Client.get_nested_data_key(first_result, "benign", "value")
            entity_key = Client.get_nested_data_key(first_result, "entity", "key")

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

            # Add tags to all results for this indicator
            for result in indicator_results:
                result["DBotScore"] = dbot_score
                result["Tags"] = tags

            # Create Common.Indicator context to manage tags
            # This ensures tags are properly added/removed in XSOAR
            common_indicator = {
                "Value": matched_value,
                "Tags": tags,
            }

            # Return indicator context to manage tags
            return_results(
                CommandResults(
                    outputs_prefix="Common.Indicator",
                    outputs_key_field="Value",
                    outputs=common_indicator,
                )
            )

        command_results = CommandResults(
            outputs_prefix="Analyst1.BatchResults", outputs_key_field="ID", outputs=raw_data["results"]
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

    raw_data = client.post_batch_search(values)
    # assume succesful result or client will have errored
    if len(raw_data["results"]) > 0:
        # Group results by matchedValue to handle multiple entity types per indicator
        results_by_indicator: dict[str, list[dict]] = {}
        for result in raw_data["results"]:
            matched_value = result.get("matchedValue")
            if matched_value:
                if matched_value not in results_by_indicator:
                    results_by_indicator[matched_value] = []
                results_by_indicator[matched_value].append(result)

        # Process each unique indicator
        for matched_value, indicator_results in results_by_indicator.items():
            # Determine tags for this indicator across all its entity types
            tags = get_analyst1_tags_for_batch_result(indicator_results)

            # Calculate verdict (use first result - they should have same verdict logic per indicator)
            first_result = indicator_results[0]
            risk_score = Client.get_nested_data_key(first_result, "indicatorRiskScore", "title")
            benign_value = Client.get_nested_data_key(first_result, "benign", "value")
            entity_key = Client.get_nested_data_key(first_result, "entity", "key")

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

            # Add tags to all results for this indicator
            for result in indicator_results:
                result["DBotScore"] = dbot_score
                result["Tags"] = tags

            # Create Common.Indicator context to manage tags
            # This ensures tags are properly added/removed in XSOAR
            common_indicator = {
                "Value": matched_value,
                "Tags": tags,
            }

            # Return indicator context to manage tags
            return_results(
                CommandResults(
                    outputs_prefix="Common.Indicator",
                    outputs_key_field="Value",
                    outputs=common_indicator,
                )
            )

        command_results = CommandResults(
            outputs_prefix="Analyst1.BatchResults", outputs_key_field="ID", outputs=raw_data["results"]
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
    # args.get('warRoomFileId'), may be added back in at a future time
    # for now it is left out on purpose
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
    commands = {
        "domain": domain_command,
        "email": email_command,
        "file": file_command,
        "ip": ip_command,
        "url": url_command,
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
        elif command in commands:
            enrichment_outputs: list[EnrichmentOutput] = commands[command](client, demisto.args())
            [e.return_outputs() for e in enrichment_outputs]
    except DemistoException as e:
        if "[404]" in str(e):
            demisto.results("No Results")
            return
        err_msg = f"Error in {INTEGRATION_NAME} Integration [{e}]\nTrace:\n{traceback.format_exc()}"
        return_error(err_msg, error=e)
    return


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
