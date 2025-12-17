import copy
import traceback
from datetime import datetime

import demistomock as demisto  # noqa: F401

# IMPORTS
import urllib3
from CommonServerPython import *  # noqa: F401
from CrowdStrikeApiModule import *  # noqa: E402

from CommonServerUserPython import *  # noqa

urllib3.disable_warnings()


# DIAGNOSTIC VERSION - Enhanced logging for XSUP-60131
# This version adds comprehensive logging to diagnose indicator creation issues


XSOAR_TYPES_TO_CROWDSTRIKE = {
    "account": "username",
    "domain": "domain",
    "email": "email_address",
    "file md5": "hash_md5",
    "file sha-256": "hash_sha256",
    "ip": "ip_address",
    "registry key": "registry",
    "url": "url",
}
CROWDSTRIKE_TO_XSOAR_TYPES = {
    "username": FeedIndicatorType.Account,
    "domain": FeedIndicatorType.Domain,
    "email_address": FeedIndicatorType.Email,
    "hash_md5": FeedIndicatorType.File,
    "hash_sha1": FeedIndicatorType.File,
    "hash_sha256": FeedIndicatorType.File,
    "registry": FeedIndicatorType.Registry,
    "url": FeedIndicatorType.URL,
    "ip_address": FeedIndicatorType.IP,
    "reports": ThreatIntel.ObjectsNames.REPORT,
    "actors": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "malware_families": ThreatIntel.ObjectsNames.MALWARE,
    "vulnerabilities": FeedIndicatorType.CVE,
}
INDICATOR_TO_CROWDSTRIKE_RELATION_DICT: Dict[str, Any] = {
    ThreatIntel.ObjectsNames.REPORT: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Account: EntityRelationship.Relationships.RELATED_TO,
    },
    ThreatIntel.ObjectsNames.THREAT_ACTOR: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Account: EntityRelationship.Relationships.RELATED_TO,
    },
    ThreatIntel.ObjectsNames.MALWARE: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Account: EntityRelationship.Relationships.RELATED_TO,
    },
    FeedIndicatorType.CVE: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Account: EntityRelationship.Relationships.RELATED_TO,
    },
}
CROWDSTRIKE_INDICATOR_RELATION_FIELDS = ["reports", "actors", "malware_families", "vulnerabilities", "relations"]


def diagnostic_log(message: str, level: str = "info"):
    """Enhanced logging function with timestamp and level"""
    timestamp = datetime.utcnow().isoformat()
    formatted_message = f"[DIAGNOSTIC {timestamp}] {message}"

    if level == "error":
        demisto.error(formatted_message)
    elif level == "debug":
        demisto.debug(formatted_message)
    else:
        demisto.info(formatted_message)


def kill_chain_standard_values(phases: list | None):
    """
    Will convert crowdstrike's return values for kill chain to our standard kill chain syntax.
    Args:
        phase: the raw inout from the api
    Returns: the standardized value, or the given value if not found
    """
    if not phases:
        return phases
    return [
        {
            "reconnaissance": "Reconnaissance",
            "weaponization": "Weaponization",
            "installation": "Installation",
            "exploitation": "Exploitation",
            "delivery": "Delivery",
            "c2": "Command & Control",
            "actionOnObjectives": "Actions on Objectives",
        }.get(phase.lower(), phase)
        for phase in phases
    ]


class Client(CrowdStrikeClient):
    def __init__(
        self,
        credentials,
        base_url,
        include_deleted,
        type,
        limit,
        tlp_color=None,
        feed_tags=None,
        malicious_confidence=None,
        filter_string=None,
        generic_phrase=None,
        insecure=True,
        proxy=False,
        first_fetch=None,
        create_relationships=True,
        timeout="10",
    ):
        params = assign_params(
            credentials=credentials, server_url=base_url, insecure=insecure, ok_codes=(), proxy=proxy, timeout=timeout
        )
        super().__init__(params)
        self.type = type
        self.malicious_confidence = malicious_confidence
        self.filter_string = filter_string
        self.generic_phrase = generic_phrase
        self.include_deleted = include_deleted
        self.tlp_color = tlp_color
        self.feed_tags = feed_tags
        self.limit = limit
        self.first_fetch = first_fetch
        self.create_relationships = create_relationships

    def get_indicators(self, params):
        diagnostic_log(f"Making API request with params: {params}")
        response = super().http_request(
            method="GET", params=params, url_suffix="intel/combined/indicators/v1", timeout=30, ok_codes=(200, 401)
        )

        if response.get("errors") and response["errors"][0].get("code") == 401:
            diagnostic_log(f'Request failed with 401, regenerating token. Error: {str(response["errors"][0])}', "error")
            self._token = self._get_token()
            self._headers = {"Authorization": "bearer " + self._token}
            response = super().http_request(method="GET", params=params, url_suffix="intel/combined/indicators/v1", timeout=30)
            diagnostic_log("Token regenerated, request retried successfully")

        resource_count = len(response.get("resources", []))
        diagnostic_log(f"API response received with {resource_count} resources")
        return response

    def get_actors_names_request(self, params_string):
        response = self._http_request(
            method="GET", url_suffix=f"intel/entities/actors/v1?{params_string}", timeout=30, ok_codes=(200, 401)
        )

        if response.get("errors") and response["errors"][0].get("code") == 401:
            diagnostic_log(f'Actors request failed with 401, error: {str(response["errors"][0])}', "error")
            self._token = self._get_token()
            self._headers = {"Authorization": "bearer " + self._token}
            response = self._http_request(method="GET", url_suffix=f"intel/entities/actors/v1?{params_string}", timeout=30)

        if "resources" not in response:
            raise DemistoException("Get actors request completed. Parse error: could not find resources in response.")
        return response["resources"]

    def fetch_indicators(self, limit: int, offset: int = 0, fetch_command: bool = False, manual_last_run: int = 0) -> tuple:
        """Get indicators from CrowdStrike API

        Args:
            limit(int): number of indicators to return
            offset: indicators offset
            fetch_command: In order not to update last_run time if it is not fetch command
            manual_last_run: The minimum timestamp to fetch indicators by

        Returns:
            tuple: (parsed indicators list, new_marker_time)
        """
        diagnostic_log(f"=== FETCH INDICATORS START === limit={limit}, offset={offset}, fetch_command={fetch_command}")

        indicators: list[dict] = []
        filter_string = f"({self.filter_string})" if self.filter_string else ""
        if self.type:
            type_fql = self.build_type_fql(self.type)
            filter_string = f"({type_fql})+{filter_string}" if filter_string else f"({type_fql})"

        if self.malicious_confidence:
            malicious_confidence_fql = ",".join([f"malicious_confidence:'{item}'" for item in self.malicious_confidence])
            filter_string = f"{filter_string}+({malicious_confidence_fql})" if filter_string else f"({malicious_confidence_fql})"

        if manual_last_run:
            filter_string = (
                f"{filter_string}+(last_updated:>={manual_last_run})" if filter_string else f"(last_updated:>={manual_last_run})"
            )

        new_last_marker_time = None

        if fetch_command:
            context_before = demisto.getIntegrationContext()
            diagnostic_log(f"Integration context BEFORE fetch: {json.dumps(context_before)}")

            if last_run := self.get_last_run():
                filter_string = f"{filter_string}+({last_run})" if filter_string else f"({last_run})"
                diagnostic_log(f"Using existing last_run marker: {last_run}")
            else:
                diagnostic_log("No last_run found, handling first fetch")
                filter_string, indicators = self.handle_first_fetch_context_or_pre_2_1_0(filter_string)
                if indicators:
                    limit = limit - len(indicators)
                    diagnostic_log(f"First fetch returned {len(indicators)} indicators, adjusting limit to {limit}")

        if filter_string or not fetch_command:
            diagnostic_log(f"Final filter string: {filter_string}")
            params = assign_params(
                include_deleted=self.include_deleted,
                limit=limit,
                offset=offset,
                q=self.generic_phrase,
                filter=filter_string,
                sort="_marker|asc",
            )

            response = self.get_indicators(params=params)

            # need to fetch all indicators after the limit
            if resources := response.get("resources", []):
                new_last_marker_time = resources[-1].get("_marker")
                diagnostic_log(f"Retrieved {len(resources)} resources, new marker: {new_last_marker_time}")
            else:
                new_last_marker_time = demisto.getIntegrationContext().get("last_marker_time")
                last_marker_time_for_debug = new_last_marker_time or "No data yet"
                diagnostic_log(f"No resources returned, keeping existing marker: {last_marker_time_for_debug}")

            # DIAGNOSTIC: Don't update context here - return marker to be updated after successful creation
            diagnostic_log(f"Parsing {len(response.get('resources', []))} indicators from response")
            parsed_from_response = self.create_indicators_from_response(
                response,
                self.get_actors_names_request,
                self.tlp_color,
                self.feed_tags,
                self.create_relationships,
            )
            diagnostic_log(f"Successfully parsed {len(parsed_from_response)} indicators")
            indicators.extend(parsed_from_response)

        diagnostic_log(f"=== FETCH INDICATORS END === Total indicators: {len(indicators)}, New marker: {new_last_marker_time}")
        return indicators, new_last_marker_time

    def handle_first_fetch_context_or_pre_2_1_0(self, filter_string: str) -> tuple[str, list[dict]]:
        """
        Checks whether the context integration uses the format used up to version 2_1_0
        (when the `last_update` parameter was removed),
        or whether this is the first time of the fetch,
        If so, the function imports one indicator
        and extracts the `_marker` from it to import the following indicators.

        The function is only called in the following two cases:
            1. At the first run of v2.1.0 or newer.
            2. In order to transfer the context integration to the new implementation

        Returns:
            Tuple:
                1. filter_string with the _marker key - str.
                2. parse indicator that retrieved - list[dict].
        """
        diagnostic_log("Handling first fetch or pre-2.1.0 context")
        filter_for_first_fetch = filter_string
        if last_run := demisto.getIntegrationContext().get("last_updated") or self.first_fetch:
            last_run = f"last_updated:>={int(last_run)}"
            filter_for_first_fetch = f"{filter_string}+({last_run})" if filter_string else f"({last_run})"
            diagnostic_log(f"Using last_updated or first_fetch: {last_run}")

        params = assign_params(
            include_deleted=self.include_deleted,
            limit=1,
            q=self.generic_phrase,
            filter=filter_for_first_fetch,
            sort="last_updated|asc",
        )
        response = self.get_indicators(params=params)

        # In case there is an indicator for extracting the `_marker`
        # it allows fetching following indicators better.
        if resources := response.get("resources", []):
            _marker = resources[-1].get("_marker")
            diagnostic_log(f"First fetch: extracted marker {_marker}")
            last_run = f"_marker:>'{_marker}'"
            parse_indicator = self.create_indicators_from_response(
                response, self.get_actors_names_request, self.tlp_color, self.feed_tags, self.create_relationships
            )
            filter_string = f"{filter_string}+({last_run})" if filter_string else f"({last_run})"
            return filter_string, parse_indicator

        # In case no indicator is returned
        diagnostic_log("First fetch: No indicator returned")
        return "", []

    @staticmethod
    def get_last_run() -> str:
        """Gets last run time in timestamp

        Returns:
            last run in timestamp, or '' if no last run.
            Taken from Integration Context key last_marker_time.

        """
        if last_run := demisto.getIntegrationContext().get("last_marker_time"):
            diagnostic_log(f"Retrieved last_marker_time from context: {last_run}")
            params = f"_marker:>'{last_run}'"
        else:
            diagnostic_log("No last_marker_time found in Integration Context")
            params = ""
        return params

    @staticmethod
    def create_indicators_from_response(
        raw_response, get_actors_names_request_func, tlp_color=None, feed_tags=None, create_relationships=True
    ) -> list:
        """Builds indicators from API raw response

        Args:
            raw_response: response from crowdstrike API
            tlp_color: tlp color chosen by customer
            feed_tags: Feed tags to filter by
            create_relationships: Whether to create relationships.

        Returns:
            (list): list of indicators
        """

        parsed_indicators: list = []
        indicator: dict = {}
        skipped_count = 0
        skipped_types = {}

        for resource in raw_response["resources"]:
            if not (type_ := auto_detect_indicator_type_from_cs(resource["indicator"], resource["type"])):
                skipped_count += 1
                cs_type = resource["type"]
                skipped_types[cs_type] = skipped_types.get(cs_type, 0) + 1
                diagnostic_log(f"SKIPPED: Indicator {resource['indicator']} of type {cs_type} not supported", "debug")
                continue
            indicator = {
                "type": type_,
                "value": resource.get("indicator"),
                "rawJSON": resource,
                "fields": {
                    "actor": resource.get("actors"),
                    "reports": resource.get("reports"),
                    "malwarefamily": resource.get("malware_families"),
                    "stixkillchainphases": kill_chain_standard_values(resource.get("kill_chains")),
                    "ipaddress": resource.get("ip_address_types"),
                    "domainname": resource.get("domain_types"),
                    "targets": resource.get("targets"),
                    "threattypes": [{"threatcategory": threat} for threat in resource.get("threat_types", [])],
                    "vulnerabilities": resource.get("vulnerabilities"),
                    "confidence": resource.get("malicious_confidence"),
                    "updateddate": resource.get("last_updated"),
                    "creationdate": resource.get("published_date"),
                    "tags": [label.get("name") for label in resource.get("labels")],  # type: ignore
                },
            }
            if tlp_color:
                indicator["fields"]["trafficlightprotocol"] = tlp_color
            if feed_tags:
                indicator["fields"]["tags"].extend(feed_tags)
            if create_relationships:
                relationships = create_and_add_relationships(indicator, resource, get_actors_names_request_func)
                indicator["relationships"] = relationships
            parsed_indicators.append(indicator)

        if skipped_count > 0:
            diagnostic_log(f"SUMMARY: Skipped {skipped_count} unsupported indicators. Breakdown: {skipped_types}", "info")

        diagnostic_log(f"Created {len(parsed_indicators)} indicator objects from {len(raw_response['resources'])} resources")
        return parsed_indicators

    @staticmethod
    def build_type_fql(types_list: list) -> str:
        """Builds an indicator type query for the filter parameter

        Args:
            types_list(list): indicator types that was chosen by user

        Returns:
            (str): FQL query containing the relevant indicator types we want to fetch from Crowdstrike
        """

        if "ALL" in types_list:
            # Replaces "ALL" for all types supported on XSOAR.
            crowdstrike_types = [f"type:'{type}'" for type in CROWDSTRIKE_TO_XSOAR_TYPES]
        else:
            crowdstrike_types = [
                f"type:'{XSOAR_TYPES_TO_CROWDSTRIKE.get(type.lower())}'"
                for type in types_list
                if type.lower() in XSOAR_TYPES_TO_CROWDSTRIKE
            ]

        result = ",".join(crowdstrike_types)
        return result


def create_and_add_relationships(indicator: dict, resource: dict, get_actors_names_request_func) -> list:
    """
    Creates and adds relationships to indicators for each CrowdStrike relationships type.

    Args:
        indicator(dict): The indicator in XSOAR format.
        resource(dict): The indicator from the response.

    Returns:
        List of relationships objects.
    """

    relationships = []

    for field in CROWDSTRIKE_INDICATOR_RELATION_FIELDS:
        if resource.get(field):
            relationships.extend(create_relationships(field, indicator, resource, get_actors_names_request_func))

    return relationships


def create_relationships(field: str, indicator: dict, resource: dict, get_actors_names_request_func) -> List:
    """
    Creates indicator relationships.

    Args:
        field(str): A CrowdStrike indicator field which contains relationships.
        indicator(dict): The indicator in XSOAR format.
        resource(dict): The indicator from the response.

    Returns:
        List of relationships objects.
    """
    relationships = []
    if field == "actors" and resource["actors"]:
        resource["actors"] = change_actors_from_id_to_name(resource["actors"], get_actors_names_request_func)
    for relation in resource[field]:
        if field == "relations" and not CROWDSTRIKE_TO_XSOAR_TYPES.get(relation.get("type")):
            diagnostic_log(f"Related indicator type {relation.get('type')} not supported", "debug")
            continue
        if field == "relations":
            related_indicator_type = auto_detect_indicator_type_from_cs(relation["indicator"], relation["type"])
            relation_name = EntityRelationship.Relationships.RELATED_TO
        else:
            related_indicator_type = CROWDSTRIKE_TO_XSOAR_TYPES[field]
            relation_name = INDICATOR_TO_CROWDSTRIKE_RELATION_DICT[related_indicator_type].get(
                indicator["type"], indicator["type"]
            )

        indicator_relation = EntityRelationship(
            name=relation_name,
            entity_a=indicator["value"],
            entity_a_type=indicator["type"],
            entity_b=relation["indicator"] if field == "relations" else relation,
            entity_b_type=related_indicator_type,
            reverse_name=EntityRelationship.Relationships.RELATIONSHIPS_NAMES.get(relation_name, ""),
        ).to_indicator()

        relationships.append(indicator_relation)
    return relationships


def change_actors_from_id_to_name(indicator_actors_array: List[str], get_name_of_actors__func):
    integration_context = get_integration_context()
    actors_to_convert = []
    converted_actors_array = []
    for actor in indicator_actors_array:
        if converted_actor := integration_context.get(actor, None):
            converted_actors_array.append(converted_actor)
        else:
            actors_to_convert.append(actor)
    if actors_to_convert:
        actor_ids_params = "ids=" + "&ids=".join(actors_to_convert) + "&fields=name"
        actors_response = get_name_of_actors__func(actor_ids_params)
        converted_actors_from_request = []
        for actor_dict in actors_response:
            converted_actors_from_request.append(actor_dict.get("name"))
        zipped_actors_list_to_context = dict(zip(actors_to_convert, converted_actors_from_request))
        update_integration_context(zipped_actors_list_to_context)
        converted_actors_array += converted_actors_from_request
    return converted_actors_array


def auto_detect_indicator_type_from_cs(value: str, crowdstrike_resource_type: str) -> str | None:
    """
    The function determines the type of indicator according to two cases::
    1. In case the type is ip_address then the type is detected by auto_detect_indicator_type function (CSP).
    2. In any other case, the type is converted by the table CROWDSTRIKE_TO_XSOAR_TYPES to a type of XSOAR.
    """
    if crowdstrike_resource_type == "ip_address":
        return auto_detect_indicator_type(value)

    return CROWDSTRIKE_TO_XSOAR_TYPES.get(crowdstrike_resource_type)


def fetch_indicators_command(client: Client):
    """fetch indicators from the Crowdstrike Intel - DIAGNOSTIC VERSION

    Args:
        client: Client object

    Returns:
        list of indicators(list)
    """
    diagnostic_log("=" * 80)
    diagnostic_log("FETCH INDICATORS COMMAND STARTED")
    diagnostic_log("=" * 80)

    try:
        # Fetch indicators and get the new marker
        parsed_indicators, new_marker = client.fetch_indicators(fetch_command=True, limit=client.limit)

        diagnostic_log(f"Fetched {len(parsed_indicators)} indicators to create")

        # Track creation success
        total_indicators = len(parsed_indicators)
        successfully_created = 0
        failed_batches = []

        # we submit the indicators in batches
        batch_num = 0
        for b in batch(parsed_indicators, batch_size=2000):
            batch_num += 1
            batch_size = len(b)
            diagnostic_log(f"Processing batch {batch_num} with {batch_size} indicators")

            try:
                # Attempt to create indicators
                diagnostic_log(f"Calling demisto.createIndicators for batch {batch_num}...")
                start_time = datetime.utcnow()

                demisto.createIndicators(b)

                end_time = datetime.utcnow()
                duration = (end_time - start_time).total_seconds()

                successfully_created += batch_size
                diagnostic_log(f"✓ Batch {batch_num} created successfully in {duration:.2f} seconds")

            except Exception as e:
                error_msg = str(e)
                error_trace = traceback.format_exc()
                diagnostic_log(f"✗ FAILED to create batch {batch_num}: {error_msg}", "error")
                diagnostic_log(f"Stack trace: {error_trace}", "error")
                failed_batches.append({"batch_num": batch_num, "size": batch_size, "error": error_msg})
                # Continue processing other batches

        # Log summary
        diagnostic_log("=" * 80)
        diagnostic_log("INDICATOR CREATION SUMMARY:")
        diagnostic_log(f"  Total fetched: {total_indicators}")
        diagnostic_log(f"  Successfully created: {successfully_created}")
        diagnostic_log(f"  Failed: {total_indicators - successfully_created}")
        diagnostic_log(f"  Success rate: {(successfully_created/total_indicators*100) if total_indicators > 0 else 0:.1f}%")

        if failed_batches:
            diagnostic_log(f"  Failed batches: {len(failed_batches)}", "error")
            for fb in failed_batches:
                diagnostic_log(f"    - Batch {fb['batch_num']} ({fb['size']} indicators): {fb['error']}", "error")

        # CRITICAL: Only update marker if at least some indicators were created successfully
        if successfully_created > 0 and new_marker:
            context = demisto.getIntegrationContext()
            old_marker = context.get("last_marker_time")
            context.update({"last_marker_time": new_marker})
            demisto.setIntegrationContext(context)
            diagnostic_log(f"✓ Updated last_marker_time: {old_marker} -> {new_marker}")
        elif successfully_created == 0:
            diagnostic_log("✗ NO INDICATORS CREATED - NOT updating marker to prevent data loss!", "error")
        else:
            diagnostic_log("No new marker to update")

        diagnostic_log("=" * 80)
        diagnostic_log("FETCH INDICATORS COMMAND COMPLETED")
        diagnostic_log("=" * 80)

        return parsed_indicators

    except Exception as e:
        error_msg = str(e)
        error_trace = traceback.format_exc()
        diagnostic_log(f"CRITICAL ERROR in fetch_indicators_command: {error_msg}", "error")
        diagnostic_log(f"Stack trace: {error_trace}", "error")
        raise


def crowdstrike_indicators_list_command(client: Client, args: dict) -> CommandResults:
    """Gets indicator from Crowdstrike Intel to readable output

    Args:
        client: Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    diagnostic_log("CROWDSTRIKE-INDICATORS-LIST command started")

    offset = arg_to_number(args.get("offset", 0)) or 0
    limit = arg_to_number(args.get("limit", 50)) or 50
    last_run = arg_to_number(args.get("last_run", 0)) or 0

    parsed_indicators, _ = client.fetch_indicators(limit=limit, offset=offset, fetch_command=False, manual_last_run=last_run)

    diagnostic_log(f"Retrieved {len(parsed_indicators)} indicators for list command")

    if outputs := copy.deepcopy(parsed_indicators):
        for indicator in outputs:
            indicator["id"] = indicator.get("rawJSON", {}).get("id")

        readable_output = tableToMarkdown(
            name="Indicators from CrowdStrike Falcon Intel",
            t=outputs,
            headers=["type", "value", "id"],
            headerTransform=pascalToSpace,
        )

        return CommandResults(
            outputs=outputs,
            outputs_prefix="CrowdStrikeFalconIntel.Indicators",
            outputs_key_field="id",
            readable_output=readable_output,
            raw_response=parsed_indicators,
        )
    else:
        return CommandResults(readable_output="No Indicators.")


def test_module(client: Client, args: dict) -> str:
    diagnostic_log("TEST-MODULE command started")
    try:
        parsed_indicators, _ = client.fetch_indicators(limit=client.limit, fetch_command=False)
        diagnostic_log(f"Test successful - fetched {len(parsed_indicators)} indicators")
    except Exception as e:
        diagnostic_log(f"Test failed: {str(e)}", "error")
        raise Exception("Could not fetch CrowdStrike Indicator Feed\n\nCheck your API key and your connection to CrowdStrike.")
    return "ok"


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    diagnostic_log("RESET-FETCH-INDICATORS command - clearing integration context")
    old_context = demisto.getIntegrationContext()
    diagnostic_log(f"Old context: {json.dumps(old_context)}")
    demisto.setIntegrationContext({})
    diagnostic_log("Integration context cleared successfully")
    return CommandResults(readable_output="Fetch history deleted successfully")


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()

    credentials = params.get("credentials")
    proxy = params.get("proxy", False)
    insecure = params.get("insecure", False)
    first_fetch_param = params.get("first_fetch")
    first_fetch_datetime = arg_to_datetime(first_fetch_param) if first_fetch_param else None
    first_fetch = first_fetch_datetime.timestamp() if first_fetch_datetime else None

    base_url = params.get("base_url")
    tlp_color = params.get("tlp_color")
    include_deleted = params.get("include_deleted", False)
    type = argToList(params.get("type"), "ALL")
    malicious_confidence = argToList(params.get("malicious_confidence"))
    filter_string = params.get("filter")
    generic_phrase = params.get("generic_phrase")
    max_fetch = arg_to_number(params.get("max_indicator_to_fetch")) if params.get("max_indicator_to_fetch") else 10000
    max_fetch = min(max_fetch, 10000)  # type: ignore
    feed_tags = argToList(params.get("feedTags"))
    create_relationships = params.get("create_relationships", True)
    timeout = params.get("timeout")

    args = demisto.args()

    try:
        command = demisto.command()
        diagnostic_log(f"Command being called: {command}")

        client = Client(
            credentials=credentials,
            base_url=base_url,
            insecure=insecure,
            proxy=proxy,
            tlp_color=tlp_color,
            feed_tags=feed_tags,
            include_deleted=include_deleted,
            type=type,
            malicious_confidence=malicious_confidence,
            filter_string=filter_string,
            generic_phrase=generic_phrase,
            limit=max_fetch,
            first_fetch=first_fetch,
            create_relationships=create_relationships,
            timeout=timeout,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, args)
            return_results(result)

        elif command == "fetch-indicators":
            fetch_indicators_command(client=client)

        elif command == "crowdstrike-indicators-list":
            return_results(crowdstrike_indicators_list_command(client, args))

        elif command == "crowdstrike-reset-fetch-indicators":
            return_results(reset_last_run())

    # Log exceptions and return errors
    except Exception as e:
        error_trace = traceback.format_exc()
        diagnostic_log(f"CRITICAL ERROR in main: {str(e)}", "error")
        diagnostic_log(f"Stack trace: {error_trace}", "error")
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
