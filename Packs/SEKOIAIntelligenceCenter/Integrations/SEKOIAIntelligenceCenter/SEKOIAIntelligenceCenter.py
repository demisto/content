import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""SEKOIA.IO Integration for Cortex XSOAR (aka Demisto)
"""
import ipaddress
import traceback

import urllib3
from stix2patterns.pattern import Pattern as PatternParser  # noqa: E402


# Disable insecure warnings
urllib3.disable_warnings()

DOC_MAPPING = {
    "GetObservable": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Observables/operation/get_observables",  # noqa
    "GetIndicator": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator",  # noqa
    "GetIndicatorContext": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator_context",  # noqa
    "ip": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator_context",  # noqa
    "url": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator_context",  # noqa
    "domain": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator_context",  # noqa
    "file": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator_context",  # noqa
    "email": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator_context",  # noqa
    "test-module": "https://docs.sekoia.io/getting_started/generate_api_keys/",  # noqa
}

DBOTSCORE_MAPPING = {
    "anomalous-activity": Common.DBotScore.BAD,
    "compromised": Common.DBotScore.BAD,
    "attribution": Common.DBotScore.BAD,
    "anonymization": Common.DBotScore.SUSPICIOUS,
    "malicious-activity": Common.DBotScore.SUSPICIOUS,
    "benign": Common.DBotScore.GOOD,
}

REPUTATION_MAPPING = {
    "domain": "domain-name",
    "url": "url",
    "file": "file",
    "email": "email-addr",
}

INTEGRATION_NAME = "SEKOIAIntelligenceCenter"

BASE_URL = "https://app.sekoia.io"

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the SEKOIA.IO API"""

    def get_validate_resource(self) -> str:
        """
        Request Sekoia.io to validate the API Key
        """
        try:
            self._http_request(
                method="GET",
                url_suffix="/v1/auth/validate",
                raise_on_status=True,
            )
            return "ok"
        except DemistoException as e:
            raise DemistoException(f"{INTEGRATION_NAME} error: the request failed due to: {e}")

    def get_observable(self, value: str, indicator_type: str) -> dict:
        """Request Sekoia.io CTI observable endpoint and return the API response

        :type value: ``str``
        :param value: indicator to get the context for

        :type indicator_type: ``str``
        :param indicator_type: type of the indicator

        :return: dict containing the context as returned from the API
        :rtype: ``dict[str, str]``
        """

        return self._http_request(
            method="GET",
            url_suffix="/v2/inthreat/observables",
            params={"match[value]": value, "match[type]": indicator_type},
        )

    def get_indicator(self, value: str, indicator_type: str) -> dict:
        """Request Sekoia.io CTI indicator endpoint and return the API response

        :type value: ``str``
        :param value: indicator to get the context for

        :type indicator_type: ``str``
        :param indicator_type: type of the indicator

        :return: dict containing the context as returned from the API
        :rtype: ``dict[str, str]``
        """

        return self._http_request(
            method="GET",
            url_suffix="/v2/inthreat/indicators",
            params={"value": value, "type": indicator_type},
        )

    def get_indicator_context(self, value: str, indicator_type: str) -> dict:
        """Request Sekoia.io CTI indicator context endpoint and return the API response

        :type value: ``str``
        :param value: indicator to get the context for

        :type type: ``str``
        :param type: type of the indicator

        :return: dict containing the context as returned from the API
        :rtype: ``dict[str, str]``
        """

        return self._http_request(
            method="GET",
            url_suffix="/v2/inthreat/indicators/context",
            params={"value": value, "type": indicator_type},
        )


""" HELPER FUNCTIONS """


def ip_version(ip: str | None) -> str | None:
    """Return the STIX type of the provided IP (ipv4-addr or ipv6-addr)"""
    if not ip:
        return None
    ip_version = ipaddress.ip_address(ip).version
    return f"ipv{ip_version}-addr"


def get_reputation_score(indicator_types: list[str]) -> int:
    """
    Return DBotScore based on indicator_types.
    Default score is Unknown
    """

    for indicator_type in indicator_types:
        dbotscore = DBOTSCORE_MAPPING.get(indicator_type)
        if dbotscore:
            return dbotscore

    return Common.DBotScore.NONE


def extract_indicator_from_pattern(stix_object: dict) -> str:
    """
    Extract indicator from STIX indicator pattern.
    i.e.
        [ipv4-addr:value = '198.51.100.1/32'] => 198.51.100.1/32
        [ipv4-addr:value = '198.51.100.1/32' OR ipv4-addr:value = '203.0.113.33/32'] => 198.51.100.1/32
    """
    if 'pattern' not in stix_object:
        return stix_object['name']

    pattern = PatternParser(stix_object['pattern'])
    data = pattern.inspect()

    # item looks like [(['value'], '=', "'198.51.100.1/32'")]
    item = next(iter(data.comparisons.values()))
    return item[0][2].strip("'")


def extract_file_indicator_hashes(pattern_str: str) -> dict:
    """
    Extract hashes composing the STIX indicator pattern
    """
    hashes = {"sha512": "", "sha256": "", "sha1": "", "md5": ""}

    # Remove enclosing brackets
    pattern_str = pattern_str.strip("[]")
    stix_object_hashes = pattern_str.split("OR")
    for object_hash in stix_object_hashes:
        if "SHA-512" in object_hash:
            hashes["sha512"] = object_hash.split("=")[1].strip(" '")
        if "SHA-256" in object_hash:
            hashes["sha256"] = object_hash.split("=")[1].strip(" '")
        if "SHA-1" in object_hash:
            hashes["sha1"] = object_hash.split("=")[1].strip(" '")
        if "MD5" in object_hash:
            hashes["md5"] = object_hash.split("=")[1].strip(" '")

    return hashes


def get_reliability_score(confidence: int) -> str:
    # Based on "Admiralty Credibility" table see
    # https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_1v6elyto0uqg

    if confidence in range(80, 100):
        return DBotScoreReliability.A_PLUS
    if confidence in range(60, 79):
        return DBotScoreReliability.A
    if confidence in range(40, 59):
        return DBotScoreReliability.B
    if confidence in range(20, 39):
        return DBotScoreReliability.C
    if confidence in range(1, 19):
        return DBotScoreReliability.D
    if confidence == 0:
        return DBotScoreReliability.E
    else:
        return DBotScoreReliability.F


def get_tlp(object_marking_refs: list[str], stix_bundle: dict) -> str:
    """
    Retrieve marking-definition object from object_marking_refs and return TLP
    If no TLP where found, return "RED" by default
    """
    for object_marking_ref in object_marking_refs:
        for stix_object in stix_bundle["objects"]:
            if stix_object["id"] == object_marking_ref and stix_object.get("definition_type") == "tlp":
                return stix_object["definition"]["tlp"]

    return "red"


def get_stix_object_reputation(stix_bundle: dict, stix_object: dict, is_unknown: bool) -> Optional[CommandResults]:
    """ "
    Transform a STIX object into a Cortex XSOAR indicator
    """

    reputation_score: int = get_reputation_score(stix_object.get("indicator_types", []))
    reliability_score: str = get_reliability_score(int(stix_object.get("confidence", -1)))
    tlp: str = get_tlp(stix_object.get("object_marking_refs", []), stix_bundle)
    if "ipv4-addr" in stix_object["x_ic_observable_types"] or "ipv6-addr" in stix_object["x_ic_observable_types"]:
        return get_ip_indicator_reputation(stix_object, reputation_score, reliability_score, tlp, is_unknown)
    if "file" in stix_object["x_ic_observable_types"]:
        return get_file_indicator_reputation(stix_object, reputation_score, reliability_score, tlp, is_unknown)
    if "domain-name" in stix_object["x_ic_observable_types"]:
        return get_domain_indicator_reputation(stix_object, reputation_score, reliability_score, tlp, is_unknown)
    if "url" in stix_object["x_ic_observable_types"]:
        return get_url_indicator_reputation(stix_object, reputation_score, reliability_score, tlp, is_unknown)
    if "email-addr" in stix_object["x_ic_observable_types"]:
        return get_email_indicator_reputation(stix_object, reputation_score, reliability_score, tlp, is_unknown)
    return None


def get_ip_indicator_reputation(
    stix_object: dict,
    reputation_score: int,
    reliability_score: str,
    tlp: str,
    is_unknown: bool
) -> CommandResults:
    """
    Return stix_object of type IP as indicator
    """
    dbot_score = Common.DBotScore(
        indicator=stix_object["name"],
        indicator_type=DBotScoreType.IP,
        integration_name=INTEGRATION_NAME,
        score=reputation_score,
        reliability=reliability_score,
        message='No results found.' if is_unknown else None
    )

    indicator_value: str = extract_indicator_from_pattern(stix_object)

    ip = Common.IP(
        ip=indicator_value,
        dbot_score=dbot_score,
        traffic_light_protocol=tlp,
    )
    return CommandResults(
        outputs_prefix="SEKOIAIntelligenceCenter.IP",
        outputs_key_field="name",
        outputs=None if is_unknown else stix_object,
        indicator=ip,
    )


def get_file_indicator_reputation(stix_object: dict, reputation_score: int, reliability_score: str,
                                  tlp: str, is_unknown: bool) -> CommandResults:
    """
    Return stix_object of type file as indicator
    """

    if is_unknown:
        return create_indicator_result_with_dbotscore_unknown(stix_object["name"], DBotScoreType.FILE, reliability_score)

    hashes = extract_file_indicator_hashes(stix_object['pattern'])

    dbot_score = Common.DBotScore(
        indicator=hashes["md5"],
        indicator_type=DBotScoreType.FILE,
        integration_name=INTEGRATION_NAME,
        score=reputation_score,
        reliability=reliability_score,
    )

    file = Common.File(
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        sha512=hashes["sha512"],
        dbot_score=dbot_score,
        traffic_light_protocol=tlp,
    )

    return CommandResults(
        outputs_prefix="SEKOIAIntelligenceCenter.File",
        outputs_key_field="name",
        outputs=stix_object,
        indicator=file
    )


def get_domain_indicator_reputation(stix_object: dict, reputation_score: int, reliability_score: str,
                                    tlp: str, is_unknown: bool) -> CommandResults:
    """
    Return stix_object of type domain as indicator
    """

    dbot_score = Common.DBotScore(
        indicator=stix_object["name"],
        indicator_type=DBotScoreType.DOMAIN,
        integration_name=INTEGRATION_NAME,
        score=reputation_score,
        reliability=reliability_score,
        message='No results found.' if is_unknown else None
    )

    domain_name = extract_indicator_from_pattern(stix_object)
    domain = Common.Domain(
        domain=domain_name,
        dbot_score=dbot_score,
        traffic_light_protocol=tlp,
    )

    return CommandResults(
        outputs_prefix="SEKOIAIntelligenceCenter.Domain",
        outputs_key_field="name",
        outputs=None if is_unknown else stix_object,
        indicator=domain,
    )


def get_url_indicator_reputation(stix_object: dict, reputation_score: int,
                                 reliability_score: str, tlp: str,
                                 is_unknown: bool) -> CommandResults:
    """
    Return stix_object of type url as indicator
    """

    dbot_score = Common.DBotScore(
        indicator=stix_object["name"],
        indicator_type=DBotScoreType.URL,
        integration_name=INTEGRATION_NAME,
        score=reputation_score,
        reliability=reliability_score,
        message='No results found.' if is_unknown else None
    )

    url_addr = extract_indicator_from_pattern(stix_object)
    url = Common.URL(
        url=url_addr,
        dbot_score=dbot_score,
        traffic_light_protocol=tlp,
    )

    return CommandResults(
        outputs_prefix="SEKOIAIntelligenceCenter.URL",
        outputs_key_field="name",
        outputs=None if is_unknown else stix_object,
        indicator=url,
    )


def get_email_indicator_reputation(
    stix_object: dict, reputation_score: int, reliability_score: str,
    tlp: str, is_unknown: bool
) -> CommandResults | None:
    """
    Return stix_object of type email as indicator
    """
    dbot_score = Common.DBotScore(
        indicator=stix_object["name"],
        indicator_type=DBotScoreType.EMAIL,
        integration_name=INTEGRATION_NAME,
        score=reputation_score,
        reliability=reliability_score,
        message='No results found.' if is_unknown else None
    )

    email_addr = extract_indicator_from_pattern(stix_object)
    if not email_addr:
        return None

    email = Common.EMAIL(
        address=email_addr,
        domain=email_addr.split("@")[-1],
        dbot_score=dbot_score,
        traffic_light_protocol=tlp,
    )

    return CommandResults(
        outputs_prefix="SEKOIAIntelligenceCenter.EMAIL",
        outputs_key_field="name",
        outputs=None if is_unknown else stix_object,
        indicator=email,
    )


def indicator_context_to_markdown(indicator_context: dict) -> str:
    """
    Find first level relationships with the stix bundle indicator
    Return the data to display as markdown

    Workflow:
    1. Find where main indicator ID is a source_ref in a relationship
    2. Use relationship's target_ref to find the linked object
    """
    table_headers = [
        "name",
        "description",
        "type",
        "aliases",
        "goals",
        "revoked",
        "created",
        "modified",
        "more_info",
    ]
    indicator_id = ""
    markdown = ""
    # Read every items of the response
    for stix_bundle in indicator_context["items"]:
        new_list_of_objects = []
        # Read every objects of the bundle
        indicator_name = ""
        for stix_object in stix_bundle["objects"]:
            # Get the ID of the STIX bundle's indicator
            if stix_object["type"] == "indicator":
                indicator_id = stix_object["id"]
                indicator_name = stix_object["name"]

        # Retrieve STIX objects relationships where source_refs is the indicator ID
        linked_stix_objects_refs: list = [
            stix_object.get("target_ref")
            for stix_object in stix_bundle["objects"]
            if stix_object.get("source_ref", "") == indicator_id
        ]

        if linked_stix_objects_refs:
            # Retrieve STIX objects which are the target in the relationship
            linked_stix_objects = [
                stix_object for stix_object in stix_bundle["objects"] if stix_object["id"] in linked_stix_objects_refs
            ]

            # Add "more_info" link, which redirect to SEKOIA Intelligence Center
            for linked_object in linked_stix_objects:
                linked_object["more_info"] = (
                    f'[More info about {linked_object["name"]}'
                    f' on SEKOIA.IO]({BASE_URL}/intelligence/objects/{linked_object["id"]})'
                )
                new_list_of_objects.append(linked_object)

            markdown += tableToMarkdown(
                name=f"Indicator {indicator_name} is linked to the following:",
                t=new_list_of_objects,
                headers=table_headers,
            )
    return markdown


def extract_indicators(indicator: dict, indicator_context: dict) -> list:
    """
    Return each indicators of the STIX bundles as a list of CommandResults
    """
    # Indicator context for empty API response
    if indicator_context["items"] == []:
        stix_object = {
            "name": indicator["value"],
            "x_ic_observable_types": [indicator["type"]],
        }

        object_reputation = get_stix_object_reputation(stix_bundle={}, stix_object=stix_object, is_unknown=True)

        if object_reputation:
            object_reputation.readable_output = tableToMarkdown(name=f'{INTEGRATION_NAME}:',
                                                                t={indicator["type"]: indicator["value"], 'Result': 'Not found'},
                                                                headers=[indicator["type"], 'Result'])

        return [object_reputation]

    # Indicator context for known indicator
    command_results_list: list = []
    for stix_bundle in indicator_context["items"]:
        for stix_object in stix_bundle["objects"]:
            if stix_object["type"] == "indicator":
                object_reputation = get_stix_object_reputation(stix_bundle, stix_object, is_unknown=False)
                if object_reputation:
                    command_results_list.append(object_reputation)

    return command_results_list


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: Client

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    # Check a JWT token’s validity
    # https://docs.sekoia.io/develop/rest_api/identity_and_authentication/#tag/User-Authentication/operation/get_validate_resource

    try:
        client.get_validate_resource()
    except DemistoException as e:
        doc = """Please visit the API Key documentation for more information:
         https://docs.sekoia.io/getting_started/generate_api_keys/"""

        if "T300" in str(e):
            return f"Authorization Error: The token is invalid. {doc}"
        elif "T301" in str(e):
            return f"Authorization Error: The token has expired. {doc}"
        elif "T302" in str(e):
            return f"Authorization Error: The token has been revoked. {doc}"
        else:
            raise e
    return "ok"


def get_observable_command(client: Client, args: dict[str, str]) -> CommandResults:
    """ip command: Returns IP reputation for a list of IPs

    :type client: ``Client``
    :param Client: SEKOIA.IO client to use

    :type args: ``dict[str, str]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['indicator']`` is a list of indicators or a single indicator

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains indicators

    :rtype: ``CommandResults``
    """

    indicator_value = args.get("value")
    indicator_type = args.get("type")
    if not indicator_value or not indicator_type:
        raise ValueError(f"incomplete command for value {indicator_value} and type {indicator_type}")

    result = client.get_observable(value=indicator_value, indicator_type=indicator_type)
    indicator = {"value": indicator_value, "type": indicator_type}
    outputs = {"indicator": indicator, "items": result.get("items", [])}

    if result["items"] == []:
        markdown = f"### {indicator_value} of type {indicator_type} is an unknown observable."
    else:
        table_title = f'Observable {result["items"][0].get("value")}'
        table_headers = ["modified", "created"]
        markdown = tableToMarkdown(table_title, result["items"][0], headers=table_headers)
        table_headers = ["valid_from", "valid_until", "name"]
        markdown += tableToMarkdown(
            "Associated tags",
            result["items"][0].get("x_inthreat_tags"),
            headers=table_headers,
        )
        markdown += (
            f"Please consult the [dedicated page]"
            f'({BASE_URL}/intelligence/objects/{result["items"][0]["id"]}) for more information.\n'
        )

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="SEKOIAIntelligenceCenter.Observable",
        outputs_key_field="ip",
        outputs=outputs,
    )


def get_indicator_command(client: Client, args: dict[str, str]) -> CommandResults:
    """get indicator command: Returns reputation for a list of indicator

    :type client: ``Client``
    :param Client: SEKOIA.IO client to use

    :type args: ``dict[str, str]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['indicator']`` is a list of indicators or a single indicator

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains indicators

    :rtype: ``CommandResults``
    """

    indicator_value = args.get("value")
    indicator_type = args.get("type")
    if not indicator_value or not indicator_type:
        raise ValueError(f"incomplete command for value {indicator_value} and type {indicator_type}")

    result = client.get_indicator(value=indicator_value, indicator_type=indicator_type)
    indicator = {"value": indicator_value, "type": indicator_type}
    outputs = {"indicator": indicator, "items": result.get("items", [])}

    # Format output
    if result["items"] == []:
        markdown = f"### {indicator_value} of type {indicator_type} is an unknown indicator."
    else:
        markdown = (
            f'### Indicator {result["items"][0].get("name")}'
            f' is categorized as {result["items"][0].get("indicator_types")}\n\n'
        )
        markdown += result["items"][0].get("description", "")
        table_headers = ["kill_chain_name", "phase_name"]
        markdown += tableToMarkdown(
            "Kill chain",
            result["items"][0].get("kill_chain_phases"),
            headers=table_headers,
        )
        markdown += (
            f"\n\nPlease consult the [dedicated page]"
            f'({BASE_URL}/intelligence/objects/{result["items"][0]["id"]}) for more information.\n'
        )

    return CommandResults(
        outputs_prefix="SEKOIAIntelligenceCenter.Analysis",
        outputs=outputs,
        readable_output=markdown,
        raw_response=result,
    )


def get_indicator_context_command(client: Client, args: dict[str, str]) -> list[CommandResults]:
    """ip command: Returns IP reputation for a list of IPs

    :type client: ``Client``
    :param Client: SEKOIA.IO client to use

    :type args: ``dict[str, str]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['indicator']`` is a list of indicators or a single indicator

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains indicators

    :rtype: ``CommandResults``
    """

    indicator = {"value": args.get("value"), "type": args.get("type")}
    if not indicator["value"] or not indicator["type"]:
        raise ValueError(f"incomplete command for {indicator}")

    indicator_context = client.get_indicator_context(value=indicator["value"], indicator_type=indicator["type"])
    outputs = {"indicator": indicator, "items": indicator_context.get("items", [])}

    if indicator_context["items"] == []:
        markdown = f"### {indicator['value']} of type {indicator['type']} is an unknown indicator."
    else:
        # Format output
        markdown = indicator_context_to_markdown(indicator_context)

    # Extract STIX object type indicator from the STIX bundles
    command_results_list: list = extract_indicators(indicator=indicator, indicator_context=indicator_context)

    command_results_list.append(
        CommandResults(
            outputs_prefix="SEKOIAIntelligenceCenter.IndicatorContext",
            readable_output=markdown,
            outputs=outputs,
            raw_response=indicator_context,
        )
    )
    return command_results_list


def get_stix_type(indicator: str, indicator_type) -> str | None:
    """Convert Demisto reputation command type to STIX (ex. email = email-addr)"""
    if indicator_type == "ip":
        return ip_version(indicator)
    return REPUTATION_MAPPING.get(indicator_type)


def reputation_command(client: Client, args: dict[str, str], indicator_type) -> list[CommandResults]:
    """reputation command: Returns reputation for a list of indicator

    This command is a wrapper around the `get_indicator_context_command`
    """
    indicators = argToList(args[indicator_type])
    results: list[CommandResults] = []
    for indicator in indicators:
        stix_type = get_stix_type(indicator, indicator_type)
        if stix_type is None:
            raise ValueError(f"Type {indicator_type=} is not a valid type")

        args = {"value": indicator, "type": stix_type}
        results += get_indicator_context_command(client=client, args=args)
    return results


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get("apikey")
    if not api_key:
        demisto.error("API Key is missing")

    # get the service API url
    BASE_URL = urljoin(demisto.params().get("url", "https://app.sekoia.io"), "/")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}

        client = Client(base_url=BASE_URL, verify=verify_certificate, headers=headers, proxy=proxy)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            # https://api.sekoia.io/v1/apiauth/auth/validate
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "GetObservable":
            return_results(get_observable_command(client, demisto.args()))

        elif demisto.command() == "GetIndicator":
            return_results(get_indicator_command(client, demisto.args()))

        elif demisto.command() == "GetIndicatorContext":
            return_results(get_indicator_context_command(client, demisto.args()))

        elif demisto.command() in ["ip", "url", "domain", "file", "email"]:
            return_results(reputation_command(client, demisto.args(), indicator_type=demisto.command()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()=} {demisto.args()=}. "
            f"\nError:\n{str(e)} please consult endpoint documentation {DOC_MAPPING.get(demisto.command())}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
