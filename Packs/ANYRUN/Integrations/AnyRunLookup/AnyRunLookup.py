import json
import demistomock as demisto
from CommonServerPython import *

from anyrun.connectors import LookupConnector
from anyrun import RunTimeException

VERSION = "PA-XSOAR:2.1.0"

DBOT_SCORE_TYPE_RESOLVER = {
    "destination_ip": DBotScoreType.IP,
    "domain_name": DBotScoreType.DOMAIN,
    "url": DBotScoreType.URL,
    "sha256": DBotScoreType.FILE,
}

DBOT_SCORE_RESOLVER = {0: 0, 1: 2, 2: 3}

LOOKUP_INDICATOR_TYPE_RESOLVER = {
    "destination_ip": "destinationIP",
    "domain_name": "domainName",
    "url": "url",
    "sha256": "sha256",
}

VERDICT_RESOLVER = {
    0: "No info",
    1: "Suspicious",
    2: "Malicious",
}


def test_module(params: dict) -> str:  # pragma: no cover
    """Performs ANY.RUN API call to verify integration is operational"""
    try:
        with LookupConnector(get_authentication(params), integration=VERSION, verify_ssl=not params.get("insecure")) as connector:
            connector.check_authorization()
            return "ok"
    except RunTimeException as exception:
        return str(exception)


def get_authentication(params: dict) -> str:
    """
    Builds API verification data using demisto params

    :param params: Demisto params
    :return: API-KEY verification string
    """
    return f"API-KEY {params.get('credentials', {}).get('password')}"


def generate_lookup_reference(indicator_type: str, indicator_value: str) -> str:
    """Generates ANY.RUN TI Lookup hyperlink"""
    return (
        "https://intelligence.any.run/analysis/lookup#{%22query%22:%22"
        + LOOKUP_INDICATOR_TYPE_RESOLVER.get(indicator_type, "")
        + ":%5C%22"
        + indicator_value
        + "%5C%22%22,%22dateRange%22:180}"
    )


def generate_indicators(
    report: dict, parent_indicator_value: str, parent_indicator_type: str, reliability: str
) -> list[EntityRelationship] | None:
    """
    Converts ANY.RUN indicators to the Demisto relationships

    :param report: ANY.RUN TI Lookup Summary
    :param parent_indicator_value: Indicator value
    :param parent_indicator_type: Indicator type
    :param reliability: Source reliability
    :return: The collection of the relationships
    """
    related_indicators = []

    if domains := report.get("relatedDNS"):
        for domain in domains:
            related_indicators.append(
                EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=parent_indicator_value,
                    entity_a_type=parent_indicator_type,
                    entity_b=domain.get("domainName"),
                    entity_b_type=FeedIndicatorType.Domain,
                    brand="ANY.RUN TI Lookup",
                    source_reliability=reliability,
                )
            )

    if urls := report.get("relatedURLs"):
        for url in urls:
            related_indicators.append(
                EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=parent_indicator_value,
                    entity_a_type=parent_indicator_type,
                    entity_b=url.get("url"),
                    entity_b_type=FeedIndicatorType.URL,
                    brand="ANY.RUN TI Lookup",
                    source_reliability=reliability,
                )
            )

    if files := report.get("relatedFiles"):
        for file in files:
            if (sha256 := file.get("hashes").get("sha256")) == parent_indicator_value:
                continue
            related_indicators.append(
                EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=parent_indicator_value,
                    entity_a_type=parent_indicator_type,
                    entity_b=sha256,
                    entity_b_type=FeedIndicatorType.File,
                    brand="ANY.RUN TI Lookup",
                    source_reliability=reliability,
                )
            )

    return related_indicators


def parse_results(report: dict, reliability: str, indicator_value: str, indicator_type: str) -> CommandResults:
    """
    Generates reputation command outputs

    :param report: ANY.RUN TI Lookup summary
    :param reliability: Source reliability
    :param indicator_value: Indicator type
    :param indicator_type: Indicator value
    :return: Demisto Command results
    """
    output_context = {}
    outputs_prefix = ""
    outputs_key_field = ""
    indicator: Common.IP | Common.Domain | Common.URL | Common.File | None = None
    relationship = generate_indicators(report, indicator_value, FeedIndicatorType.IP, reliability)
    dbot_score = Common.DBotScore(
        indicator=indicator_value,
        indicator_type=DBOT_SCORE_TYPE_RESOLVER.get(indicator_type),
        reliability=reliability,
        integration_name="ANY.RUN TI Lookup",
        score=DBOT_SCORE_RESOLVER.get(report.get("summary", {}).get("threatLevel"), 0),
    )

    if indicator_type == "destination_ip":
        indicator = Common.IP(indicator_value, dbot_score)
        outputs_prefix = "IP"
        outputs_key_field = "Address"
        output_context["Address"] = indicator_value
    elif indicator_type == "domain_name":
        indicator = Common.Domain(indicator_value, dbot_score)
        outputs_prefix = "Domain"
        outputs_key_field = "Name"
        output_context["Name"] = indicator_value
    elif indicator_type == "url":
        indicator = Common.URL(indicator_value, dbot_score)
        outputs_prefix = "URL"
        outputs_key_field = "Data"
        output_context["Url"] = indicator_value
    elif indicator_type == "sha256":
        if info := report.get("relatedFiles"):
            outputs_prefix = "File"
            outputs_key_field = "Name"
            file_info = info[0]
            ext = file_info.get("fileExtension")
            path = file_info.get("fileName") + f".{ext}"
            name = path.split("\\")[-1]
            md5 = file_info.get("hashes").get("md5")
            sha1 = file_info.get("hashes").get("sha1")
            ssdeep = file_info.get("hashes").get("ssdeep")

            indicator = Common.File(
                dbot_score, name=name, sha256=indicator_value, extension=ext, path=path, md5=md5, sha1=sha1, ssdeep=ssdeep
            )

            output_context["Name"] = name
            output_context["Path"] = path
            output_context["Extensions"] = ext
            output_context["SHA256"] = indicator_value
            output_context["SHA1"] = sha1
            output_context["MD5"] = md5

            output_context["SSDeep"] = ssdeep

    if indicator_type != "sha256":
        if geo := report.get("destinationIPgeo"):
            output_context["Country"] = geo[0].upper()

        if port := report.get("destinationPort"):
            output_context["Port"] = port[0]

    if indicator_type in ("domain_name", "destination_ip"):
        if asn := report.get("destinationIpAsn"):
            output_context["ASOwner"] = asn[0].get("asn").upper()

        output_context["LastModified"] = report.get("summary", {}).get("lastSeen")

    if tags := report.get("summary", {}).get("tags"):
        output_context["Tags"] = ",".join(tags)

    if industries := report.get("industries", {}):
        output_context["Industries"] = ",".join(
            [
                industry.get('industryName') for industry in
                sorted(industries, key=lambda x: x['confidence'], reverse=True)
            ]
        )

    output_context["Verdict"] = VERDICT_RESOLVER.get(
        report.get("summary", {}).get("threatLevel", 0), "No info"
    )

    return_results(
        CommandResults(
            outputs_prefix="ANYRUN.LookupURL",
            outputs=f"Link to the TI Lookup request: {generate_lookup_reference(indicator_type, indicator_value)}",
            ignore_auto_extract=True,
        )
    )

    return CommandResults(
        raw_response=report,
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=output_context,
        indicator=indicator,
        tags=tags,
        relationships=relationship,
    )


def get_enrichment(params: dict, indicator_type: str, args: str):
    """
    Implements Demisto reputation command

    :param params: Demisto params
    :param indicator_type: Indicator type
    :param args: Demisto args
    """
    indicators = argToList(args)
    results = []

    with LookupConnector(get_authentication(params), integration=VERSION, verify_ssl=not params.get("insecure")) as connector:
        for indicator in indicators:
            intelligence = connector.get_intelligence(**{indicator_type: indicator}, lookup_depth=180)
            results.append(parse_results(intelligence, params.get("integrationReliability", ""), indicator, indicator_type))

    return results


def get_intelligence(params: dict, args: dict) -> None:  # pragma: no cover
    """
    Initialize TI Lookup search

    :param params: Demisto params
    :param args: Demisto args
    """
    try:
        if args.get("lookup_depth"):
            args["lookup_depth"] = int(args["lookup_depth"])
    except ValueError:
        raise ValueError("The value of the lookup_depth parameter must be an integer-like")

    with LookupConnector(get_authentication(params), integration=VERSION, verify_ssl=not params.get("insecure")) as connector:
        intelligence = connector.get_intelligence(**args)

    return_results(fileResult("anyrun_lookup_summary.json", json.dumps(intelligence).encode()))

    command_results = CommandResults(
        outputs_key_field="destinationIP",
        outputs_prefix="ANYRUN.Lookup",
        outputs=intelligence,
        ignore_auto_extract=True,
    )

    return_results(command_results)


def main():  # pragma: no cover
    """Main Execution block"""
    params = demisto.params()
    args = demisto.args()

    if params.get("proxy"):
        handle_proxy()

    try:
        if demisto.command() == "anyrun-get-intelligence":
            get_intelligence(params, args)
        elif demisto.command() == "test-module":
            result = test_module(params)
            return_results(result)
        elif demisto.command() == "ip":
            result = get_enrichment(params, "destination_ip", args.get("ip"))
            return_results(result)
        elif demisto.command() == "domain":
            result = get_enrichment(params, "domain_name", args.get("domain"))
            return_results(result)
        elif demisto.command() == "url":
            result = get_enrichment(params, "url", args.get("url"))
            return_results(result)
        elif demisto.command() == "file":
            result = get_enrichment(params, "sha256", args.get("file"))
            return_results(result)
        else:
            raise NotImplementedError(f"Command {demisto.command()} is not implemented")
    except RunTimeException as exception:
        return_error(exception.description, error=str(exception.json))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
