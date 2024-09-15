from CommonServerPython import *
from typing import Any
from enum import Enum


class ReputationEnum(Enum):
    BAD = "Bad"
    SUSPICIOUS = "Suspicious"
    GOOD = "Good"
    UNKNOWN = "Unknown"


def find_age(first_seen: str) -> int:
    time_diff = datetime.utcnow() - datetime.strptime(first_seen, "%Y-%m-%dT%H:%M:%SZ")
    return time_diff.days


def find_indicator_reputation(domain_age: int, proximity_score: int, threat_profile_score: int) -> ReputationEnum:
    proximity_score_threshold = arg_to_number(
        demisto.args().get('proximity_score_threshold')) or 70
    age_threshold = arg_to_number(demisto.args().get('age_threshold')) or 7
    threat_profile_score_threshold = arg_to_number(
        demisto.args().get('threat_profile_score_threshold')) or 70

    if proximity_score > proximity_score_threshold or threat_profile_score > threat_profile_score_threshold:
        return ReputationEnum.BAD
    elif domain_age < age_threshold and (
            proximity_score < proximity_score_threshold or threat_profile_score < threat_profile_score_threshold):
        return ReputationEnum.SUSPICIOUS
    else:
        return ReputationEnum.GOOD


def format_attribute(attribute: list[dict], key: str = '') -> str:
    """Format list of attribute to str

    Args:
        attribute (list[dict]): The attribute to format
        key (str): The key to lookup, supports nested dict (e.g "host.value")

    Returns:
        str: The string formatted attribute
    """
    formatted_str = []
    for attr in attribute or []:
        if isinstance(attr, dict):
            keys = key.split(".")
            value = attr[keys[0]][keys[1]] if len(keys) > 1 else attr[keys[0]]
            formatted_str.append(value)
        else:  # for list only values
            formatted_str.append(attr)

    return ",".join(formatted_str) if formatted_str else ""


def set_indicator_table_data(args: dict[str, Any]) -> CommandResults:
    human_readable_str = "No context data for domain."
    required_keys = ("Name", "Hosting", "Identity", "Analytics")

    domaintools_data = args["domaintools_data"]
    if isinstance(domaintools_data, dict) and all(
        k in domaintools_data for k in required_keys
    ):
        domain_name = domaintools_data.get("Name")
        domaintools_hosting_data = domaintools_data.get("Hosting", {})
        domaintools_identity_data = domaintools_data.get("Identity", {})
        domaintools_analytics_data = domaintools_data.get("Analytics", {})

        first_seen = domaintools_data.get("FirstSeen") or ""
        domain_age = 0
        if first_seen:
            domain_age = find_age(first_seen)

        try:
            threat_profile_score = domaintools_analytics_data.get(
                "ThreatProfileRiskScore", {}
            ).get("RiskScore") or 0
            proximity_risk_score = domaintools_analytics_data.get(
                "ProximityRiskScore") or 0
            reputation = find_indicator_reputation(
                domain_age, proximity_risk_score, threat_profile_score)

        except Exception:
            reputation = ReputationEnum.UNKNOWN

        riskscore_component_mapping = {
            "ProximityRiskScore": domaintools_analytics_data.get("ProximityRiskScore") or "",
            "MalwareRiskScore": domaintools_analytics_data.get("MalwareRiskScore") or "",
            "PhishingRiskScore": domaintools_analytics_data.get("PhishingRiskScore") or "",
            "SpamRiskScore": domaintools_analytics_data.get("SpamRiskScore") or "",
            "ThreatProfileRiskScore": {"Evidence": domaintools_analytics_data.get("ThreatProfileRiskScore", {}).get("Evidence")}
        }

        domaintools_iris_indicator = {
            "type": "DomainTools Iris",
            "value": domain_name,
            "source": "DomainTools Iris",
            "reputation": reputation.value,
            "seenNow": "true",
            "domaintoolsirisdomainage": domain_age,
            "firstseen": first_seen,
            "domaintoolsirisriskscore": domaintools_analytics_data.get("OverallRiskScore"),
            "domaintoolsirisfirstseen": first_seen,
            "domaintoolsiristags": format_attribute(domaintools_analytics_data.get("Tags"), key="label"),
            "domaintoolsirisadditionalwhoisemails": format_attribute(domaintools_identity_data.get(
                "AdditionalWhoisEmails",
            ), key="value"),
            "emaildomains": format_attribute(domaintools_identity_data.get("EmailDomains")),
            "nameservers": format_attribute(domaintools_hosting_data.get("NameServers"), key="host.value"),
            "domaintoolsirisipaddresses": format_attribute(domaintools_hosting_data.get("IPAddresses"), key="address.value"),
            "domaintoolsirismailservers": format_attribute(domaintools_hosting_data.get("MailServers"), key="domain.value"),
            "domaintoolsirisipcountrycode": domaintools_hosting_data.get("IPCountryCode"),
            "domaintoolsirisregistrantorg": domaintools_identity_data.get("RegistrantOrg"),
            "registrantname": domaintools_identity_data.get("RegistrantName"),
            "domaintoolsirissoaemail": format_attribute(domaintools_identity_data.get("SOAEmail"), key="value"),
            "domaintoolsirisexpirationdate": domaintools_data.get("Registration", {}).get("ExpirationDate"),
            "domaintoolsirisriskscorecomponents": riskscore_component_mapping
        }

        demisto.info(
            f"Creating new domaintools iris indicator: {domaintools_iris_indicator}")
        demisto.executeCommand("createNewIndicator",
                               domaintools_iris_indicator)

        human_readable_str = f"Data for {domain_name} enriched."

    return CommandResults(readable_output=human_readable_str)


def main():
    try:
        return_results(set_indicator_table_data(demisto.args()))
    except Exception as ex:
        return_error(
            f"Failed to execute SetIndicatorTableData. Error: {str(ex)}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
