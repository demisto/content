from CommonServerPython import *
from typing import Dict, Any
from enum import Enum
import traceback


class ReputationEnum(Enum):
    BAD = "Bad"
    SUSPICIOUS = "Suspicious"
    GOOD = "Good"
    UNKNOWN = "Unknown"


def find_age(create_date: str) -> int:
    time_diff = datetime.now() - datetime.strptime(create_date, "%Y-%m-%d")
    return time_diff.days


def find_indicator_reputation(domain_age: int, proximity_score: int, threat_profile_score: int) -> ReputationEnum:
    proximity_score_threshold = arg_to_number(
        demisto.args().get('proximity_score_threshold', 70))
    age_threshold = arg_to_number(demisto.args().get('age_threshold', 7))
    threat_profile_score_threshold = arg_to_number(
        demisto.args().get('threat_profile_score_threshold', 70))

    if proximity_score > proximity_score_threshold or threat_profile_score > threat_profile_score_threshold:
        return ReputationEnum.BAD
    elif domain_age < age_threshold and (
            proximity_score < proximity_score_threshold or threat_profile_score < threat_profile_score_threshold):
        return ReputationEnum.SUSPICIOUS
    else:
        return ReputationEnum.GOOD


def set_indicator_table_data(args: Dict[str, Any]) -> CommandResults:
    human_readable_str = "No context data for domain."

    domaintools_data = args["domaintools_data"]
    if domaintools_data:
        domain_name = domaintools_data.get("Name")
        domaintools_hosting_data = domaintools_data.get("Hosting", {})
        domaintools_identity_data = domaintools_data.get("Identity", {})
        domaintools_analytics_data = domaintools_data.get("Analytics", {})

        create_date = domaintools_data.get(
            "Registration", {}).get("CreateDate")
        domain_age = 0
        if create_date:
            domain_age = find_age(create_date)

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

        demisto_indicator = {
            "type": "Domain",
            "value": domain_name,
            "source": "DomainTools",
            "reputation": reputation.value,
            "seenNow": "true",
            "ipaddresses": json.dumps(domaintools_hosting_data.get("IPAddresses")),
            "ipcountrycode": domaintools_hosting_data.get("IPCountryCode"),
            "mailservers": json.dumps(domaintools_hosting_data.get("MailServers")),
            "spfrecord": domaintools_hosting_data.get("SPFRecord"),
            "nameservers": domaintools_hosting_data.get("NameServers"),
            "sslcertificate": json.dumps(
                domaintools_hosting_data.get("SSLCertificate")
            ),
            "soaemail": domaintools_identity_data.get("SOAEmail"),
            "sslcertificateemail": domaintools_identity_data.get("SSLCertificateEmail"),
            "emaildomains": domaintools_identity_data.get("EmailDomains"),
            "additionalwhoisemails": domaintools_identity_data.get(
                "AdditionalWhoisEmails"
            ),
            "domainage": domain_age,
        }
        demisto.executeCommand("createNewIndicator", demisto_indicator)

        human_readable_str = "Data for {} enriched.".format(domain_name)

    return CommandResults(readable_output=human_readable_str)


def main():
    try:
        return_results(set_indicator_table_data(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(
            f"Failed to execute set_indicator_table_data. Error: {str(ex)}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
