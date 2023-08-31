from CommonServerPython import *


def find_age(create_date):
    time_diff = datetime.now() - datetime.strptime(create_date, "%Y-%m-%d")
    return time_diff.days


def find_indicator_reputation(domain_age, proximity_score, threat_profile_score):
    proximity_score_threshold = int(demisto.args().get('proximity_score_threshold', 70))
    age_threshold = int(demisto.args().get('age_threshold', 7))
    threat_profile_score_threshold = int(demisto.args().get('threat_profile_score_threshold', 70))

    if proximity_score > proximity_score_threshold or threat_profile_score > threat_profile_score_threshold:
        return 'Bad'
    elif domain_age < age_threshold and (
            proximity_score < proximity_score_threshold or threat_profile_score < threat_profile_score_threshold):
        return 'Suspicious'
    else:
        return 'Good'


def main():
    domaintools_data = demisto.args().get("domaintools_data", None)

    human_readable_str = "No context data for domain."
    if domaintools_data:
        domain_name = domaintools_data.get("Name")
        domaintools_hosting_data = domaintools_data.get("Hosting", {})
        domaintools_identity_data = domaintools_data.get("Identity", {})
        domaintools_analytics_data = domaintools_data.get("Analytics", {})

        create_date = domaintools_data.get("Registration", {}).get("CreateDate")
        domain_age = 0
        if create_date:
            domain_age = find_age(create_date)

        try:
            threat_profile_score = domaintools_analytics_data.get(
                "ThreatProfileRiskScore", {}
            ).get("RiskScore", 0)
            proximity_risk_score = domaintools_analytics_data.get(
                "ProximityRiskScore", 0
            )
            reputation = find_indicator_reputation(domain_age, proximity_risk_score, threat_profile_score)
        except Exception:
            reputation = "Unknown"

        demisto_indicator = {
            "type": "Domain",
            "value": domain_name,
            "source": "DomainTools",
            "reputation": reputation,
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

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": {},
            "HumanReadable": human_readable_str,
            "EntryContext": {},
        }
    )


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
