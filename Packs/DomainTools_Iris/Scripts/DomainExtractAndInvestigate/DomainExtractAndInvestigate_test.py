from DomainExtractAndInvestigate import main

from CommonServerPython import *


def test_domain_extract_and_investigate_output(mocker):
    domaintools_data = {
        "Name": "demisto.com",
        "LastEnriched": "2023-11-10",
        "Analytics": {
            "OverallRiskScore": 0,
            "ProximityRiskScore": 0,
            "MalwareRiskScore": 0,
            "PhishingRiskScore": 0,
            "SpamRiskScore": 0,
            "ThreatProfileRiskScore": {"RiskScore": 0, "Threats": "", "Evidence": ""},
            "WebsiteResponseCode": 200,
            "GoogleAdsenseTrackingCode": {"value": "", "count": 0},
            "GoogleAnalyticTrackingCode": {"value": "", "count": 0},
            "Tags": [],
        },
        "Identity": {
            "RegistrantName": "",
            "RegistrantOrg": "Palo Alto Networks, Inc.",
            "RegistrantContact": {
                "Country": {"value": "us", "count": 275572451},
                "Email": [
                    {
                        "value": "select request email form at https://domains.markmonitor.com/whois/demisto.com",
                        "count": 1,
                    }
                ],
                "Name": {"value": "", "count": 0},
                "Phone": {"value": "", "count": 0},
                "Street": {"value": "", "count": 0},
                "City": {"value": "", "count": 0},
                "State": {"value": "CA", "count": 18232716},
                "Postal": {"value": "", "count": 0},
                "Org": {"value": "Palo Alto Networks, Inc.", "count": 645},
            },
            "Registrar": {"value": "MarkMonitor, Inc.", "count": 867819},
            "SOAEmail": [{"value": "it-staff-sysadmin@paloaltonetworks.com", "count": 34}],
            "SSLCertificateEmail": [],
            "AdminContact": {
                "Country": {"value": "us", "count": 275572451},
                "Email": [
                    {
                        "value": "select request email form at https://domains.markmonitor.com/whois/demisto.com",
                        "count": 1,
                    }
                ],
                "Name": {"value": "", "count": 0},
                "Phone": {"value": "", "count": 0},
                "Street": {"value": "", "count": 0},
                "City": {"value": "", "count": 0},
                "State": {"value": "CA", "count": 18232716},
                "Postal": {"value": "", "count": 0},
                "Org": {"value": "Palo Alto Networks, Inc.", "count": 645},
            },
            "TechnicalContact": {
                "Country": {"value": "us", "count": 275572451},
                "Email": [
                    {
                        "value": "select request email form at https://domains.markmonitor.com/whois/demisto.com",
                        "count": 1,
                    }
                ],
                "Name": {"value": "", "count": 0},
                "Phone": {"value": "", "count": 0},
                "Street": {"value": "", "count": 0},
                "City": {"value": "", "count": 0},
                "State": {"value": "CA", "count": 18232716},
                "Postal": {"value": "", "count": 0},
                "Org": {"value": "Palo Alto Networks, Inc.", "count": 645},
            },
            "BillingContact": {
                "Country": {"value": "", "count": 0},
                "Email": [],
                "Name": {"value": "", "count": 0},
                "Phone": {"value": "", "count": 0},
                "Street": {"value": "", "count": 0},
                "City": {"value": "", "count": 0},
                "State": {"value": "", "count": 0},
                "Postal": {"value": "", "count": 0},
                "Org": {"value": "", "count": 0},
            },
            "EmailDomains": ["markmonitor.com", "paloaltonetworks.com"],
            "AdditionalWhoisEmails": [
                {"value": "abusecomplaints@markmonitor.com", "count": 1291667},
                {"value": "whoisrequest@markmonitor.com", "count": 798372},
            ],
        },
        "Registration": {
            "RegistrarStatus": [
                "clientdeleteprohibited",
                "clienttransferprohibited",
                "clientupdateprohibited",
            ],
            "DomainStatus": True,
            "CreateDate": "2015-01-16",
            "ExpirationDate": "2028-01-16",
        },
        "Hosting": {
            "IPAddresses": [
                {
                    "address": {"value": "34.120.160.120", "count": 16},
                    "asn": [{"value": 396982, "count": 30156647}],
                    "country_code": {"value": "us", "count": 197334117},
                    "isp": {"value": "Google", "count": 56964370},
                }
            ],
            "IPCountryCode": "us",
            "MailServers": [
                {
                    "host": {"value": "mxa-00169c01.gslb.pphosted.com", "count": 1097},
                    "domain": {"value": "pphosted.com", "count": 148978},
                    "ip": [{"value": "67.231.156.123", "count": 854}],
                    "priority": 10,
                },
                {
                    "host": {"value": "mxb-00169c01.gslb.pphosted.com", "count": 1098},
                    "domain": {"value": "pphosted.com", "count": 148978},
                    "ip": [{"value": "67.231.156.123", "count": 854}],
                    "priority": 10,
                },
            ],
            "SPFRecord": "",
            "NameServers": [
                {
                    "host": {"value": "pdns112.ultradns.net", "count": 369},
                    "domain": {"value": "ultradns.net", "count": 800581},
                    "ip": [{"value": "156.154.65.112", "count": 369}],
                },
                {
                    "host": {"value": "pdns112.ultradns.com", "count": 369},
                    "domain": {"value": "ultradns.com", "count": 651583},
                    "ip": [{"value": "156.154.64.112", "count": 369}],
                },
                {
                    "host": {"value": "pdns112.ultradns.biz", "count": 369},
                    "domain": {"value": "ultradns.biz", "count": 648560},
                    "ip": [{"value": "156.154.66.112", "count": 369}],
                },
                {
                    "host": {"value": "pdns112.ultradns.org", "count": 369},
                    "domain": {"value": "ultradns.org", "count": 762389},
                    "ip": [{"value": "156.154.67.112", "count": 369}],
                },
            ],
            "SSLCertificate": [
                {
                    "hash": {
                        "value": "9eb6468deaea5a1c9d022ebaa3694e9ce2f9dce8",
                        "count": 1,
                    },
                    "subject": {"value": "CN=demisto.com", "count": 1},
                    "organization": {"value": "", "count": 0},
                    "email": [],
                    "alt_names": [
                        {"value": "blog.demisto.com", "count": 0},
                        {"value": "go.demisto.com", "count": 0},
                        {"value": "info.demisto.com", "count": 0},
                        {"value": "demisto.com", "count": 0},
                        {"value": "www.demisto.com", "count": 0},
                    ],
                    "common_name": {"value": "demisto.com", "count": 1},
                    "issuer_common_name": {
                        "value": "Go Daddy Secure Certificate Authority - G2",
                        "count": 18413841,
                    },
                    "not_after": {"value": 20240716, "count": 180059},
                    "not_before": {"value": 20230717, "count": 343154},
                    "duration": {"value": 365, "count": 10714248},
                }
            ],
            "RedirectsTo": {"value": "www.paloaltonetworks.com", "count": 16},
            "RedirectDomain": {"value": "paloaltonetworks.com", "count": 27},
        },
        "WebsiteTitle": "",
        "FirstSeen": "2015-01-16T00:00:00Z",
        "ServerType": "",
    }

    mocker.patch.object(
        demisto, "args", return_value={
            "url": b"demisto.com"
        }
    )

    mocker.patch.object(demisto, "executeCommand", return_value=[
        {
            "Contents": "demisto.com"
        }
    ])
    mocker.patch.object(demisto, "results", return_value=[
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": {"domain": "", "domaintools": domaintools_data}
        }
    ])
    main()
    assert demisto.results.call_count == 1

    results = demisto.results.return_value
    assert len(results) == 1

    assert results[0]["Type"] == entryTypes["note"]
    assert results[0]["ContentsFormat"] == formats["json"]
    assert "domaintools" in results[0]["Contents"]
    assert "domain" in results[0]["Contents"]
