from CheckPivotableDomains import main

from CommonServerPython import *


def test_check_pivotable_output(mocker):
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
                "Name": {"value": "just a test", "count": 200},
                "Phone": {"value": "", "count": 0},
                "Street": {"value": "", "count": 0},
                "City": {"value": "", "count": 0},
                "State": {"value": "CA", "count": 18232716},
                "Postal": {"value": "", "count": 0},
                "Org": {"value": "Palo Alto Networks, Inc.", "count": 200},
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
                    "host": {"value": "pdns112.ultradns.net", "count": 200},
                    "domain": {"value": "ultradns.net", "count": 200},
                    "ip": [{"value": "156.154.65.112", "count": 200}],
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
                        "count": 10,
                    },
                    "subject": {"value": "CN=demisto.com", "count": 2},
                    "organization": {"value": "just a test org", "count": 20},
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
            "domaintools_data": domaintools_data,
            "max_name_server_host_count": "250",
            "max_name_server_ip_count": "250",
            "max_name_server_domain_count": "250",
            "max_registrant_contact_name_count": "250",
            "max_registrant_org_count": "250",
            "max_registrar_count": "200",
            "max_ssl_info_organization_count": "350",
            "max_ssl_info_hash_count": "350",
            "max_ssl_email_count": "350",
            "max_ssl_subject_count": "350",
            "max_soa_email_count": "200",
            "max_ip_address_count": "200",
            "max_mx_ip_count": "200",
            "max_mx_host_count": "200",
            "max_mx_domain_count": "200",
            "max_google_adsense_count": "200",
            "max_google_analytics_count": "200",
        }
    )
    mocker.patch.object(demisto, "results")
    main()

    expected_context = {
        "Name": "demisto.com",
        "PivotableRegistrantContactName": {
            "pivotable": True,
            "items": {"count": 200, "value": "just a test"}
        },
        "PivotableRegistrantOrg": {
            "pivotable": True,
            "items": {"count": 200, "value": "Palo Alto Networks, Inc."}
        },
        "PivotableRegistrar": {
            "pivotalbe": False
        },
        "PivotableSslInfoOrganization": {
            "pivotable": True,
            "items": [{"count": 20,
                       "value": "just a test org"}]
        },
        "PivotableSslInfoHash": {
            "pivotable": True,
            "items": [{"count": 10,
                       "value": "9eb6468deaea5a1c9d022ebaa3694e9ce2f9dce8"}]
        },
        "PivotableSslSubject": {
            "pivotable": True,
            "items": [{"count": 2,
                       "value": "CN=demisto.com"}]
        },
        "PivotableSslEmail": {
            "pivotable": False
        },
        "PivotableNameServerHost": {
            "pivotable": True,
            "items": [{"count": 200,
                       "value": "pdns112.ultradns.net"}]
        },
        "PivotableNameServerIp": {
            "pivotable": True,
            "items": [{"count": 200,
                       "value": '156.154.65.112'}]
        },
        "PivotableNameServerDomain": {
            "pivotable": True,
            "items": [{"count": 200,
                       "value": "ultradns.net"}]
        },
        "PivotableSoaEmail": {
            "pivotable": True,
            "items": [
                {
                    "count": 34,
                    "value": "it-staff-sysadmin@paloaltonetworks.com"
                }
            ]
        },
        "PivotableIpAddress": {
            "pivotable": True,
            "items": [
                {
                    "count": 16,
                    "value": "34.120.160.120"
                }
            ]
        },
        "PivotableMxIp": {
            "pivotable": False
        },
        "PivotableMxHost": {
            "pivotable": False
        },
        "PivotableMxDomain": {
            "pivotable": False
        },
        "PivotableGoogleAnalytics": {
            "pivotable": False
        },
        "PivotableAdsense": {
            "pivotable": False
        }
    }

    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["Type"] == entryTypes["note"]
    assert results[0]["ContentsFormat"] == formats["json"]
    assert results[0]["Contents"] == expected_context
