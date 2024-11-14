import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


""" IMPORTS """


from json import dumps as json_dumps
from datetime import datetime

from dateparser import parse as dateparser_parse
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
from cyberintegrations import TIPoller
from traceback import format_exc
import re


# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

INDICATORS_TYPES = {
    "compromised/account_group": {
        "types": {
            "event_url": "URL",
            "event_domain": "Domain",
            "events_ipv4_ip": "IP",
        },
        "add_fields_types": {
            "event_url": {},
            "event_domain": {},
            "events_ipv4_ip": {
                "asn": "asn",
                "country_name": "geocountry",
                "region": "geolocation",
            }
        },
    },
    "compromised/bank_card_group": {
        "types": {
            "cnc_url": "URL",
            "cnc_domain": "Domain",
            "cnc_ipv4_ip": "IP",
        },
        "add_fields_types": {
            "cnc_url": {},
            "cnc_domain": {},
            "cnc_ipv4_ip": {
                "cnc_ipv4_asn": "asn",
                "cnc_ipv4_country_name": "geocountry",
                "cnc_ipv4_region": "geolocation",
            }
        },
    },
    "compromised/mule": {
        "types": {
            "cnc_url": "URL",
            "cnc_domain": "Domain",
            "cnc_ipv4_ip": "IP",
        },
        "add_fields_types": {
            "cnc_url": {},
            "cnc_domain": {},
            "cnc_ipv4_ip": {
                "cnc_ipv4_asn": "asn",
                "cnc_ipv4_country_name": "geocountry",
                "cnc_ipv4_region": "geolocation",
            }
        },
    },
    "compromised/card": {
        "types": {
            "cnc_url": "URL",
            "cnc_domain": "Domain",
            "cnc_ipv4_ip": "IP",
        },
        "add_fields_types": {
            "cnc_url": {},
            "cnc_domain": {},
            "cnc_ipv4_ip": {
                "cnc_ipv4_asn": "asn",
                "cnc_ipv4_country_name": "geocountry",
                "cnc_ipv4_region": "geolocation",
            }
        },
    },
    "osi/vulnerability": {
        "types": {
            "id": "CVE",
        },
        "markdowns": {
            "software_mixed": (
                "| Software Name | Software Type | Software Version |\n"
                "| ------------- | ------------- | ---------------- |\n"
            )
        },
        "add_fields_types": {
            "id": {
                "cvss_score": "cvss",
                "description": "description",
                "software_mixed": "gibsoftwaremixed",
                "dateLastSeen": "cvemodified",
                "datePublished": "published",
                "severity": "severity",
            }
        },
    },
    "osi/git_repository": {
        "types": {
            "contributors_emails": "Email",
            "hash": "GIB Hash",
        },
        "add_fields_types": {
            "contributors_emails": {},
            "hash": {}
        },
    },
    "attacks/phishing_kit": {"types": {"emails": "Email"}, "add_fields_types": {"emails": {}}},
    "attacks/phishing_group": {
        "types": {
            "url": "URL",
            "phishing_domain_domain": "Domain",
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "url": {},
            "phishing_domain_domain": {"phishing_domain_registrar": "registrarname"},
            "ipv4_ip": {
                "ipv4_country_name": "geocountry",
            },
        },
    },
    "attacks/deface": {
        "types": {"url": "URL", "target_domain": "Domain", "target_ip_ip": "IP"},
        "add_fields_types": {
            "url": {},
            "target_domain": {},
            "target_ip_ip": {
                "target_ip_asn": "asn",
                "target_ip_country_name": "geocountry",
                "target_ip_region": "geolocation",
            }
        },
    },
    "attacks/ddos": {
        "types": {"cnc_url": "URL", "cnc_domain": "Domain", "cnc_ipv4_ip": "IP"},
        "add_fields_types": {
            "cnc_url": {},
            "cnc_domain": {},
            "cnc_ipv4_ip": {
                "cnc_ipv4_asn": "asn",
                "cnc_ipv4_country_name": "geocountry",
                "cnc_ipv4_region": "geolocation",
            }
        },
    },
    "malware/cnc": {
        "types": {
            "url": "URL",
            "domain": "Domain",
        },
        "add_fields_types": {
            "url": {},
            "domain": {
                "ipv4_ip": "IP",
                "ipv4_asn": "asn",
                "country_name": "geocountry",
                "ipv4_region": "geolocation",
            }
        },
    },
    "suspicious_ip/socks_proxy": {
        "types": {"ipv4_ip": "IP"},
        "add_fields_types": {
            "ipv4_ip": {
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
            }
        },
    },
    "suspicious_ip/open_proxy": {
        "types": {
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "ipv4_ip": {
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
            }
        },
    },
    "suspicious_ip/tor_node": {
        "types": {"ipv4_ip": "IP"},
        "add_fields_types": {
            "ipv4_ip": {
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
            }
        },
    },
    "suspicious_ip/vpn": {
        "types": {
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "ipv4_ip": {
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
            },
        },
    },
    "suspicious_ip/scanner": {
        "types": {
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "ipv4_ip": {
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
            },
        },
    },
    "hi/threat": {
        "types": {
            "ipv4": "IP",
            "domain": "Domain",
            "url": "URL",
            "hashes_md5": "File",
        },
        "add_fields_types": {
            "ipv4": {},
            "domain": {},
            "url": {},
            "hashes_md5": {
                "name": "gibfilename",
                "hashes_md5": "md5",
                "hashes_sha1": "sha1",
                "hashes_sha256": "sha256",
                "size": "size",
            }
        },
    },
    "apt/threat": {
        "types": {
            "ipv4": "IP",
            "domain": "Domain",
            "url": "URL",
            "hashes_md5": "File",
        },
        "add_fields_types": {
            "ipv4": {},
            "domain": {},
            "url": {},
            "hashes_md5": {
                "name": "gibfilename",
                "hashes_md5": "md5",
                "hashes_sha1": "sha1",
                "hashes_sha256": "sha256",
                "size": "size",
            }
        },
    },
}

PREFIXES = {
    "compromised/account_group": "Compromised Account Group",
    "compromised/bank_card_group": "Compromised Card Group",
    "compromised/breached": "Data Breach",
    "compromised/mule": "Compromised Mule",
    "osi/git_repository": "Git Leak",
    "osi/public_leak": "Public Leak",
    "osi/vulnerability": "OSI Vulnerability",
    "attacks/ddos": "Attacks DDoS",
    "attacks/deface": "Attacks Deface",
    "attacks/phishing_group": "Phishing Group",
    "attacks/phishing_kit": "Phishing Kit",
    "apt/threat": "Nation-State Cybercriminals Threat Report",
    "apt/threat_actor": "Nation-State Cybercriminals Threat Actor Profile",
    "hi/threat": "GIB Cybercriminal Threat Report",
    "hi/threat_actor": "GIB Cybercriminal Threat Actor Profile",
    "suspicious_ip/tor_node": "Suspicious IP Tor Node",
    "suspicious_ip/open_proxy": "Suspicious IP Open Proxy",
    "suspicious_ip/socks_proxy": "Suspicious IP Socks Proxy",
    "suspicious_ip/vpn": "Suspicious IP VPN",
    "suspicious_ip/scanner": "Suspicious IP Scanner",
    "malware/cnc": "Malware CNC",
    "malware/malware": "Malware",
}

INCIDENT_CREATED_DATES_MAPPING = {
    "compromised/account_group": "dateFirstSeen",
    "compromised/breached": "uploadTime",
    "compromised/mule": ["dateAdd", "dateIncident"],
    "compromised/bank_card_group": "dateFirstCompromised",
    "osi/git_repository": "dateDetected",
    "osi/public_leak": "created",
    "osi/vulnerability": "datePublished",
    "attacks/ddos": "dateReg",
    "attacks/deface": "date",
    "attacks/phishing_kit": "dateFirstSeen",
    "attacks/phishing_group": ["detected", "updated"],
    "apt/threat": "createdAt",
    "apt/threat_actor": "createdAt",
    "hi/threat": "createdAt",
    "hi/threat_actor": "createdAt",
    "suspicious_ip/tor_node": "dateFirstSeen",
    "suspicious_ip/open_proxy": "dateFirstSeen",
    "suspicious_ip/socks_proxy": "dateFirstSeen",
    "suspicious_ip/vpn": "dateFirstSeen",
    "suspicious_ip/scanner": "dateFirstSeen",
    "malware/cnc": "dateFirstSeen",
    "malware/malware": "updatedAt",
}

COLLECTIONS_THAT_MAY_NOT_SUPPORT_ID_SEARCH_VIA_UPDATED = [
    "suspicious_ip/tor_node",
    "suspicious_ip/open_proxy",
    "suspicious_ip/socks_proxy",
]

SET_WITH_ALL_DATE_FIELDS = {
    "dateEnd",
    "createdAt",
    "updated",
    "dateCreated",
    "dateFirstSeen",
    "dateModified",
    "dateLastCompromised",
    "added",
    "updatedAt",
    "created",
    "dateAdd",
    "dateBegin",
    "dateLastSeen",
    "blocked",
    "detected",
    "dateIncident",
    "dateFirstCompromised",
    "dateDetected",
    "datePublished",
    "dateReg",
    "date",
    "validThruDate",
    "datecompromised",
    "dateDetected",
}

TABLES_MAPPING = {
    "compromised/account_group": ["events_table"],
    "compromised/bank_card_group": ["threatActor", "compromised_events", "malware"],
    "osi/git_repository": ["files"],
    "osi/public_leak": ["linkList", "matches"],
    "osi/vulnerability": ["cpeTable", "affectedSoftware"],
    "attacks/phishing_kit": ["downloadedFrom"],
    "malware/cnc": ["threatActor", "malwareList"],
    "malware/malware": ["taList"],
    "hi/threat": ["forumsAccounts"],
    "hi/threat_actor": ["reports"],
    "apt/threat_actor": ["reports"],
    "apt/threat": ["forumsAccounts"],
}

HTML_FIELDS = {
    "apt/threat_actor": ["description"],
    "apt/threat": ["description"],
    "malware/malware": ["description", "shortDescription"],
    "hi/threat": ["description"],
    "hi/threat_actor": ["description"],
    "osi/public_leak": ["data"],
}

PORTAL_LINKS = {
    "compromised/account_group": "https://tap.group-ib.com/cd/accounts?id=",
    "compromised/breached": "https://tap.group-ib.com/cd/breached?id=",
    "compromised/bank_card_group": "https://tap.group-ib.com/cd/cards?id=",
    "compromised/mule": "https://tap.group-ib.com/cd/mules?id=",
    "hi/threat": "https://tap.group-ib.com/ta/last-threats?threat=",
    "hi/threat_actor": "https://tap.group-ib.com/ta/actors?ta=",
    "apt/threat": "https://tap.group-ib.com/ta/last-threats?threat=",
    "apt/threat_actor": "https://tap.group-ib.com/ta/actors?ta=",
    "attacks/ddos": "https://tap.group-ib.com/attacks/ddos?id=",
    "attacks/deface": "https://tap.group-ib.com/attacks/deface?q=id:",
    "attacks/phishing_group": "https://tap.group-ib.com/attacks/phishing?scope=all&q=id:",
    "attacks/phishing_kit": "https://tap.group-ib.com/malware/phishing-kit?p=1&q=",
    "malware/malware": "https://tap.group-ib.com/malware/reports/",
    "osi/git_repository": "https://tap.group-ib.com/cd/git-leaks?id=",
    "osi/public_leak": "https://tap.group-ib.com/cd/leaks?id=",
    "osi/vulnerability": "https://tap.group-ib.com/malware/vulnerabilities?p=1&scope=all&q=",
    "suspicious_ip/tor_node": "https://tap.group-ib.com/suspicious/tor?q=",
    "suspicious_ip/open_proxy": "https://tap.group-ib.com/suspicious/proxies?q=",
    "suspicious_ip/socks_proxy": "https://tap.group-ib.com/suspicious/socks?q=",
    "suspicious_ip/scanner": "https://tap.group-ib.com/suspicious/scanning?ip=",
    "suspicious_ip/vpn": "https://tap.group-ib.com/suspicious/vpn?q=",
}

COLLECTIONS_THAT_ARE_REQUIRED_HUNTING_RULES = ["osi/git_repository", "osi/public_leak", "compromised/breached"]

COLLECTIONS_FOR_WHICH_THE_PORTAL_LINK_WILL_BE_GENERATED = ["compromised/breached"]



MAPPING = {
    "compromised/account_group": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "login",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "login": "login",  # GIB Compromised Login
        "password": "password",  # GIB Password
        "parsedLogin": {
            "domain": "parsedLogin.domain",  # GIB Parsed Login Domain
            "ip": "parsedLogin.ip",  # GIB Parsed Login IP
        },
        "service": {
            "domain": "service.domain",  # GIB Service Domain
            "ip": "service.ip",  # GIB Service IP
            "url": "service.url",  # GIB Service URL
        },
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("compromised/account_group"),
                "dynamic": "id",
            }
        },
        "events_table": {  # GIB Compromised Events Information Table
            "cnc": "events.cnc.cnc",
            "asn": "events.client.ipv4.asn",
            "city": "events.client.ipv4.city",
            "region": "events.client.ipv4.region",
            "provider": "events.client.ipv4.provider",
            "countryCode": "events.client.ipv4.countryCode",
            "ip": "events.client.ipv4.ip",
            "malware": "events.malware.name",
            "threatActor": "events.threatActor.name",
            "dateDetected": "events.dateDetected",
            "dateCompromised": "events.dateCompromised",
            "phone": "events.person.phone",
            "name": "events.person.name",
            "email": "events.person.email",
            "address": "events.person.address",
        },
        # END Information from Group-IB
        # Group-IB Dates
        "dateFirstCompromised": "dateFirstCompromised",  # GIB Date First Compromised
        "dateLastCompromised": "dateLastCompromised",  # GIB Date Last Compromised
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        # END Group-IB Dates
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "event_url": "events.cnc.url",
            "event_domain": "events.cnc.domain",
            "events_ipv4_ip": "events.cnc.ipv4.ip",
            "asn": "events.client.ipv4.asn",
            "country_name": "events.client.ipv4.countryName",
            "region": "events.client.ipv4.region",
        },
    },
    "compromised/bank_card_group": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "cardInfo.number",
        # Card Info From Group-IB
        "issuer": "cardInfo.issuer.issuer",  # GIB Card Issuer
        "number": "cardInfo.number",  # GIB Card Number
        "type": "cardInfo.type",  # GIB Card Type
        "payment_system": "cardInfo.system",  # GIB Payment System
        # End Card Info From Group-IB
        # Information from Group-IB
        "id": "id",  # GIB ID
        "compromised_events": {  # GIB Compromised Events Table
            "valid_thru_date": "events.cardInfo.validThruDate",
            "valid_thru": "events.cardInfo.validThru",
            "client_ip": "events.client.ipv4.ip",
            "cnc": "events.cnc.cnc",
            "cnc_ip": "events.cnc.ipv4.ip",
            "threat_actor_name": "events.threatActor.name",
            "date_compromised": "events.dateCompromised",
            "victim_phone": "events.owner.phone",
            "victim_name": "events.owner.name",
            "malware": "events.malware.name",
        },
        "malware": {  # GIB Malware Table
            "id": "malware.id",
            "name": "malware.name",
        },
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("compromised/bank_card_group"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        # Group-IB Dates
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "dateFirstCompromised": "dateFirstCompromised",  # GIB Date First Compromised
        "dateLastCompromised": "dateLastCompromised",  # GIB Date Last Compromised
        # END Group-IB Dates
        # Threat Actor
        "threatActor": {  # GIB Threat Actors Table
            "id": "threatActor.id",
            "name": "threatActor.name",
        },
        # End Threat Actor
        "indicators": {  # GIB Related Indicators Data
            "cnc_url": "events.cnc.url",
            "cnc_domain": "events.cnc.domain",
            "cnc_ipv4_ip": "events.cnc.ipv4.ip",
            "cnc_ipv4_asn": "events.cnc.ipv4.asn",
            "cnc_ipv4_country_name": "events.cnc.ipv4.countryName",
            "cnc_ipv4_region": "events.cnc.ipv4.region",
        },
    },
    "compromised/breached": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "id",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "leakName": "leakName",  # GIB Leak Name
        "passwords": "password",  # GIB Passwords
        "description": "description",  # Description
        "emails": "email",  # GIB Emails
        "emailDomains": "addInfo.emailDomain",  # GIB Email Domains
        "portalLink": "set_generated_portal_link",  # GIB Portal Link
        # END Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        # Group-IB Dates
        "leakPublished": "leakPublished",  # GIB Leak Published
        "updateTime": "updateTime",  # GIB Update Time
        "uploadTime": "uploadTime",  # GIB Upload Time
        # END Group-IB Dates
    },
    "compromised/mule": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "account",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "hash": "hash",  # GIB Data Hash
        "dateAdd": "dateAdd",  # GIB Date Add
        "dateIncident": "dateIncident",  # GIB Date Incident
        "organization": {
            "bic": "organization.bic",  # GIB Organization BIC
            "bsb": "organization.bsb",  # GIB Organization BSB
            "iban": "organization.iban",  # GIB Organization IBAN
            "name": "organization.name",  # GIB Organization Name
            "swift": "organization.swift",  # GIB Organization SWIFT
            "clabe": "organization.clabe",  # GIB Organization CLABE
        },
        "account": "account",  # GIB Compromised Account
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("compromised/mule"),
                "dynamic": "id",
            }
        },
        # END Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "cnc_url": "cnc.url",
            "cnc_domain": "cnc.domain",
            "cnc_ipv4_ip": "cnc.ipv4.ip",
            "cnc_ipv4_asn": "cnc.ipv4.asn",
            "cnc_ipv4_country_name": "cnc.ipv4.countryName",
            "cnc_ipv4_region": "cnc.ipv4.region",
        },
    },
    "osi/git_repository": {  # GIB Source:sourceType, severity:systemSeverity
        # Information from Group-IB
        "id": "id",  # GIB ID
        "name": "name",
        "leaked_file_name": "name",  # GIB Leaked File Name
        "source": "source",  # GIB GIT Source
        "dateDetected": "dateDetected",  # GIB Date of Detection
        "dateCreated": "dateCreated",  # GIB Date Created
        "files": {  # GIB OSI Git Repository Files Table
            "file_id": "files.id",
            "file_name": "files.name",
            "hash": "files.revisions.hash",
            "dateCreated": "files.dateCreated",
            "dateDetected": "files.dateDetected",
            "authorName": "files.revisions.info.authorName",
            "authorEmail": "files.revisions.info.authorEmail",
            "url": "files.url",
            "dataFound": "files.dataFound",
        },
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("osi/git_repository"),
                "dynamic": "id",
            }
        },
        # END Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "hash": "files.revisions.hash",
            "contributors_emails": "contributors.authorEmail",
        },
    },
    "osi/public_leak": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "hash",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "hash": "hash",  # GIB Data Hash
        "created": "created",  # GIB Date Created
        "data": "data",  # GIB Leaked Data
        "linkList": {  # GIB Link List Table
            "author": "linkList.author",
            "hash": "linkList.hash",
            "link": "linkList.link",
            "title": "linkList.title",
            "source": "linkList.source",
            "dateDetected": "linkList.dateDetected",
            "datePublished": "linkList.datePublished",
        },
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("osi/public_leak"),
                "dynamic": "id",
            }
        },
        "matches": "matches",  # GIB Matches Table
        # END Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
    },
    "osi/vulnerability": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "id",
        # Group-IB Dates
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "dateModified": "dateModified",  # GIB Date Modified
        "datePublished": "datePublished",  # GIB Date Published
        # END Group-IB Dates
        # Information from Group-IB
        "id": "id",  # GIB ID
        "bulletinFamily": "bulletinFamily",  # GIB Bulletin Family
        "description": "description",  # Description
        "extDescription": "extDescription",  # GIB Extended Description
        "reporter": "reporter",  # GIB Reporter
        "hasExploit": "hasExploit",  # GIB Has Exploit
        "href": "href",  # GIB Href
        "mergedCvss": "mergedCvss",  # GIB Merged Cvss
        "type": "type",  # GIB Vulnerability Type
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("osi/vulnerability"),
                "dynamic": "id",
            }
        },
        "cpeTable": {  # GIB CPE Table
            "product": "cpeTable.product",
            "string": "cpeTable.string",
            "string23": "cpeTable.string23",
            "type": "cpeTable.type",
            "vendor": "cpeTable.vendor",
            "version": "cpeTable.version",
        },
        # END Information from Group-IB
        # Group-IB Affected Software
        "affectedSoftware": {  # GIB Affected Software Table
            "name": "affectedSoftware.name",
            "operator": "affectedSoftware.operator",
            "version": "affectedSoftware.version",
        },
        # END Group-IB Affected Software
        # Group-IB CVSS Information
        "cvss": {
            "score": "cvss.score",  # GIB CVSS Score
            "vector": "cvss.vector",  # GIB CVSS Vector
        },
        "extCvss": {
            "base": "extCvss.base",  # GIB Extended CVSS Base
            "exploitability": "extCvss.exploitability",  # GIB Extended CVSS Exploitability
            "impact": "extCvss.impact",  # GIB Extended CVSS Impact
            "overall": "extCvss.overall",  # GIB Extended CVSS Overall
            "temporal": "extCvss.temporal",  # GIB Extended CVSS Temporal
        },
        # END Group-IB CVSS Information
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "severity": "evaluation.severity",
            "id": "id",
            "cvss_score": "cvss.score",
            "description": "description",
            "dateLastSeen": "dateLastSeen",
            "datePublished": "datePublished",
            "software_mixed": {
                "names": "softwareMixed.softwareName",
                "types": "softwareMixed.softwareType",
                "versions": "softwareMixed.softwareVersion",
            },
        },
    },
    "attacks/ddos": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "target.ipv4.ip",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "dateBegin": "dateBegin",  # GIB DDOS Date Begin
        "dateEnd": "dateEnd",  # GIB DDOS Date End
        "dateReg": "dateReg",  # GIB DDOS Date Registration
        "duration": "duration",  # GIB DDOS Duration
        "protocol": "protocol",  # GIB DDOS Protocol
        "source": "source",  # GIB DDOS Source
        "type": "type",  # GIB DDOS Type
        "malwareName": "malware.name",  # GIB Malware Name
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("attacks/ddos"),
                "dynamic": "id",
            }
        },
        # END Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        # CNC Information from Group-IB
        "cnc": {
            "cnc": "cnc.cnc",  # GIB CNC
            "domain": "cnc.domain",  # GIB CNC Domain
            "port": "cnc.port",  # GIB CNC Port
            "url": "cnc.url",  # GIB CNC URL
        },
        # END CNC Information from Group-IB
        # Group-IB Threat Actor
        "threatActor": {
            "id": "threatActor.id",  # GIB Threat Actor ID
            "name": "threatActor.name",  # GIB Threat Actor Name
            "isAPT": "threatActor.isAPT",  # GIB Threat Actor is APT
        },
        # End Group-IB Threat Actor
        # Group-IB DDOS Target
        "target": {
            "url": "target.url",  # GIB DDOS Target URL
            "asn": "target.ipv4.asn",  # GIB DDOS Target ASN
            "city": "target.ipv4.city",  # GIB DDOS Target City
            "region": "target.ipv4.region",  # GIB DDOS Target Region
            "provider": "target.ipv4.provider",  # GIB DDOS Target Provider
            "countryCode": "target.ipv4.countryCode",  # GIB DDOS Target Country Code
            "countryName": "target.ipv4.countryName",  # GIB DDOS Target Country Name
            "ip": "target.ipv4.ip",  # GIB DDOS Target IP
            "port": "target.port",  # GIB DDOS Target Port
            "category": "target.category",  # GIB DDOS Target Category
            "domain": "target.domain",  # GIB DDOS Target Domain
        },
        # END Group-IB DDOS Target
        # Group-IB DDOS Request
        "requestData": {
            "link": "requestData.link",  # GIB DDOS Request Data Link
            "headersHash": "requestData.headersHash",  # GIB DDOS Request Headers Hash
            "body": "requestData.body",  # GIB DDOS Request Body
            "bodyHash": "requestData.bodyHash",  # GIB DDOS Request Body Hash
        },
        # END Group-IB DDOS Request
        "indicators": {  # GIB Related Indicators Data
            "target_ipv4_ip": "target.ipv4.ip",
            "cnc_url": "cnc.url",
            "cnc_domain": "cnc.domain",
            "cnc_ipv4_ip": "cnc.ipv4.ip",
            "cnc_ipv4_asn": "cnc.ipv4.asn",
            "cnc_ipv4_country_name": "cnc.ipv4.countryName",
            "cnc_ipv4_region": "cnc.ipv4.region",
        },
    },
    "attacks/deface": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "url",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "mirrorLink": "mirrorLink",  # GIB Mirror Link
        "providerDomain": "providerDomain",  # GIB Provider Domain
        "siteUrl": "siteUrl",  # GIB Deface Site URL
        "source": "source",  # GIB Deface Source
        "targetDomain": "targetDomain",  # GIB Target Domain
        "targetDomainProvider": "targetDomainProvider",  # GIB Target Domain Provider
        "date": "date",  # GIB Deface Date
        "contacts": "contacts",  # GIB Deface Contacts
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("attacks/deface"),
                "dynamic": "id",
            }
        },
        # END Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        # Group-IB Target IP
        "targetIp": {
            "asn": "targetIp.asn",  # GIB Target ASN
            "city": "targetIp.city",  # GIB Target City
            "countryCode": "targetIp.countryCode",  # GIB Country Code
            "countryName": "targetIp.countryName",  # GIB Country Name
            "ip": "targetIp.ip",  # GIB Target IP
            "provider": "targetIp.provider",  # GIB Target Provider
            "region": "targetIp.region",  # GIB Target Region
        },
        # END Group-IB Target IP
        # Group-IB Threat Actor
        "threatActor": {
            "id": "threatActor.id",  # GIB Threat Actor ID
            "name": "threatActor.name",  # GIB Threat Actor Name
            "isAPT": "threatActor.isAPT",  # GIB Threat Actor is APT
        },
        # End Group-IB Threat Actor
        "indicators": {  # GIB Related Indicators Data
            "url": "url",
            "target_domain": "targetDomain",
            "target_ip_ip": "targetIp.ip",
            "target_ip_asn": "targetIp.asn",
            "target_ip_country_name": "targetIp.countryName",
            "target_ip_region": "targetIp.region",
        },
    },
    "attacks/phishing_group": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "brand",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "brand": "brand",  # GIB Phishing Brand
        "phishing_urls": "phishing.url",  # GIB Phishing URLs
        "objective": "objective",  # GIB Phishing Objectives
        "source": "source",  # GIB Phishing Sources
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("attacks/phishing_group"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Dates
        "blocked": "date.blocked",  # GIB Phishing Date Blocked
        "added": "date.added",  # GIB Phishing Date Added
        "detected": "date.detected",  # GIB Phishing Date Detected
        "updated": "date.updated",  # GIB Phishing Date Updated
        # END Group-IB Dates
        # Group-IB Domain Information
        "domainInfo": {
            "domain": "domainInfo.domain",  # GIB Phishing Domain
            "domainPuny": "domainInfo.domainPuny",  # GIB Phishing Domain Puny
            "expirationDate": "domainInfo.expirationDate",  # GIB Phishing Domain Expiration Date
            "registrar": "domainInfo.registrar",  # GIB Phishing Registrar
        },
        # END Group-IB Domain Information
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        # Group-IB Phishing Information
        "phishing_ip": {  # GIB Phishing IP Table
            "ip": "ip.ip",
            "countryCode": "ip.countryCode",
            "countryName": "ip.countryName",
            "provider": "ip.provider",
        },
        # End Phishing Information from Group-IB
        # Group-IB Threat Actor Information
        "threatActor": {
            "id": "threatActor.id",  # GIB Threat Actor ID
            "name": "threatActor.name",  # GIB Threat Actor Name
        },
        # End Group-IB Threat Actor Information
        # Group-IB Phishing Kit Table
        "phishing_kit_table": {  # GIB Phishing Kit Table
            "name": "phishing.phishingKit.name",
            "email": "phishing.phishingKit.email",
        },
        # END Group-IB Phishing Kit Table
        "indicators": {  # GIB Related Indicators Data
            "url": "phishing.url",
            "phishing_domain_domain": "domain",
            "phishing_domain_registrar": "domainInfo.registrar",
            "ipv4_ip": "phishing.ip.ip",
            "ipv4_country_name": "phishing.ip.countryName",
        },
    },
    "attacks/phishing_kit": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "hash",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "hash": "hash",  # GIB Data Hash
        "dateDetected": "dateDetected",  # GIB Date of Detection
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "source": "source",  # GIB Phishing Kit Source
        "emails": "emails",  # GIB Phishing Kit Email
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("attacks/phishing_kit"),
                "dynamic": "id",
            }
        },
        "downloadedFrom": {  # GIB Downloaded From Table
            "date": "downloadedFrom.date",
            "url": "downloadedFrom.url",
            "phishingUrl": "downloadedFrom.phishingUrl",
            "domain": "downloadedFrom.domain",
            "fileName": "downloadedFrom.fileName",
        },
        # End Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {"emails": "emails"},  # GIB Related Indicators Data
    },
    "suspicious_ip/tor_node": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "ipv4.ip",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("suspicious_ip/tor_node"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
        },
    },
    "suspicious_ip/open_proxy": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "ipv4.ip",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "dateDetected": "dateDetected",  # GIB Date of Detection
        "port": "port",  # GIB Proxy Port
        "source": "source",  # GIB Proxy Source
        "sources": "sources",  # GIB Proxy Sources
        "type": "type",  # GIB Proxy Type
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("suspicious_ip/open_proxy"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
        },
    },
    "suspicious_ip/socks_proxy": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "ipv4.ip",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "dateDetected": "dateDetected",  # GIB Date of Detection
        "source": "source",  # GIB Socks Proxy Source
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("suspicious_ip/socks_proxy"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
        },
    },
    "suspicious_ip/vpn": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "id",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "sources": "sources",  # GIB VPN Sources
        "names": "names",  # GIB VPN Names
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("suspicious_ip/vpn"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
        },
    },
    "suspicious_ip/scanner": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "id",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("suspicious_ip/scanner"),
                "dynamic": "id",
            }
        },
        "categories": "categories",  # GIB Scanner Categories
        "sources": "sources",  # GIB Scanner Sources
        # End Information from Group-IB
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        "indicators": {  # GIB Related Indicators Data
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
        },
    },
    "malware/cnc": {  # GIB Source:sourceType
        "name": "cnc",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "cnc": "cnc",  # GIB CNC URL
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "dateDetected": "dateDetected",  # GIB Date of Detection
        "domain": "domain",  # GIB Malware CNC Domain
        "malwareList": {  # GIB Malware Table
            "id": "malwareList.id",
            "name": "malwareList.name",
        },
        # End Information from Group-IB
        # Group-IB Threat Actor
        "threatActor": {  # GIB Threat Actors Table
            "id": "threatActor.id",
            "name": "threatActor.name",
        },
        # End Group-IB Threat Actor
        "indicators": {  # GIB Related Indicators Data
            "url": "url",
            "domain": "domain",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "cnc": "cnc",
        },
    },
    "malware/malware": {  # GIB Source:sourceType
        # Information from Group-IB
        "id": "id",  # GIB ID
        "name": "name",
        "malware_name": "name",  # GIB Malware Name
        "updatedAt": "updatedAt",  # GIB Date Updated At
        "aliases": "aliases",  # GIB Malware Aliases
        "category": "category",  # GIB Malware Categories
        "description": "description",  # GIB Malware Description
        "shortDescription": "shortDescription",  # GIB Malware Short Description
        "geoRegion": "geoRegion",  # GIB Malware Regions
        "langs": "langs",  # GIB Malware Langs
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("malware/malware"),
                "dynamic": "id",
            }
        },
        "sourceCountry": "sourceCountry",  # GIB Malware Source Countries
        "platform": "platform",  # GIB Malware Platforms
        "threatLevel": "threatLevel",  # GIB Threat Level
        # End Information from Group-IB
        # Group-IB Threat Actor
        "taList": {  # GIB Threat Actors Table
            "id": "taList.id",
            "name": "taList.name",
        },
        # END Group-IB Threat Actor
    },
    "hi/threat": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "threatActor.name",
        # Group-IB Threat Actor
        "threatActor": {
            "country": "threatActor.country",  # GIB Threat Actor Country
            "id": "threatActor.id",  # GIB Threat Actor ID
            "isAPT": "threatActor.isAPT",  # GIB Threat Actor is APT
            "name": "threatActor.name",  # GIB Threat Actor Name
        },
        # END Group-IB Threat Actor
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        # Group-IB Cybercriminal Forum Information
        "forumsAccounts": {  # GIB Cybercriminal Forums Table
            "nickname": "forumsAccounts.nickname",
            "url": "forumsAccounts.url",
        },
        # END Group-IB Cybercriminal Forum Information
        # Information from Group-IB
        "id": "id",  # GIB ID
        "title": "title",  # GIB Cybercriminal Threat Title
        "description": "description",  # GIB Cybercriminal Threat Description
        "createdAt": "createdAt",  # GIB Date Created At
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        "isTailored": "isTailored",  # GIB Is Tailored
        "expertise": "expertise",  # GIB Cybercriminal Expertises
        "regions": "regions",  # GIB Cybercriminal Regions
        "sectors": "sectors",  # GIB Cybercriminal Sectors
        "reportNumber": "reportNumber",  # GIB Report Number
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("hi/threat"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        "indicators": {  # GIB Related Indicators Data
            "ipv4": "indicators.params.ipv4",
            "domain": "indicators.params.domain",
            "url": "indicators.params.url",
            "hashes_md5": "indicators.params.hashes.md5",
            "name": "indicators.params.name",
            "hashes_sha1": "indicators.params.hashes.sha1",
            "hashes_sha256": "indicators.params.hashes.sha256",
            "size": "indicators.params.size",
        },
    },
    "hi/threat_actor": {  # GIB Source:sourceType
        # Information from Group-IB
        "name": "name",
        "id": "id",  # GIB ID
        "aliases": "aliases",  # GIB Cybercriminal Threat Actor Aliases
        "description": "description",  # GIB Cybercriminal Threat Actor Description
        "isAPT": "isAPT",  # GIB Threat Actor is APT
        "threat_actor_name": "name",  # GIB Threat Actor Name
        "expertise": "stat.expertise",  # GIB Cybercriminal Expertises
        "regions": "stat.regions",  # GIB Cybercriminal Regions
        "sectors": "stat.sectors",  # GIB Cybercriminal Sectors
        "malware": "stat.malware",  # GIB Cybercriminal Malware
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("hi/threat_actor"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Threat Actor Reports
        "reports": {  # GIB Cybercriminal Threat Actor Reports Table
            "id": "stat.reports.id",
            "name": "stat.reports.name.en",
            "datePublished": "stat.reports.datePublished",
        },
        # END Group-IB Threat Actor Reports
        # Group-IB Dates
        "createdAt": "createdAt",  # GIB Date Created At
        "updatedAt": "updatedAt",  # GIB Date Updated At
        "dateFirstSeen": "stat.dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "stat.dateLastSeen",  # GIB Date Last Seen
        # END Group-IB Dates
    },
    "apt/threat_actor": {  # GIB Source:sourceType
        # Information from Group-IB
        "name": "name",
        "id": "id",  # GIB ID
        "aliases": "aliases",  # GIB Nation-State Cybercriminals Threat Actor Aliases
        "country": "country",  # GIB Nation-State Cybercriminals Threat Actor Country
        "description": "description",  # GIB Nation-State Cybercriminals Threat Actor Description
        "goals": "goals",  # GIB Nation-State Cybercriminals Threat Actor Goals
        "isAPT": "isAPT",  # GIB Threat Actor is APT
        "labels": "labels",  # GIB Nation-State Cybercriminals Threat Actor Labels
        "threat_actor_name": "name",  # GIB Threat Actor Name
        "roles": "roles",  # GIB Nation-State Cybercriminals Threat Actor Roles
        "cve": "stat.cve",  # GIB Nation-State Cybercriminals Threat Actor CVE
        "expertise": "stat.expertise",  # GIB Nation-State Cybercriminals Expertises
        "malware": "stat.malware",  # GIB Nation-State Cybercriminals Malware
        "regions": "stat.regions",  # GIB Nation-State Cybercriminals Regions
        "sectors": "stat.sectors",  # GIB Nation-State Cybercriminals Sectors
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("apt/threat_actor"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Threat Actor Reports
        "reports": {  # GIB Nation-State Cybercriminals Threat Actor Reports Table
            "id": "stat.reports.id",
            "name": "stat.reports.name.en",
            "datePublished": "stat.reports.datePublished",
        },
        # END Group-IB Threat Actor Reports
        # Group-IB Dates
        "createdAt": "createdAt",  # GIB Date Created At
        "dateFirstSeen": "stat.dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "stat.dateLastSeen",  # GIB Date Last Seen
        "updatedAt": "updatedAt",  # GIB Date Updated At
        # END Group-IB Dates
    },
    "apt/threat": {  # GIB Source:sourceType, severity:systemSeverity
        "name": "threatActor.name",
        # Information from Group-IB
        "id": "id",  # GIB ID
        "title": "title",  # GIB Nation-State Cybercriminals Threat Title
        "countries": "countries",  # GIB Nation-State Cybercriminals Threat Countries
        "description": "description",  # GIB Nation-State Cybercriminals Threat Description
        "expertise": "expertise",  # GIB Nation-State Cybercriminals Threat Expertises
        "isTailored": "isTailored",  # GIB Is Tailored
        "labels": "labels",  # GIB Nation-State Cybercriminals Threat Actor Labels
        "langs": "langs",  # GIB Nation-State Cybercriminals Threat Langs
        "regions": "regions",  # GIB Nation-State Cybercriminals Threat Regions
        "reportNumber": "reportNumber",  # GIB Nation-State Cybercriminals Threat Report Number
        "sectors": "sectors",  # GIB Nation-State Cybercriminals Threat Sectors
        "portalLink": {  # GIB Portal Link
            "__concatenate": {
                "static": PORTAL_LINKS.get("apt/threat"),
                "dynamic": "id",
            }
        },
        # End Information from Group-IB
        # Group-IB Dates
        "createdAt": "createdAt",  # GIB Date Created At
        "dateFirstSeen": "stat.dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "stat.dateLastSeen",  # GIB Date Last Seen
        "datePublished": "datePublished",  # GIB Date Published
        # END Group-IB Dates
        # Group-IB Threat Actor
        "threatActor": {
            "country": "threatActor.country",  # GIB Threat Actor Country
            "id": "threatActor.id",  # GIB Threat Actor ID
            "isAPT": "threatActor.isAPT",  # GIB Threat Actor is APT
            "name": "threatActor.name",  # GIB Threat Actor Name
        },
        # END Group-IB Threat Actor
        # Group-IB Evaluation
        "evaluation": {
            "admiraltyCode": "evaluation.admiraltyCode",  # GIB Admiralty Code
            "credibility": "evaluation.credibility",  # GIB Credibility
            "reliability": "evaluation.reliability",  # GIB Reliability
            "severity": "evaluation.severity",  # GIB Severity
        },
        # END Group-IB Evaluation
        # Group-IB Cybercriminal Forum Information
        "forumsAccounts": {  # GIB Nation-State Cybercriminal Forums Table
            "nickname": "forumsAccounts.nickname",
            "url": "forumsAccounts.url",
        },
        # END Group-IB Cybercriminal Forum Information
        "indicators": {  # GIB Related Indicators Data
            "ipv4": "indicators.params.ipv4",
            "domain": "indicators.params.domain",
            "url": "indicators.params.url",
            "hashes_md5": "indicators.params.hashes.md5",
            "name": "indicators.params.name",
            "hashes_sha1": "indicators.params.hashes.sha1",
            "hashes_sha256": "indicators.params.hashes.sha256",
            "size": "indicators.params.size",
        },
    },
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    limit = 100

    def __init__(self, base_url, verify=True, proxy=False, headers=None, auth=None):
        super().__init__(
            base_url=base_url, verify=verify, proxy=proxy, headers=headers, auth=auth
        )

        self._auth: tuple[str, str]
        self.poller = TIPoller(
            username=self._auth[0],
            api_key=self._auth[1],
            api_url=base_url,
        )
        self.poller.set_product(
            product_type="SOAR",
            product_name="CortexSOAR",
            product_version="unknown",
            integration_name="Group-IB Threat Intelligence",
            integration_version="1.4.2",
        )

    @staticmethod
    def handle_first_time_fetch(kwargs: dict[str, Any]) -> tuple[str, str | None]:
        """
        Handle first time fetch
        """
        date_from = None
        last_fetch = kwargs.get("last_fetch")
        if not last_fetch:
            date_from = dateparser_parse(date_string=kwargs.get("first_fetch_time"))  # type: ignore
            if date_from is None:
                raise DemistoException(
                    "Inappropriate first_fetch format, "
                    f"please use something like this: 2020-01-01 or January 1 2020 or 3 days. It's now been received: {date_from}"
                )
            date_from = date_from.strftime("%Y-%m-%d")  # type: ignore

        return last_fetch, date_from  # type: ignore

    def create_poll_generator(
        self, collection_name: str, hunting_rules: int, **kwargs
    ):
        """
        Interface to work with different types of indicators.
        """

        last_fetch, date_from = Client.handle_first_time_fetch(kwargs)

        if collection_name == "compromised/breached":
            hunting_rules = 1

            # we need the isinstance check for BC because it used to be a string

            if last_fetch and isinstance(last_fetch, dict):
                starting_date_from = last_fetch.get("starting_date_from")
                starting_date_to = last_fetch.get("starting_date_to")
                date_to = last_fetch.get("current_date_to")
            else:
                starting_date_from = date_from
                starting_date_to = datetime.now().strftime(DATE_FORMAT)
                date_to = starting_date_to

            return self.poller.create_search_generator(
                collection_name=collection_name,
                date_from=date_from,
                date_to=date_to,
                limit=self.limit,
                apply_hunting_rules=hunting_rules,
            ), {
                "starting_date_from": starting_date_from,
                "starting_date_to": starting_date_to,
                "current_date_to": date_to,
            }

        else:
            if collection_name in COLLECTIONS_THAT_ARE_REQUIRED_HUNTING_RULES:
                hunting_rules = 1
            return (
                self.poller.create_update_generator(
                    collection_name=collection_name,
                    date_from=date_from,
                    sequpdate=last_fetch,
                    limit=self.limit,
                    apply_hunting_rules=hunting_rules,
                ),
                last_fetch,
            )


""" Support functions """


class CommonHelpers:
    @staticmethod
    def transform_dict(
        input_dict: dict[str, list[str | list[Any]] | str | None]
    ) -> list[dict[str, Any]]:
        if not input_dict:
            return [{}]

        normalized_dict = {
            k: v if isinstance(v, list) else [v] for k, v in input_dict.items()  # type: ignore
        }

        max_length = max(
            (len(v) for v in normalized_dict.values() if isinstance(v, list)), default=1
        )

        result = []
        for i in range(max_length):
            result.append(
                {
                    k: (v[i] if i < len(v) else (v[0] if v else None))
                    for k, v in normalized_dict.items()
                }
            )

        return result

    @staticmethod
    def remove_underscore_and_lowercase_keys(
        dict_list: list[dict[str, Any]] | list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        updated_dicts = []

        for d in dict_list:
            new_dict = {}
            for key, value in d.items():
                new_key = key.replace("_", "").lower()
                new_dict[new_key] = value

            updated_dicts.append(new_dict)

        return updated_dicts

    @staticmethod
    def replace_empty_values(
        data: dict[str, Any] | list[dict[str, Any]]
    ) -> dict[str, Any] | list[dict[str, Any]]:

        if isinstance(data, dict):
            return {
                key: CommonHelpers.replace_empty_values(value)
                for key, value in data.items()
            }

        elif isinstance(data, list):
            if not data:
                return None  # type: ignore

            if all(isinstance(item, list) and not item for item in data):
                return None  # type: ignore

            return [CommonHelpers.replace_empty_values(item) for item in data]  # type: ignore

        else:
            if data == "":
                return None
            return data

    @staticmethod
    def all_lists_empty(data: dict[str, Any] | list[Any]) -> bool:
        all_empty = True

        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    if value:
                        all_empty = False
                elif isinstance(value, dict) and not CommonHelpers.all_lists_empty(value):
                    all_empty = False
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and not CommonHelpers.all_lists_empty(item):
                    all_empty = False

        return all_empty

    @staticmethod
    def date_parse(date: str, arg_name: str) -> str:
        date_from_parsed = dateparser_parse(date)
        if date_from_parsed is None:
            raise DemistoException(
                f"Inappropriate {arg_name} format, "
                "please use something like this: 2020-01-01 or January 1 2020"
            )
        date_from_parsed = date_from_parsed.strftime(DATE_FORMAT)
        return date_from_parsed

    @staticmethod
    def remove_html_tags(entry: dict, collection_name: str) -> dict:
        if collection_name in HTML_FIELDS:
            fields = HTML_FIELDS.get(collection_name, [])
            for field in fields:
                entry_field_value = entry.get(field, None)
                if isinstance(entry_field_value, str):
                    entry_field_value = re.sub(r"<[^>]+>", "", entry_field_value)
                    entry[field] = entry_field_value

        return entry

    @staticmethod
    def transform_list_to_str(data: list[dict]) -> list[dict]:
        for item in data:
            if isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(value, list):
                        item[key] = ", ".join(str(v) for v in value)
        return data


class IndicatorsHelper:

    @staticmethod
    def check_empty_list(add_fields: dict) -> bool:
        dict_len = len(add_fields)
        empty_found_count = 0
        for _key, value in add_fields.items():
            if isinstance(value, list) and len(value) < 1:
                empty_found_count += 1

        return dict_len == empty_found_count

    @staticmethod
    def parse_to_outputs(
        value: str | None | list, indicator_type: str, fields: dict
    ) -> Any:
        def calculate_dbot_score(type_):
            severity = fields.get("evaluation", {}).get("severity")
            if severity == "green":
                score = Common.DBotScore.GOOD
            elif severity == "orange":
                score = Common.DBotScore.SUSPICIOUS
            elif severity == "red":
                score = Common.DBotScore.BAD
            else:
                score = Common.DBotScore.NONE

            return Common.DBotScore(
                indicator=value,
                indicator_type=type_,
                integration_name="GIB TI&A",
                score=score,
            )

        indicator: Any = None
        if (
            (value is not None and len(value) > 0) or len(fields) > 0
        ) and IndicatorsHelper.check_empty_list(fields) is False:
            if indicator_type == "IP":
                indicator = Common.IP(
                    ip=value,
                    asn=fields.get("asn"),
                    geo_country=fields.get("geocountry"),
                    geo_description=fields.get("geolocation"),
                    dbot_score=calculate_dbot_score(DBotScoreType.IP),
                )
            elif indicator_type == "Domain":
                indicator = Common.Domain(
                    domain=value,
                    registrar_name=fields.get("registrarname"),
                    dbot_score=calculate_dbot_score(DBotScoreType.DOMAIN),
                )
            elif indicator_type == "File":
                indicator = Common.File(
                    md5=value,
                    sha1=fields.get("sha1"),
                    sha256=fields.get("sha256"),
                    name=fields.get("gibfilename"),
                    size=fields.get("size"),
                    dbot_score=calculate_dbot_score(DBotScoreType.FILE),
                )
            elif indicator_type == "URL":
                indicator = Common.URL(
                    url=value, dbot_score=calculate_dbot_score(DBotScoreType.URL)
                )
            elif indicator_type == "CVE":
                indicator = Common.CVE(
                    id=value,
                    cvss=fields.get("cvss"),
                    published=fields.get("published"),
                    modified=fields.get("cvemodified"),
                    description=fields.get("cvedescription"),
                )
        return indicator

    @staticmethod
    def find_iocs_in_feed(feed: str | dict[Any, Any], collection_name: str) -> list:
        """
        Finds IOCs in the feed and transform them to the appropriate format to ingest them into Demisto.

        :param feed: feed from GIB TI&A.
        :param collection_name: which collection this feed belongs to.
        """

        indicators = []
        if isinstance(feed, dict) and feed.get("indicators", None) is not None:
            indicator_types: dict = INDICATORS_TYPES.get(collection_name, {}).get("types", {})  # type: ignore
            add_fields_types: dict = INDICATORS_TYPES.get(collection_name, {}).get(
                "add_fields_types", {}
            )  # type: ignore
            if len(add_fields_types.keys()) > 0:
                fedd_indicators: dict = feed["indicators"]
                fedd_indicators.update(
                    {"severity": feed.get("evaluation", {}).get("severity")}
                )

            for indicator_type_name, indicator_type in indicator_types.items():
                add_fields = {}
                indicator_value = fedd_indicators.get(indicator_type_name)
                if indicator_type_name in add_fields_types:
                    for (
                        additional_field_name,
                        additional_field_type,
                    ) in add_fields_types.get(
                        indicator_type_name
                    ).items():  # type: ignore
                        additional_field_value = fedd_indicators.get(
                            additional_field_name
                        )
                        if additional_field_value is not None:
                            add_fields.update(
                                {additional_field_type: additional_field_value}
                            )

                output = IndicatorsHelper.parse_to_outputs(
                    indicator_value, indicator_type, add_fields
                )
                if output:
                    if len(add_fields) > 0:
                        add_fields.update(
                            {"severity": feed.get("evaluation", {}).get("severity")}
                        )
                    results = [
                        CommandResults(
                            readable_output=tableToMarkdown(
                                f"{indicator_type} indicator",
                                {"value": indicator_value, **add_fields},
                            ),
                            indicator=output,
                            ignore_auto_extract=True,
                        )
                    ]
                    indicators.append(results)

        return indicators


class IncidentBuilder:
    fields_list_for_parse = [
        "creationdate",
        "firstseenbysource",
        "lastseenbysource",
        "gibdatecompromised",
    ]

    def __init__(self, collection_name: str, incident: dict, mapping: dict) -> None:
        self.collection_name = collection_name
        self.incident = incident
        self.mapping = mapping

    def get_system_severity(self) -> int:
        severity = self.incident.get("evaluation", {}).get("severity")
        system_severity = 0
        if severity == "green":
            system_severity = 1
        elif severity == "orange":
            system_severity = 2
        elif severity == "red":
            system_severity = 3
        return system_severity

    def get_incident_created_time(self) -> str:
        occured_date_field = INCIDENT_CREATED_DATES_MAPPING.get(
            self.collection_name, "-"
        )

        if isinstance(occured_date_field, str):
            occured_date_field = [occured_date_field]

        assert isinstance(
            occured_date_field, list
        ), f"Expected list or string for occured_date_field, got {type(occured_date_field).__name__}"

        for variant in occured_date_field:
            try:
                incident_occured_date = dateparser_parse(
                    date_string=self.incident.get(variant, "")
                )
                assert incident_occured_date is not None, (
                    f"{self.incident} incident_occured_date cannot be None, "
                    f"occured_date_field: {variant}, incident_occured_date: {incident_occured_date}"
                )
                return incident_occured_date.strftime(DATE_FORMAT)
            except AssertionError as e:
                last_exception = e

        raise AssertionError(
            f"None of the date fields {occured_date_field} returned a valid date. Last error: {last_exception}"
        )

    def get_incident_name(self) -> str:
        name = ""
        prefix = PREFIXES.get(self.collection_name, "")
        if self.collection_name == "compromised/breached":
            names = self.incident["name"]
            if not isinstance(names, list):
                names = [names]
            name = f"{prefix}: " + ", ".join(names)
        else:
            name = f"{prefix}: {self.incident['name']}"

        return name

    def set_custom_severity(self):
        severity = self.incident.get("evaluation", {}).get("severity")
        if severity:
            set_severity = "Unknown"
            if severity == "green":
                set_severity = "Low"
            elif severity == "orange":
                set_severity = "Medium"
            elif severity == "red":
                set_severity = "High"

            self.incident["evaluation"]["severity"] = set_severity

    @staticmethod
    def date_conversion(date: str):
        try:
            date_obj = datetime.strptime(date, "%Y-%m-%d")
            return date_obj.isoformat()
        except ValueError:
            try:
                datetime.fromisoformat(date)
                return None
            except ValueError:
                raise ValueError("Invalid date format provided.")

    def check_dates(self):
        for field, value in self.incident.items():
            if field in SET_WITH_ALL_DATE_FIELDS and value is not None:
                new_value = self.date_conversion(value)
                if new_value:
                    self.incident[field] = new_value

    def osi_public_leak_mathes_transform_to_grid_table(self, field: str):
        field_data = self.incident.get(field, {})
        if field_data:
            new_matches = []
            if isinstance(field_data, list):
                field_data = {}
            for type_, sub_dict in field_data.items():
                for sub_type, sub_list in sub_dict.items():
                    for value in sub_list:
                        new_matches.append(
                            {"type": type_, "sub_type": sub_type, "value": value}
                        )

            transformed_and_replaced_empty_values_data = (
                CommonHelpers.replace_empty_values(new_matches)
            )
            clean_data = CommonHelpers.remove_underscore_and_lowercase_keys(
                transformed_and_replaced_empty_values_data  # type: ignore
            )
            self.incident[field] = clean_data

    def transform_fields_to_grid_table(self):
        fields_for_modify_in_table = TABLES_MAPPING.get(self.collection_name, [])

        if fields_for_modify_in_table:
            for field in fields_for_modify_in_table:
                if self.collection_name == "osi/public_leak" and field == "matches":
                    self.osi_public_leak_mathes_transform_to_grid_table(field=field)
                else:
                    field_data = self.incident.get(field, {})

                    if (
                        field_data
                        and CommonHelpers.all_lists_empty(field_data) is False
                    ):
                        transformed_data = CommonHelpers.transform_dict(
                            input_dict=field_data
                        )
                        if (
                            self.collection_name == "osi/git_repository"
                            and field == "files"
                        ):

                            transformed_data = CommonHelpers.transform_list_to_str(
                                transformed_data
                            )

                        transformed_and_replaced_empty_values_data = (
                            CommonHelpers.replace_empty_values(transformed_data)
                        )
                        clean_data = CommonHelpers.remove_underscore_and_lowercase_keys(
                            transformed_and_replaced_empty_values_data  # type: ignore
                        )

                        self.incident[field] = clean_data
                    else:
                        self.incident[field] = None

    def custom_generate_portal_link(self):
        if (
            self.collection_name
            in COLLECTIONS_FOR_WHICH_THE_PORTAL_LINK_WILL_BE_GENERATED
        ):
            # generating just for compromised/breached
            self.incident["portalLink"] = PORTAL_LINKS.get(
                "compromised/breached", ""
            ) + str(self.incident["emails"][0])

    def build_incident(self) -> dict:
        self.custom_generate_portal_link()
        incident_name = self.get_incident_name()
        system_severity = self.get_system_severity()
        self.incident.update(
            {
                "name": incident_name,
                "gibType": self.collection_name,
                "systemSeverity": system_severity,
            }
        )

        self.set_custom_severity()
        self.check_dates()
        self.transform_fields_to_grid_table()
        self.incident = CommonHelpers.remove_html_tags(
            self.incident, self.collection_name
        )
        data = {
            "name": self.incident["name"],
            "occurred": self.get_incident_created_time(),
            "rawJSON": json_dumps(self.incident),
            "dbotMirrorId": self.incident.get("id"),
        }
        return data


class BuilderCommandResponses:

    def __init__(self, client: Client, collection_name: str, args: dict) -> None:
        self.client = client
        self.collection_name = collection_name
        self.args = args

    def transform_additional_fields_to_markdown_tables(self, feed: dict):
        additional_tables = []
        delete_keys = []
        for key, value in feed.items():
            if key not in ("evaluation", "indicators") and isinstance(value, dict):
                additional_data = CommonHelpers.transform_dict(value)
                for index, item in enumerate(additional_data):
                    table = self.get_human_readable_feed(
                        table=item, name=f"{key} table {index}"
                    )
                    additional_tables.append(
                        CommandResults(
                            readable_output=table,
                            ignore_auto_extract=True,
                        )
                    )
                delete_keys.append(key)
        for key in delete_keys:
            feed.pop(key)

        return feed, additional_tables

    def get_feed(self) -> dict:
        id_ = str(self.args.get("id"))
        if self.collection_name in ["threat", "threat_actor"]:
            flag = self.args.get("isAPT")
            if flag:
                self.collection_name = "apt/" + self.collection_name
            else:
                self.collection_name = "hi/" + self.collection_name

        cleaned_feed = {}
        if (
            self.collection_name
            in COLLECTIONS_THAT_MAY_NOT_SUPPORT_ID_SEARCH_VIA_UPDATED
        ):
            portions = self.client.poller.create_update_generator(
                collection_name=self.collection_name, query=id_
            )
            for portion in portions:
                parsed_portion = portion.parse_portion(
                    keys=MAPPING.get(self.collection_name, {})
                )
                cleaned_feed = parsed_portion[0] if isinstance(parsed_portion, list) else parsed_portion  # type: ignore

        else:
            result = self.client.poller.search_feed_by_id(self.collection_name, id_)

            parsed_portion = result.parse_portion(
                keys=MAPPING.get(self.collection_name, {})
            )
            cleaned_feed = parsed_portion[0] if isinstance(parsed_portion, list) else parsed_portion  # type: ignore

        return cleaned_feed  # type: ignore

    def get_indicators(
        self, feed: dict[Any, Any]
    ) -> tuple[list[CommandResults] | list, dict[Any, Any]]:
        indicators = []
        indicators = IndicatorsHelper.find_iocs_in_feed(
            feed=feed, collection_name=self.collection_name
        )

        return indicators, feed

    def get_table_data(
        self,
        feed: dict[Any, Any],
    ):
        dont_need_transformations = ["compromised/breached"]

        main_table_data, additional_tables = feed, (
            []
            if self.collection_name in dont_need_transformations
            else self.transform_additional_fields_to_markdown_tables(feed)
        )

        return main_table_data, additional_tables

    def get_human_readable_feed(self, table: dict[Any, Any], name: str):
        return tableToMarkdown(
            name=name,
            t=table,
            removeNull=True,
        )

    def build_feed(self):
        feed = self.get_feed()
        indicators, feed = self.get_indicators(feed=feed)
        main_table_data, additional_tables = self.get_table_data(feed=feed)
        feed_id = feed.get("id")
        readable_output = self.get_human_readable_feed(
            table=feed, name=f"Feed from {self.collection_name} with ID {feed_id}"
        )
        return feed, main_table_data, additional_tables, indicators, readable_output


""" Commands """


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    :param client: GIB_TI client
    :return: 'ok' if test passed, anything else will fail the test.
    """

    for collection in client.poller.get_available_collections():
        if collection not in MAPPING.keys():
            return f"Test failed, some problems with getting available collections. Error in collection {str(collection)}"
    return "ok"


def fetch_incidents_command(
    client: Client,
    last_run: dict,
    first_fetch_time: str,
    incident_collections: list[str],
    max_requests: int,
    hunting_rules: int,
) -> tuple[dict, list]:
    """
    This function will execute each interval (default is 1 minute).

    :param client: GIB_TI&A_Feed client.
    :param last_run: the greatest sequpdate we fetched from last fetch.
    :param first_fetch_time: if last_run is None then fetch all incidents since first_fetch_time.
    :param incident_collections: list of collections enabled by client.
    :param max_requests: count of requests to API per collection.
    :param hunting_rules: enable this parameter to collect using hunting rules

    :return: next_run will be last_run in the next fetch-incidents; incidents and indicators will be created in Demisto.
    """
    incidents = []
    next_run: dict[str, dict[str, int | Any]] = {"last_fetch": {}}
    for collection_name in incident_collections:  # noqa: B007
        last_fetch = last_run.get("last_fetch", {}).get(collection_name)
        requests_count = 0
        sequpdate = 0
        portions, last_fetch = client.create_poll_generator(
            collection_name=collection_name,
            hunting_rules=hunting_rules,
            last_fetch=last_fetch,
            first_fetch_time=first_fetch_time,
        )

        mapping = MAPPING.get(collection_name, {})
        for portion in portions:
            sequpdate = portion.sequpdate
            new_parsed_json = portion.bulk_parse_portion(
                keys_list=[mapping], as_json=False
            )
            if isinstance(new_parsed_json, list):
                for i in new_parsed_json:
                    for incident in i:
                        constructed_incident = IncidentBuilder(
                            collection_name=collection_name,
                            incident=incident,
                            mapping=mapping,
                        ).build_incident()
                        incidents.append(constructed_incident)
            else:
                raise Exception("new_parsed_json in portion should not be a string")

            requests_count += 1
            if requests_count > max_requests:
                break

        if collection_name == "compromised/breached":
            next_run["last_fetch"][collection_name] = last_fetch

        next_run["last_fetch"][collection_name] = sequpdate

    return next_run, incidents


def get_available_collections_command(client: Client, args: dict | None = None):
    """
    Returns list of available collections to context and War Room.

    :param client: GIB_TI&A_Feed client.
    """

    my_collections = client.poller.get_available_collections()
    readable_output = tableToMarkdown(
        name="Available collections",
        t={"collections": my_collections},
        headers="collections",
    )
    return CommandResults(
        outputs_prefix="GIBTIA.OtherInfo",
        outputs_key_field="collections",
        outputs={"collections": my_collections},
        readable_output=readable_output,
        ignore_auto_extract=True,
        raw_response=my_collections,
    )


def get_info_by_id_command(collection_name: str):
    """
    Decorator around actual commands, that returns command depends on `collection_name`.
    """

    def get_info_by_id_for_collection(
        client: Client, args: dict
    ) -> list[CommandResults]:
        """
        This function returns additional information to context and War Room.

        :param client: GIB_TI&A_Feed client.
        :param args: arguments, provided by client.
        """
        results = []

        feed, main_table_data, additional_tables, indicators, readable_output = (
            BuilderCommandResponses(
                client=client, collection_name=collection_name, args=args
            ).build_feed()
        )

        results.append(
            CommandResults(
                outputs_prefix="GIBTIA.{}".format(
                    PREFIXES.get(collection_name, "").replace(" ", "")
                ),
                outputs_key_field="id",
                outputs=feed,
                readable_output=readable_output,
                raw_response=feed,
                ignore_auto_extract=True,
            )
        )
        results.extend(additional_tables)
        results.extend(indicators)
        return results

    return get_info_by_id_for_collection


def global_search_command(client: Client, args: dict):
    query = str(args.get("query"))
    raw_response = client.poller.global_search(query=query)
    handled_list = []
    for result in raw_response:
        if result.get("apiPath") in MAPPING:
            apiPath = result.get("apiPath")
            handled_list.append(
                {
                    "apiPath": apiPath,
                    "count": result.get("count"),
                    "GIBLink": result.get("link"),
                    "query": f"{apiPath}?q={query}",
                }
            )
    if len(handled_list) != 0:
        results = CommandResults(
            outputs_prefix="GIBTIA.search.global",
            outputs_key_field="query",
            outputs=handled_list,
            readable_output=tableToMarkdown(
                "Search results",
                t=handled_list,
                headers=["apiPath", "count", "GIBLink"],
                url_keys=["GIBLink"],
            ),
            raw_response=raw_response,
            ignore_auto_extract=True,
        )
    else:
        results = CommandResults(
            raw_response=raw_response,
            ignore_auto_extract=True,
            outputs=[],
            readable_output="Did not find anything for your query :(",
        )
    return results


def local_search_command(client: Client, args: dict):
    query, date_from, date_to = (
        args.get("query"),
        args.get("date_from", None),
        args.get("date_to", None),
    )
    collection_name = str(args.get("collection_name"))

    date_from_parsed = (
        CommonHelpers.date_parse(date=date_from, arg_name="date_from")
        if date_from is not None
        else date_from
    )
    date_to_parsed = (
        CommonHelpers.date_parse(date=date_to, arg_name="date_to")
        if date_to is not None
        else date_to
    )

    portions = client.poller.create_search_generator(
        collection_name=collection_name,
        query=query,
        date_from=date_from_parsed,
        date_to=date_to_parsed,
    )
    mapping = MAPPING.get(collection_name, {})

    result_list = []
    for portion in portions:
        new_parsed_json = portion.parse_portion(keys=mapping, as_json=False)
        for feed in new_parsed_json:
            name = feed.get("name", None)
            if name is not None:
                name = f"Name: {name}"
            result_list.append({"id": feed.get("id"), "additional_info": name})

    results = CommandResults(
        outputs_prefix="GIBTIA.search.local",
        outputs_key_field="id",
        outputs=result_list,
        readable_output=tableToMarkdown(
            "Search results", t=result_list, headers=["id", "additional_info"]
        ),
        ignore_auto_extract=True,
    )
    return results


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    try:
        params = demisto.params()
        credentials: dict = params.get("credentials", {})
        username = credentials.get("identifier")
        password = credentials.get("password")
        base_url = str(params.get("url"))
        proxy = params.get("proxy", False)
        hunting_rules = params.get("hunting_rules", 0)
        verify_certificate = not params.get("insecure", False)
        endpoint = None

        incident_collections = params.get("incident_collections", [])
        incidents_first_fetch = params.get("first_fetch", "3 days").strip()
        requests_count = int(params.get("max_fetch", 3))

        args = demisto.args()
        command = demisto.command()
        LOG(f"Command being called is {command}")

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy,
            headers={"Accept": "*/*"},
        )
        demisto.info("client getted")

        deprecated_comands = [
            "gibtia-get-compromised-card-info",
            "gibtia-get-compromised-imei-info",
            "gibtia-get-malware-targeted-malware-info",
            "gibtia-get-phishing-info",
        ]
        if command in deprecated_comands:
            raise Exception(f"{command} deprecated")

        if hunting_rules is True:
            hunting_rules = 1
            list_hunting_rules_collections = (
                client.poller.get_hunting_rules_collections()
            )

            for collection in incident_collections:
                if collection not in list_hunting_rules_collections:
                    raise Exception(
                        f"Collection {collection} Does't support hunting rules"
                    )

        
        info_comands = {
            "gibtia-get-compromised-account-info": "compromised/account_group",
            "gibtia-get-compromised-card-group-info": "compromised/bank_card_group",
            "gibtia-get-compromised-mule-info": "compromised/mule",
            "gibtia-get-compromised-breached-info": "compromised/breached",
            "gibtia-get-phishing-kit-info": "attacks/phishing_kit",
            "gibtia-get-phishing-group-info": "attacks/phishing_group",
            "gibtia-get-osi-git-leak-info": "osi/git_repository",
            "gibtia-get-osi-public-leak-info": "osi/public_leak",
            "gibtia-get-osi-vulnerability-info": "osi/vulnerability",
            "gibtia-get-attacks-ddos-info": "attacks/ddos",
            "gibtia-get-attacks-deface-info": "attacks/deface",
            "gibtia-get-threat-info": "threat",
            "gibtia-get-threat-actor-info": "threat_actor",
            "gibtia-get-suspicious-ip-tor-node-info": "suspicious_ip/tor_node",
            "gibtia-get-suspicious-ip-open-proxy-info": "suspicious_ip/open_proxy",
            "gibtia-get-suspicious-ip-socks-proxy-info": "suspicious_ip/socks_proxy",
            "gibtia-get-suspicious-ip-vpn-info": "suspicious_ip/vpn",
            "gibtia-get-suspicious-ip-scanner-info": "suspicious_ip/scanner",
            "gibtia-get-malware-cnc-info": "malware/cnc",
            "gibtia-get-malware-malware-info": "malware/malware",
        }

        other_commands = {
            "gibtia-get-available-collections": get_available_collections_command,
            "gibtia-global-search": global_search_command,
            "gibtia-local-search": local_search_command,
        }

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif command == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents_command(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=incidents_first_fetch,
                incident_collections=incident_collections,
                max_requests=requests_count,
                hunting_rules=hunting_rules,
            )
            demisto.info(f"{str(incidents)}")
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            incident_collections = None
            if command in info_comands:
                endpoint = info_comands[command]
                result = get_info_by_id_command(endpoint)(client, args)
            else:
                result = other_commands[command](client, args)  # type: ignore
            return_results(result)

    # Log exceptions
    except Exception:
        return_error(
            f"Failed to execute {demisto.command()} command.\n"
            f"Incident collection: {incident_collections}.\n"
            f"Command endpoint: {endpoint}.\n Error: {format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
