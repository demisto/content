import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


""" IMPORTS """


from json import dumps as json_dumps
from datetime import datetime

from dateparser import parse as dateparser_parse  # type: ignore[import-untyped]
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
from cyberintegrations import TIPoller
from cyberintegrations.utils import ParserHelper
from traceback import format_exc
import re
from enum import Enum
from itertools import chain
from collections.abc import Iterable
from typing import Any, TypeAlias, cast

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
            },
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
            },
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
            },
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
            },
        },
    },
    "osi/vulnerability": {
        "types": {
            "id": "CVE",
        },
        "markdowns": {
            "software_mixed": (
                "| Software Name | Software Type | Software Version |\n| ------------- | ------------- | ---------------- |\n"
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
        "add_fields_types": {"contributors_emails": {}, "hash": {}},
    },
    "attacks/phishing_kit": {
        "types": {"emails": "Email"},
        "add_fields_types": {"emails": {}},
    },
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
            },
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
            },
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
            },
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
            },
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
            },
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
    "compromised/bank_card_group": ["dateFirstCompromised", "dateFirstSeen"],
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
    "osi/public_leak",
    "attacks/phishing_group",
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

COLLECTIONS_THAT_ARE_REQUIRED_HUNTING_RULES = [
    "osi/git_repository",
    "osi/public_leak",
    "compromised/breached",
]

COLLECTIONS_FOR_WHICH_THE_PORTAL_LINK_WILL_BE_GENERATED = ["compromised/breached"]

COLLECTIONS_REQUIRING_SEARCH_VIA_QUERY_PARAMETER = [
    "osi/public_leak",
    "attacks/phishing_group",
]

COMMON_SCORE_MAP = {
    "unknown": Common.DBotScore.NONE,
    "good": Common.DBotScore.GOOD,
    "suspicious": Common.DBotScore.SUSPICIOUS,
    "bad": Common.DBotScore.BAD,
}

Reliability: TypeAlias = str

COMMON_REABILITY_MAP: dict[str, Reliability] = {
    "a": DBotScoreReliability.A,
    "a+": DBotScoreReliability.A_PLUS,
    "b": DBotScoreReliability.B,
    "c": DBotScoreReliability.C,
    "d": DBotScoreReliability.D,
    "e": DBotScoreReliability.E,
    "f": DBotScoreReliability.F,
}


class NumberedSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class StringSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


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
            "tlp": "evaluation.tlp",  # GIB TLP
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
        "source_type": "sourceType",  # Not displayed in the incident, but used in the code
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
            "cvv": "events.cardInfo.cvv",
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
            "tlp": "evaluation.tlp",  # GIB TLP
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
        "isTailored": "isTailored",  # GIB Is Tailored
        "expertise": "expertise",  # GIB Cybercriminal Expertises
        "regions": "regions",  # GIB Cybercriminal Regions
        "sectors": "sectors",  # GIB Cybercriminal Sectors
        "reportNumber": "reportNumber",  # GIB Report Number
        # Group-IB Dates
        "createdAt": "createdAt",  # GIB Date Created At
        "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
        "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
        # END Group-IB Dates
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
            "tlp": "evaluation.tlp",  # GIB TLP
        },
        # END Group-IB Evaluation
        # Group-IB Nation-State Cybercriminal Forum Information
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

DEPRECATED_COLLECTIONS = {
    "malware/targeted_malware": "malware/malware",
    "compromised/masked_cards": "compromised/bank_card_group",
    "compromised/bank_card": "compromised/bank_card_group",
    "compromised/card": "compromised/bank_card_group",
    "compromised/account": "compromised/account_group",
    "attacks/phishing": "attacks/phishing_group",
}

REMOVED_COLLECTIONS = ["bp/phishing", "bp/phishing_kit", "compromised/imei"]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    limit = 100

    def __init__(self, base_url, verify=True, proxy=False, headers=None, auth=None, limit: int = 100):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

        self._auth: tuple[str, str]
        self.poller = TIPoller(
            username=self._auth[0],
            api_key=self._auth[1],
            api_url=base_url,
        )
        self.limit = int(limit)
        self.poller.set_product(
            product_type="SOAR",
            product_name="CortexSOAR",
            product_version="unknown",
            integration_name="Group-IB Threat Intelligence",
            integration_version="2.3.2",
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
                    f"please use a format such as: 2020-01-01 or January 1 2020 or 3 days. The format given is: {date_from}"
                )
            date_from = date_from.strftime("%Y-%m-%d")  # type: ignore
        demisto.debug(
            "[handle_first_time_fetch] Computed initial parameters: "
            f"last_fetch_exists={bool(last_fetch)}, date_from={date_from}"
        )

        return last_fetch, date_from  # type: ignore

    def create_poll_generator(
        self,
        collection_name: str,
        hunting_rules: int,
        enable_probable_corporate_access: bool,
        unique: bool,
        combolist: bool,
        **kwargs,
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
            demisto.debug(
                "[create_poll_generator] Using search generator for compromised/breached: "
                f"last_fetch={last_fetch}, date_from={date_from}, date_to={date_to}, "
                f"starting_date_from={starting_date_from}, starting_date_to={starting_date_to}"
            )

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
            sequpdate_for_generator = last_fetch
            date_from_for_generator = date_from
            if not last_fetch and date_from:
                try:
                    demisto.debug(
                        "[create_poll_generator] Resolving initial seqUpdate via sequence_list: "
                        f"collection={collection_name}, date_from={date_from}, hunting_rules={hunting_rules}"
                    )
                    seq_map = self.poller.get_seq_update_dict(
                        date=date_from,
                        collection_name=collection_name,
                        apply_hunting_rules=hunting_rules,
                    )
                    resolved_seq = seq_map.get(collection_name)
                    if resolved_seq:
                        sequpdate_for_generator = resolved_seq
                        date_from_for_generator = None
                        demisto.debug(f"[create_poll_generator] Using resolved seqUpdate={resolved_seq}; dropping date_from")
                    else:
                        demisto.debug(
                            "[create_poll_generator] sequence_list returned empty for collection; fallback to date_from"
                        )
                except Exception as e:
                    demisto.debug(f"[create_poll_generator] sequence_list resolution failed: {e}; fallback to date_from")

            demisto.debug(
                "[create_poll_generator] Using update generator: "
                f"collection={collection_name}, sequpdate={sequpdate_for_generator}, date_from={date_from_for_generator}, "
                f"limit={self.limit}, hunting_rules={hunting_rules}"
            )

            return (
                self.poller.create_update_generator(
                    collection_name=collection_name,
                    date_from=date_from_for_generator,
                    sequpdate=sequpdate_for_generator,
                    limit=self.limit,
                    apply_hunting_rules=hunting_rules,
                    probable_corporate_access=int(enable_probable_corporate_access),
                    unique=int(unique),
                    combolist=int(combolist),
                ),
                sequpdate_for_generator,
            )

    def search_proxy_function(self, query: str) -> list[dict[str, Any]]:
        return self.poller.global_search(query=query)

    def get_available_collections_proxy_function(self) -> list:
        return self.poller.get_available_collections()


""" Support functions """


class CommonHelpers:
    @staticmethod
    def transform_dict(input_dict: dict[str, list[str | list[Any]] | str | None]) -> list[dict[str, Any]]:
        if not input_dict:
            return [{}]

        normalized_dict = {
            k: v if isinstance(v, list) else [v]  # type: ignore
            for k, v in input_dict.items()
        }

        max_length = max((len(v) for v in normalized_dict.values() if isinstance(v, list)), default=1)

        result = []
        for i in range(max_length):
            result.append({k: (v[i] if i < len(v) else (v[0] if v else None)) for k, v in normalized_dict.items()})

        return result

    @staticmethod
    def remove_underscore_and_lowercase_keys(dict_list: list[dict[str, Any]] | list[dict[str, Any]]) -> list[dict[str, Any]]:
        updated_dicts = []

        for d in dict_list:
            new_dict = {}
            for key, value in d.items():
                new_key = key.replace("_", "").lower()
                new_dict[new_key] = value

            updated_dicts.append(new_dict)

        return updated_dicts

    @staticmethod
    def replace_empty_values(data: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any] | list[dict[str, Any]]:
        if isinstance(data, dict):
            return {key: CommonHelpers.replace_empty_values(value) for key, value in data.items()}

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
    def safe_json_one_line(obj: Any) -> str:
        """
        Serialize an object to a single-line JSON string for safe War Room/context rendering.
        Falls back to `str(obj)` if JSON serialization fails.
        """
        try:
            return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
        except Exception:
            return str(obj)

    @staticmethod
    def date_parse(date: str, arg_name: str) -> str:
        date_from_parsed = dateparser_parse(date)
        if date_from_parsed is None:
            raise DemistoException(
                f"Inappropriate {arg_name} format, please use something like this: 2020-01-01 or January 1 2020"
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

    @staticmethod
    def custom_generate_portal_link(collection_name: str, incident: dict):
        if collection_name in COLLECTIONS_FOR_WHICH_THE_PORTAL_LINK_WILL_BE_GENERATED:
            # generating just for compromised/breached
            incident["portalLink"] = PORTAL_LINKS.get("compromised/breached", "") + str(incident["emails"][0])

        return incident

    @staticmethod
    def validate_collections(collection_name):
        if collection_name in DEPRECATED_COLLECTIONS:
            raise Exception(f"Collection {collection_name} is obsolete. Please use {DEPRECATED_COLLECTIONS.get(collection_name)}")
        if collection_name in REMOVED_COLLECTIONS:
            raise Exception(f"The {collection_name} collection is not valid")


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
    def parse_to_outputs(value: str | None | list, indicator_type: str, fields: dict) -> Any:
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
                integration_name="GIB TI",
                score=score,
            )

        indicator: Any = None
        if (value is not None or len(fields) > 0) and IndicatorsHelper.check_empty_list(fields) is False:
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
                    url=value,
                    dbot_score=calculate_dbot_score(DBotScoreType.URL),
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

        :param feed: feed from GIB TI.
        :param collection_name: which collection this feed belongs to.
        """

        indicators = []
        if isinstance(feed, dict) and feed.get("indicators", None) is not None:
            indicator_types: dict = INDICATORS_TYPES.get(collection_name, {}).get("types", {})  # type: ignore
            add_fields_types: dict = INDICATORS_TYPES.get(collection_name, {}).get("add_fields_types", {})  # type: ignore
            if len(add_fields_types.keys()) > 0:
                fedd_indicators: dict = feed["indicators"]
                fedd_indicators.update({"severity": feed.get("evaluation", {}).get("severity")})

            for indicator_type_name, indicator_type in indicator_types.items():
                add_fields = {}
                indicator_value = fedd_indicators.get(indicator_type_name)
                if indicator_type_name in add_fields_types:
                    for (
                        additional_field_name,
                        additional_field_type,
                    ) in add_fields_types.get(indicator_type_name).items():  # type: ignore
                        additional_field_value = fedd_indicators.get(additional_field_name)
                        if additional_field_value is not None:
                            add_fields.update({additional_field_type: additional_field_value})

                output = IndicatorsHelper.parse_to_outputs(indicator_value, indicator_type, add_fields)
                if output:
                    if len(add_fields) > 0:
                        add_fields.update({"severity": feed.get("evaluation", {}).get("severity")})
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

    @staticmethod
    def dbot_from_score(score: Any) -> int:
        """
        Convert numeric Group-IB riskScore (0..100) into XSOAR DBotScore.

        Mapping:
        - None / out of range -> NONE (Unknown)
        - 0..49 -> GOOD
        - 50..84 -> SUSPICIOUS
        - 85..100 -> BAD
        """
        if score is None:
            return Common.DBotScore.NONE
        if 0 <= score <= 49:
            return Common.DBotScore.GOOD
        if 50 <= score <= 84:
            return Common.DBotScore.SUSPICIOUS
        if 85 <= score <= 100:
            return Common.DBotScore.BAD
        return Common.DBotScore.NONE

    @staticmethod
    def collect_portions_for_indicator(
        indicator_name: str,
        indicator_value: str,
        path: str,
        poller: Any,
        dates_mapping: dict[str, dict[str, str]] | None,
        sensitive_collections: list[str] | None,
    ) -> list:
        """Collect parsed portions for a given path."""
        portions = poller.create_update_generator(collection_name=path, query=indicator_value)
        portions_data = []
        use_dates = path in (sensitive_collections or [])
        for portion in portions:
            if use_dates and dates_mapping:
                parsed_portion = portion.parse_portion(keys=dates_mapping.get(path))
            else:
                parsed_portion = portion.raw_dict
            cleaned_feed = parsed_portion[0] if isinstance(parsed_portion, list) else parsed_portion  # type: ignore
            portions_data.append(cleaned_feed)
        return portions_data

    @staticmethod
    def build_ip_enrichment(
        poller: Any,
        indicator_value: str,
        mapping: dict[str, Any],
    ) -> dict[str, Any]:
        """Build scoring and graph IP enrichment block."""
        data: dict[str, Any] = {}
        # Commented as an update is required: https://github.com/demisto/dockerfiles/pull/41838
        # scoring = poller.scoring(indicator_value)
        scoring = {"items": {indicator_value: {"ip": indicator_value, "riskScore": 35}}}
        score = scoring.get("items", {}).get(indicator_value, {}).get("riskScore")
        data.update({"scoring": {"score": score}})

        try:
            graph_ip = poller.graph_ip_search(indicator_value)
            graph_data = ParserHelper.find_by_template(graph_ip, keys=mapping)
            data.update({"graph_ip": graph_data})
        except Exception as e:
            demisto.debug(f"[graph_ip_search] failed for {indicator_value}: {e}")
        return data

    @staticmethod
    def parse_source_reliability(value: str | None) -> Reliability | None:
        """
        Parse Source Reliability parameter (e.g. 'A - Completely reliable') into DBotScoreReliability.
        Returns None if missing or unrecognized.
        """
        if not value:
            return None
        token = value.split()[0].strip().lower()
        return COMMON_REABILITY_MAP.get(token)


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
        severity_map = {
            "green": NumberedSeverity.LOW.value,
            "orange": NumberedSeverity.MEDIUM.value,
            "red": NumberedSeverity.HIGH.value,
        }
        severity = self.incident.get("evaluation", {}).get("severity")
        return severity_map.get(severity, 0)

    def get_incident_created_time(self) -> str:
        last_exception = None
        incident_id = self.incident.get("id", None)
        occured_date_field = INCIDENT_CREATED_DATES_MAPPING.get(self.collection_name, "-")

        if isinstance(occured_date_field, str):
            occured_date_field = [occured_date_field]

        if not isinstance(occured_date_field, list):
            raise DemistoException(f"Expected list or string for occured_date_field, got {type(occured_date_field).__name__}")

        for variant in occured_date_field:
            try:
                date_value = self.incident.get(variant, "")

                if date_value is None:
                    continue
                if not isinstance(date_value, str):
                    date_value = str(date_value)
                if not date_value.strip():
                    continue
                incident_occured_date = dateparser_parse(date_string=date_value)

                assert incident_occured_date is not None, (
                    f"{self.incident} incident_occured_date cannot be None, "
                    f"occured_date_field: {variant}, incident_occured_date: {incident_occured_date}"
                    f"{self.collection_name} {incident_id}"
                )
                return incident_occured_date.strftime(DATE_FORMAT)
            except AssertionError as e:
                last_exception = e

        raise AssertionError(
            f"None of the date fields {occured_date_field} returned a valid date."
            f"Last error: {last_exception} {self.collection_name} {incident_id}"
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
        severity_map = {
            "green": StringSeverity.LOW.value,
            "orange": StringSeverity.MEDIUM.value,
            "red": StringSeverity.HIGH.value,
        }
        severity = self.incident.get("evaluation", {}).get("severity")
        if severity:
            self.incident["evaluation"]["severity"] = severity_map.get(severity, "Unknown")

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
                raise ValueError(f"Invalid date format provided: {date}")

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
                        new_matches.append({"type": type_, "sub_type": sub_type, "value": value})

            transformed_and_replaced_empty_values_data = CommonHelpers.replace_empty_values(new_matches)
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

                    if field_data and CommonHelpers.all_lists_empty(field_data) is False:
                        transformed_data = CommonHelpers.transform_dict(input_dict=field_data)
                        if self.collection_name == "osi/git_repository" and field == "files":
                            transformed_data = CommonHelpers.transform_list_to_str(transformed_data)

                        transformed_and_replaced_empty_values_data = CommonHelpers.replace_empty_values(transformed_data)
                        clean_data = CommonHelpers.remove_underscore_and_lowercase_keys(
                            transformed_and_replaced_empty_values_data  # type: ignore
                        )

                        self.incident[field] = clean_data
                    else:
                        self.incident[field] = None

    def build_incident(self) -> dict:
        self.incident = CommonHelpers.custom_generate_portal_link(collection_name=self.collection_name, incident=self.incident)
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
        self.incident = CommonHelpers.remove_html_tags(self.incident, self.collection_name)
        data = {
            "name": self.incident["name"],
            "occurred": self.get_incident_created_time(),
            "rawJSON": json_dumps(self.incident),
            "dbotMirrorId": self.incident.get("id"),
        }
        return data


class BuilderCommandResponses:
    dont_need_transformations = ["compromised/breached"]

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
                    table = self.get_human_readable_feed(table=item, name=f"{key} table {index}")
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
        cleaned_feed = {}
        if self.collection_name in COLLECTIONS_THAT_MAY_NOT_SUPPORT_ID_SEARCH_VIA_UPDATED:
            if self.collection_name in COLLECTIONS_REQUIRING_SEARCH_VIA_QUERY_PARAMETER:
                query = f"id:{id_}"
            else:
                query = id_
            portions = self.client.poller.create_update_generator(collection_name=self.collection_name, query=query)
            for portion in portions:
                parsed_portion = portion.parse_portion(keys=MAPPING.get(self.collection_name, {}))
                cleaned_feed = parsed_portion[0] if isinstance(parsed_portion, list) else parsed_portion  # type: ignore

        else:
            result = self.client.poller.search_feed_by_id(self.collection_name, id_)
            mapping = MAPPING.get(self.collection_name, {})
            # This was done because the response when receiving a single record can
            # differentiate your json from getting the whole list
            if self.collection_name == "compromised/breached":
                mapping["emailDomains"] = "emails"

            parsed_portion = result.parse_portion(keys=mapping)
            cleaned_feed = parsed_portion[0] if isinstance(parsed_portion, list) else parsed_portion  # type: ignore

        return cleaned_feed  # type: ignore

    def get_indicators(self, feed: dict[Any, Any]) -> tuple[list[CommandResults] | list, dict[Any, Any]]:
        indicators = []
        indicators = IndicatorsHelper.find_iocs_in_feed(feed=feed, collection_name=self.collection_name)

        return indicators, feed

    def get_table_data(
        self,
        feed: dict[Any, Any],
    ):
        main_table_data, additional_tables = (
            feed,
            (
                []
                if self.collection_name in self.dont_need_transformations
                else self.transform_additional_fields_to_markdown_tables(feed)
            ),
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
        feed = CommonHelpers.custom_generate_portal_link(collection_name=self.collection_name, incident=feed)
        indicators, feed = self.get_indicators(feed=feed)
        main_table_data, additional_tables = self.get_table_data(feed=feed)
        feed_id = feed.get("id")
        readable_output = self.get_human_readable_feed(table=feed, name=f"Feed from {self.collection_name} with ID {feed_id}")
        return feed, main_table_data, additional_tables, indicators, readable_output


""" Commands """


def _parse_seq_update(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _serialize_seq_update(value: int) -> str:
    return str(value)


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    :param client: GIB_TI client
    :return: 'ok' if test passed, anything else will fail the test.
    """
    test = client.poller.get_available_collections()
    if len(test) == 0:
        return "There are no collections available"
    return "ok"


def collection_availability_check(client: Client, collection_name: str) -> None:
    if collection_name not in client.poller.get_available_collections():
        raise Exception(
            f"Collection {collection_name} is not available from you, "
            "please disable collection on it or contact Group-IB to grant access"
        )


def fetch_incidents_command(
    client: Client,
    last_run: dict,
    first_fetch_time: str,
    incident_collections: list[str],
    max_requests: int,
    hunting_rules: int,
    combolist: bool = False,
    unique: bool = False,
    enable_probable_corporate_access: bool = False,
) -> tuple[dict, list]:
    """
    This function will execute each interval (default is 1 minute).

    :param client: GIB_TI_Feed client.
    :param last_run: the greatest sequpdate we fetched from last fetch.
    :param first_fetch_time: if last_run is None then fetch all incidents since first_fetch_time.
    :param incident_collections: list of collections enabled by client.
    :param max_requests: count of requests to API per collection.
    :param hunting_rules: enable this parameter to collect using hunting rules

    :return: next_run will be last_run in the next fetch-incidents; incidents and indicators will be created in Demisto.
    """
    demisto.debug(
        "[fetch-incidents] Starting fetch with params: "
        f"collections={incident_collections}, max_requests={max_requests}, "
        f"hunting_rules={hunting_rules}, combolist={combolist}, unique={unique}, "
        f"enable_probable_corporate_access={enable_probable_corporate_access}, "
        f"first_fetch_time={first_fetch_time}"
    )
    incidents: list[dict] = []
    next_run: dict[str, dict[str, int | Any]] = {"last_fetch": {}}
    for collection_name in incident_collections:  # noqa: B007
        collection_availability_check(client=client, collection_name=collection_name)
        CommonHelpers.validate_collections(collection_name)
        last_fetch_raw = None
        if isinstance(last_run, dict):
            embedded = last_run.get("last_fetch")
            if isinstance(embedded, dict):
                last_fetch_raw = embedded.get(collection_name)
            else:
                last_fetch_raw = last_run.get(collection_name)
        demisto.debug(f"[fetch-incidents] Collection={collection_name} previous_last_fetch={last_fetch_raw}")
        requests_count = 0
        sequpdate = 0

        last_fetch_for_generator: Any
        if collection_name == "compromised/breached":
            last_fetch_for_generator = last_fetch_raw
        else:
            last_fetch_int = _parse_seq_update(last_fetch_raw)
            last_fetch_for_generator = (
                _serialize_seq_update(last_fetch_int) if isinstance(last_fetch_int, int) and last_fetch_int > 0 else None
            )

        portions, generator_cursor_raw = client.create_poll_generator(
            collection_name=collection_name,
            hunting_rules=hunting_rules,
            last_fetch=last_fetch_for_generator,
            first_fetch_time=first_fetch_time,
            enable_probable_corporate_access=enable_probable_corporate_access,
            combolist=combolist,
            unique=unique,
        )

        mapping = MAPPING.get(collection_name, {})
        demisto.debug(f"[fetch-incidents] Collection={collection_name} generator created: {portions}")

        generator_cursor_int = _parse_seq_update(generator_cursor_raw)
        max_seen_seq_update: int | None = None

        for portion in portions:
            sequpdate = portion.sequpdate
            demisto.debug(
                f"[fetch-incidents] Portion received: collection={collection_name}, seqUpdate={sequpdate}, "
                f"portion_size={portion.portion_size}, count={portion.count}"
            )
            new_parsed_json = portion.bulk_parse_portion(keys_list=[mapping], as_json=False)
            if not isinstance(new_parsed_json, list):
                raise Exception("new_parsed_json in portion should be a list")

            portion_seq_int = _parse_seq_update(sequpdate)
            if (
                isinstance(generator_cursor_int, int)
                and isinstance(portion_seq_int, int)
                and portion_seq_int <= generator_cursor_int
            ):
                demisto.debug(
                    f"[fetch-incidents] seqUpdate did not advance (portion_seq={sequpdate}, "
                    f"cursor_seq={generator_cursor_raw}); skipping portion to avoid duplicates."
                )
                break

            if new_parsed_json and isinstance(new_parsed_json[0], list):
                iterable: Iterable[dict] = cast(Iterable[dict], chain.from_iterable(new_parsed_json))
            else:
                iterable = cast(Iterable[dict], new_parsed_json)

            iterable = [item for item in iterable if isinstance(item, dict) and item.get("id")]
            if not iterable:
                demisto.debug(
                    f"[fetch-incidents] Portion contains no incidents with ids; skipping addition. "
                    f"collection={collection_name}, seqUpdate={sequpdate}"
                )
                continue

            before_count = len(incidents)
            incidents.extend(
                IncidentBuilder(
                    collection_name=collection_name,
                    incident=incident,
                    mapping=mapping,
                ).build_incident()
                for incident in iterable
            )
            added = len(incidents) - before_count
            demisto.debug(f"[fetch-incidents] Built incidents for portion: added={added}, total={len(incidents)}")

            if isinstance(portion_seq_int, int) and portion_seq_int > 0:
                max_seen_seq_update = (
                    portion_seq_int if max_seen_seq_update is None else max(max_seen_seq_update, portion_seq_int)
                )

            requests_count += 1
            if requests_count >= max_requests:
                break

        if collection_name == "compromised/breached":
            next_run["last_fetch"][collection_name] = generator_cursor_raw
        else:
            demisto.debug(f"[fetch-incidents] Final seqUpdate for collection={collection_name}: {sequpdate}")
            effective_last_fetch_int: int | None = None
            if isinstance(max_seen_seq_update, int) and max_seen_seq_update > 0:
                effective_last_fetch_int = max_seen_seq_update
            elif isinstance(generator_cursor_int, int) and generator_cursor_int > 0:
                effective_last_fetch_int = generator_cursor_int

            next_run["last_fetch"][collection_name] = (
                _serialize_seq_update(effective_last_fetch_int)
                if isinstance(effective_last_fetch_int, int) and effective_last_fetch_int > 0
                else None
            )
            demisto.debug(
                f"[fetch-incidents] Updated next_run for collection={collection_name}: "
                f"{next_run['last_fetch'][collection_name]}"
            )

    return next_run, incidents


def get_available_collections_command(client: Client, args: dict | None = None):
    """
    Returns list of available collections to context and War Room.

    :param client: GIB_TI_Feed client.
    """

    my_collections = client.get_available_collections_proxy_function()
    readable_output = tableToMarkdown(
        name="Available collections",
        t={"collections": my_collections},
        headers="collections",
    )
    return CommandResults(
        outputs_prefix="GIBTI.OtherInfo",
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

    def get_info_by_id_for_collection(client: Client, args: dict) -> list[CommandResults]:
        """
        This function returns additional information to context and War Room.

        :param client: GIB_TI_Feed client.
        :param args: arguments, provided by client.
        """
        results = []
        CommonHelpers.validate_collections(collection_name)
        feed, main_table_data, additional_tables, indicators, readable_output = BuilderCommandResponses(
            client=client, collection_name=collection_name, args=args
        ).build_feed()

        results.append(
            CommandResults(
                outputs_prefix="GIBTI.{}".format(PREFIXES.get(collection_name, "").replace(" ", "")),
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


def global_search_command(client: Client, args: dict) -> CommandResults:
    query = str(args.get("query"))
    raw_response = client.search_proxy_function(query=query)
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
            outputs_prefix="GIBTI.search.global",
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
            outputs_prefix="GIBTI.search.global",
            raw_response=raw_response,
            ignore_auto_extract=True,
            outputs=[],
            readable_output="Did not find anything for your query :(",
        )
    return results


def local_search_command(client: Client, args: dict) -> CommandResults:
    def _parse_optional_int(value: Any, arg_name: str) -> int | None:
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            try:
                return int(stripped)
            except ValueError as e:
                raise DemistoException(f"Invalid '{arg_name}' value: expected int, got {value!r}") from e
        raise DemistoException(f"Invalid '{arg_name}' type: expected int/str, got {type(value).__name__}")

    query = args.get("query")
    date_from = args.get("date_from")
    date_to = args.get("date_to")
    collection_name = str(args.get("collection_name"))
    include_raw_feed = argToBoolean(args.get("include_raw_feed", False))

    CommonHelpers.validate_collections(collection_name)

    requests_limit = _parse_optional_int(args.get("requests_limit"), "requests_limit") or 1
    page_size_limit = _parse_optional_int(args.get("page_size_limit"), "page_size_limit")
    filter_seq_update = _parse_optional_int(args.get("seq_update"), "seq_update")

    demisto.debug(
        "[local_search] Params: "
        f"collection={collection_name}, query={query!r}, date_from={date_from!r}, date_to={date_to!r}, "
        f"seq_update={filter_seq_update!r}, requests_limit={requests_limit}, page_size_limit={page_size_limit}, "
        f"include_raw_feed={include_raw_feed}"
    )

    date_from_parsed = CommonHelpers.date_parse(date=str(date_from), arg_name="date_from") if date_from is not None else None
    date_to_parsed = CommonHelpers.date_parse(date=str(date_to), arg_name="date_to") if date_to is not None else None

    if collection_name == "compromised/breached":
        portions = client.poller.create_search_generator(
            collection_name=collection_name,
            query=query,
            date_from=date_from_parsed,
            date_to=date_to_parsed,
            limit=page_size_limit,
        )
    else:
        update_kwargs: dict[str, Any] = {
            "collection_name": collection_name,
            "query": query,
            "limit": page_size_limit,
        }
        if filter_seq_update is not None:
            update_kwargs["sequpdate"] = filter_seq_update

        portions = client.poller.create_update_generator(**update_kwargs)

    mapping = MAPPING.get(collection_name, {})

    requests_count = 0
    result_list: list[dict[str, Any]] = []
    for portion in portions:
        sequpdate = getattr(portion, "sequpdate", None)
        new_parsed_json = portion.parse_portion(keys=mapping, as_json=False)
        for feed in new_parsed_json:
            name = feed.get("name")
            additional_info = f"Name: {name}" if name else None
            entry: dict[str, Any] = {
                "id": feed.get("id"),
                "additional_info": additional_info,
                "seqUpdate": sequpdate,
            }
            if include_raw_feed:
                entry["raw_feed"] = CommonHelpers.safe_json_one_line(feed)
            result_list.append(entry)
        requests_count += 1
        if requests_limit is not None and requests_count >= requests_limit:
            break

    return CommandResults(
        outputs_prefix="GIBTI.search.local",
        outputs_key_field="id",
        outputs=result_list,
        readable_output=tableToMarkdown(
            "Search results",
            t=result_list,
            headers=["id", "additional_info", "seqUpdate", "raw_feed"],
        ),
        ignore_auto_extract=True,
    )


class ReputationCommandProcessor:
    ALLOWED_PATHS: dict[str, list[str]] = {
        "file": ["ioc/common"],
        "domain": [
            "apt/threat",
            "apt/threat_actor",
            "attacks/deface",
            "hi/open_threats",
            "ioc/common",
        ],
        # "scoring",
        "ip": [
            "apt/threat",
            "apt/threat_actor",
            "attacks/deface",
            "hi/open_threats",
            "ioc/common",
        ],
    }
    SENSITIVE_TO_DATES_COLLECTIONS: dict[str, list[str]] = {
        "domain": [
            "attacks/deface",
            "hi/open_threats",
            "ioc/common",
        ],
    }
    DATES_MAPPING: dict[str, dict[str, dict[str, str]]] = {
        "domain": {
            "attacks/deface": {
                "date": "date",
            },
            "hi/open_threats": {
                "detected": "detected",
            },
            "ioc/common": {"dateLastSeen": "dateLastSeen"},
        }
    }
    RECENT_WINDOW = timedelta(days=365 * 3)
    DATE_FORMATS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ")
    RELIABILITY_BY_COLLECTION: dict[str, dict[str, Reliability]] = {
        "file": {
            "ioc/common": DBotScoreReliability.A,
        },
        "domain": {
            "apt/threat": DBotScoreReliability.A,
            "apt/threat_actor": DBotScoreReliability.A,
            "ioc/common": DBotScoreReliability.A,
            "attacks/deface": DBotScoreReliability.B,
            "hi/open_threats": DBotScoreReliability.B,
        },
        "ip": {
            "apt/threat": DBotScoreReliability.A,
            "apt/threat_actor": DBotScoreReliability.A,
            "ioc/common": DBotScoreReliability.A,
            "attacks/deface": DBotScoreReliability.B,
            "hi/open_threats": DBotScoreReliability.B,
        },
    }
    RULES: list[dict[str, Any]] = [
        # IOC common last 3 years -> BAD
        {"any_recent": [("ioc/common", "dateLastSeen")], "score": Common.DBotScore.BAD},
        # open threats / defaces last 3 years -> SUSPICIOUS
        {
            "any_recent": [("hi/open_threats", "detected"), ("attacks/deface", "date")],
            "score": Common.DBotScore.SUSPICIOUS,
        },
        # IOC Common >3 years or no date -> SUSPICIOUS (if records exist)
        {
            "ioc_stale_or_no_date": ("ioc/common", "dateLastSeen"),
            "score": Common.DBotScore.SUSPICIOUS,
        },
        # no findings -> NONE
        {"no_findings": True, "score": Common.DBotScore.NONE},
    ]

    GRAPH_MAPPING = {
        "ip": {
            "asn": "whoisSummary.asn",
            "country": "whoisSummary.country",
            "descr": "whoisSummary.descr",
            "isp": "whoisSummary.isp",
            "netname": "whoisSummary.netname",
            "phone": "whoisSummary.phone",
        }
    }

    def __init__(
        self,
        client: Client,
        args: dict,
        integration_reliability: Reliability | None = None,
    ) -> None:
        self.client = client
        self.args = args
        self.integration_reliability = integration_reliability

    def _extract_indicator(self, indicator_name: str, arg_keys: list[str]) -> str:
        for key in arg_keys:
            value = self.args.get(key)
            if value:
                return str(value)
        raise DemistoException(f"Argument '{indicator_name}' is required.")

    def _filter_allowed_paths(self, indicator_name: str, exclude: list[str]) -> list[str]:
        base_paths = self.ALLOWED_PATHS.get(indicator_name, [])
        if not exclude:
            return base_paths
        exclude_set = set(exclude)
        return [p for p in base_paths if p not in exclude_set]

    def _get_indicator_data(self, indicator_name: str, indicator_value: str, search_data):
        data_per_collections = {}
        search_data = self._get_search_data(indicator_value)
        allowed_paths = self.ALLOWED_PATHS.get(indicator_name, [])
        for path, _count in search_data:
            if path in allowed_paths:
                portions_data = IndicatorsHelper.collect_portions_for_indicator(
                    indicator_name=indicator_name,
                    indicator_value=indicator_value,
                    path=path,
                    poller=self.client.poller,
                    dates_mapping=self.DATES_MAPPING.get(indicator_name),
                    sensitive_collections=self.SENSITIVE_TO_DATES_COLLECTIONS.get(indicator_name, []),
                )
                data_per_collections.update({path: portions_data})

            if indicator_name == "ip":
                ip_data = IndicatorsHelper.build_ip_enrichment(
                    poller=self.client.poller,
                    indicator_value=indicator_value,
                    mapping=self.GRAPH_MAPPING.get(indicator_name, {}),
                )
                data_per_collections.update(ip_data)
        return data_per_collections

    def _get_search_data(self, indicator_value):
        search = self.client.poller.global_search(indicator_value)
        finding = []
        for found in search:
            apiPath = found.get("apiPath")
            count = found.get("count")
            finding.append((apiPath, count))
        return finding

    def _parse_date(self, s):
        if not s:
            return None
        for fmt in self.DATE_FORMATS:
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    def _any_recent(self, items, date_key, now):
        for it in items or []:
            dt = self._parse_date((it or {}).get(date_key))
            if dt and (now - dt) <= self.RECENT_WINDOW:
                return True
        return False

    def _any_present(self, items, date_key):
        return any((it or {}).get(date_key) for it in (items or []))

    def _get_score(self, indicator_name, indicator_data):
        if indicator_name == "file":
            # if at least one element is found in ioc/common -> BAD, otherwise NONE
            score = Common.DBotScore.BAD if indicator_data.get("ioc/common") else Common.DBotScore.NONE

        elif indicator_name == "domain":
            # Rules:
            # - IOC common last 3 years -> BAD
            # - open threats / defaces last 3 years -> SUSPICIOUS
            # - IOC Common > 3 years or no date -> SUSPICIOUS (if there are records)
            # - no findings -> NONE
            now = datetime.utcnow()
            score = None

            for rule in self.RULES:
                any_recent = rule.get("any_recent")
                if any_recent and any(self._any_recent(indicator_data.get(coll), key, now) for coll, key in any_recent):
                    score = rule["score"]
                    break

                if rule.get("ioc_stale_or_no_date"):
                    coll, key = rule["ioc_stale_or_no_date"]
                    items = indicator_data.get(coll) or []
                    if items and (not self._any_present(items, key) or not self._any_recent(items, key, now)):
                        score = rule["score"]
                        break

                if rule.get("no_findings"):
                    has_any = any(indicator_data.get(c) for c in ("attacks/deface", "hi/open_threats", "ioc/common"))
                    if not has_any:
                        score = rule["score"]
                        break

            if score is None:
                score = Common.DBotScore.NONE

        elif indicator_name == "ip":
            # riskScore mapping to DBotScore:
            # 0-49 -> GOOD, 50-84 -> SUSPICIOUS, 85-100 -> BAD, None/out-of-range -> NONE
            scoring = indicator_data.get("scoring", {}).get("score")
            score = IndicatorsHelper.dbot_from_score(scoring)

        else:
            score = Common.DBotScore.NONE

        return score

    @staticmethod
    def _pick_best_reliability(reliabilities: list[Reliability]) -> Reliability | None:
        """
        Pick the most trusted reliability deterministically.

        Current policy:
        - Prefer A over B
        - Otherwise None
        """
        # Use a set to avoid order-dependence and make membership checks explicit.
        rset = set(reliabilities)
        if DBotScoreReliability.A in rset:
            return DBotScoreReliability.A
        if DBotScoreReliability.B in rset:
            return DBotScoreReliability.B
        return None

    def _get_reliability(self, indicator_name: str, indicator_data: dict[str, Any]) -> Reliability | None:
        if self.integration_reliability:
            return self.integration_reliability
        if indicator_name == "file":
            # if found in ioc/common, always A - Completely reliable : ‘a’:DBotScoreReliability.A
            reliability = DBotScoreReliability.A if indicator_data.get("ioc/common") else None
        elif indicator_name == "domain":
            # Summary:
            # - A: any match in apt/* or ioc/common
            # - B: any match in attacks/deface or hi/open_threats
            #
            # Detailed mapping:
            # - nation state (apt/threat, apt/threat_actor) -> A - Completely reliable
            # - other IOC common (ioc/common) -> A - Completely reliable
            # - defaces (attacks/deface) -> B - Usually reliable
            # - open threats (hi/open_threats) -> B - Usually reliable
            matched_reliabilities = [
                self.RELIABILITY_BY_COLLECTION.get(indicator_name, {}).get(coll)
                for coll in self.ALLOWED_PATHS.get(indicator_name, [])
                if indicator_data.get(coll)
            ]
            reliability = self._pick_best_reliability([r for r in matched_reliabilities if r])
        elif indicator_name == "ip":
            # Summary:
            # - A: any match in apt/* or ioc/common
            # - B: any match in attacks/deface or hi/open_threats
            #
            # Detailed mapping:
            # - nation state (apt/threat, apt/threat_actor) -> A - Completely reliable
            # - other IOC common (ioc/common) -> A - Completely reliable
            # - defaces (attacks/deface) -> B - Usually reliable
            # - open threats (hi/open_threats) -> B - Usually reliable
            matched_reliabilities = [
                self.RELIABILITY_BY_COLLECTION.get(indicator_name, {}).get(coll)
                for coll in self.ALLOWED_PATHS.get(indicator_name, [])
                if indicator_data.get(coll)
            ]
            reliability = self._pick_best_reliability([r for r in matched_reliabilities if r])
        else:
            reliability = None
        return reliability

    def _normalize_graph_ip(self, graph_ip_info: Any) -> dict[str, Any]:
        """Normalize graph_ip response to a single dict."""
        if isinstance(graph_ip_info, list):
            if graph_ip_info:
                graph_ip_info = graph_ip_info[0] or {}
            else:
                graph_ip_info = {}
        if not isinstance(graph_ip_info, dict):
            return {}
        return graph_ip_info

    def _build_ip_enrichment_kwargs(self, graph_ip_info: dict[str, Any]) -> dict[str, Any]:
        """Build kwargs for Common.IP from graph_ip whois data."""
        return {
            "asn": graph_ip_info.get("asn"),
            "as_owner": graph_ip_info.get("isp"),
            "geo_country": graph_ip_info.get("country"),
            "geo_description": graph_ip_info.get("descr") or graph_ip_info.get("netname"),
            "registrar_abuse_phone": graph_ip_info.get("phone"),
            "organization_name": graph_ip_info.get("netname"),
            "description": graph_ip_info.get("descr") or graph_ip_info.get("netname"),
        }

    @staticmethod
    def _build_readable_output(
        title: str,
        indicator_value: str,
        score_value: Any,
        reliability: Any = None,
        numerical_score: Any = None,
    ) -> str:
        table_data = {
            "Indicator": indicator_value,
            "Score": {v: k for k, v in COMMON_SCORE_MAP.items()}.get(score_value, score_value),
        }
        if reliability is not None:
            table_data["Reliability"] = reliability
        if numerical_score is not None:
            table_data["Numerical Score"] = numerical_score

        return tableToMarkdown(
            title,
            table_data,
            removeNull=True,
        )

    def run(
        self,
        indicator_name: str,
        indicator_type,
        arg_keys: list[str] | None = None,
    ) -> CommandResults:
        arg_keys = arg_keys or ["value", indicator_name]
        indicator_value = self._extract_indicator(indicator_name, arg_keys)
        search_data = self._get_search_data(indicator_value=indicator_value)
        indicator_data = self._get_indicator_data(indicator_name, indicator_value, search_data)
        score = self._get_score(indicator_name, indicator_data)
        reliability = self._get_reliability(indicator_name, indicator_data)
        graph_ip_info = indicator_data.get("graph_ip") or {}
        graph_ip_info = self._normalize_graph_ip(graph_ip_info)

        d_bot_score = Common.DBotScore(
            indicator=indicator_value,
            indicator_type=indicator_type,
            integration_name="GroupIBTI",
            score=score,
            reliability=reliability,
        )
        indicator_obj: Any = None
        if indicator_name == "ip":
            indicator_obj = Common.IP(
                ip=indicator_value,
                dbot_score=d_bot_score,
                **self._build_ip_enrichment_kwargs(graph_ip_info),
            )
        elif indicator_name == "domain":
            indicator_obj = Common.Domain(domain=indicator_value, dbot_score=d_bot_score)
        elif indicator_name == "file":
            # hash type is not specified; pass as md5 for DBot correlation
            indicator_obj = Common.File(md5=indicator_value, dbot_score=d_bot_score)

        readable_output = self._build_readable_output(
            title=f"Group-IB reputation for {indicator_value}",
            indicator_value=indicator_value,
            score_value=score,
            reliability=reliability,
        )

        return CommandResults(
            readable_output=readable_output,
            indicator=indicator_obj,
            raw_response={
                "indicator": indicator_value,
                "score": score,
                "reliability": str(reliability),
            },
        )


def gibti_ip_scoring_command(client: Client, args: dict) -> CommandResults:
    indicator_value = args.get("ip")
    if not indicator_value:
        raise DemistoException("Argument 'ip' is required.")

    ip_data = IndicatorsHelper.build_ip_enrichment(
        poller=client.poller,
        indicator_value=indicator_value,
        mapping={},
    )
    risk_score = ip_data.get("scoring", {}).get("score")
    dbot_score_value = IndicatorsHelper.dbot_from_score(risk_score)

    d_bot_score = Common.DBotScore(
        indicator=indicator_value,
        indicator_type=DBotScoreType.IP,
        integration_name="GroupIBTI",
        score=dbot_score_value,
        reliability=None,
    )

    indicator_obj = Common.IP(
        ip=indicator_value,
        dbot_score=d_bot_score,
    )

    readable_output = ReputationCommandProcessor._build_readable_output(
        title=f"Group-IB scoring for {indicator_value}",
        indicator_value=indicator_value,
        score_value=dbot_score_value,
        numerical_score=risk_score,
    )

    return CommandResults(
        readable_output=readable_output,
        indicator=indicator_obj,
        raw_response={
            "indicator": indicator_value,
            "score": dbot_score_value,
            "riskScore": risk_score,
        },
    )


class ReputationCommands:
    @staticmethod
    def file(
        client: Client,
        args: dict,
        integration_reliability: Reliability | None = None,
    ) -> CommandResults:
        return ReputationCommandProcessor(client, args, integration_reliability).run(
            indicator_name="file", indicator_type=DBotScoreType.FILE
        )

    @staticmethod
    def domain(
        client: Client,
        args: dict,
        integration_reliability: Reliability | None = None,
    ) -> CommandResults:
        return ReputationCommandProcessor(client, args, integration_reliability).run(
            indicator_name="domain", indicator_type=DBotScoreType.DOMAIN
        )

    @staticmethod
    def ip(
        client: Client,
        args: dict,
        integration_reliability: Reliability | None = None,
    ) -> CommandResults:
        return ReputationCommandProcessor(client, args, integration_reliability).run(
            indicator_name="ip", indicator_type=DBotScoreType.IP
        )


class ReputationCommandPolicy:
    _SUPPORTED_REPUTATION_COMMANDS: frozenset[str] = frozenset({"ip", "domain", "file"})

    def __init__(self, enabled_commands: set[str]) -> None:
        self._enabled_commands = enabled_commands

    @classmethod
    def from_params(cls, params: dict) -> "ReputationCommandPolicy":
        """
        Policy precedence:
        - Allow-list only: only explicitly enabled commands can run.
        - Fail-safe default: if the param is missing or empty -> no reputation commands run.
        """

        raw_enabled = params.get("enabled_reputation_commands") or []
        enabled = {str(x).strip().lower() for x in argToList(raw_enabled) if str(x).strip()}
        enabled &= set(cls._SUPPORTED_REPUTATION_COMMANDS)
        return cls(enabled_commands=enabled)

    def is_enabled(self, command: str) -> bool:
        return command in self._enabled_commands

    @staticmethod
    def build_not_enabled_result(command: str) -> CommandResults:
        return CommandResults(
            readable_output=(
                f"Reputation command '{command}' is not enabled in the integration instance settings. "
                "No enrichment was performed."
            ),
            raw_response={"command": command, "enabled": False},
        )


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    incident_collections = None
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
        result: Any = None

        incident_collections = params.get("incident_collections", [])
        incidents_first_fetch = params.get("first_fetch", "3 days").strip()
        requests_count = int(params.get("max_fetch", 3))

        combolist = params.get("combolist", False)
        unique = params.get("unique", False)
        enable_probable_corporate_access = params.get("enable_probable_corporate_access", False)
        limit_param = params.get("limit", 100)
        limit = int(limit_param)
        integration_reliability_param = params.get("integration_reliability")
        disable_reliability_override = params.get("disable_integration_reliability_override", False)
        integration_reliability = (
            None if disable_reliability_override else IndicatorsHelper.parse_source_reliability(integration_reliability_param)
        )
        reputation_policy = ReputationCommandPolicy.from_params(params)

        args = demisto.args()
        raw_command = demisto.command()
        command_aliases = {
            "gibtia-get-compromised-account-info": "gibti-get-compromised-account-info",
            "gibtia-get-compromised-card-group-info": "gibti-get-compromised-card-group-info",
            "gibtia-get-compromised-mule-info": "gibti-get-compromised-mule-info",
            "gibtia-get-compromised-breached-info": "gibti-get-compromised-breached-info",
            "gibtia-get-phishing-kit-info": "gibti-get-phishing-kit-info",
            "gibtia-get-phishing-group-info": "gibti-get-phishing-group-info",
            "gibtia-get-osi-git-leak-info": "gibti-get-osi-git-leak-info",
            "gibtia-get-osi-public-leak-info": "gibti-get-osi-public-leak-info",
            "gibtia-get-osi-vulnerability-info": "gibti-get-osi-vulnerability-info",
            "gibtia-get-attacks-ddos-info": "gibti-get-attacks-ddos-info",
            "gibtia-get-attacks-deface-info": "gibti-get-attacks-deface-info",
            "gibtia-get-threat-info": "gibti-get-threat-info",
            "gibtia-get-threat-actor-info": "gibti-get-threat-actor-info",
            "gibtia-get-suspicious-ip-tor-node-info": "gibti-get-suspicious-ip-tor-node-info",
            "gibtia-get-suspicious-ip-open-proxy-info": "gibti-get-suspicious-ip-open-proxy-info",
            "gibtia-get-suspicious-ip-socks-proxy-info": "gibti-get-suspicious-ip-socks-proxy-info",
            "gibtia-get-suspicious-ip-vpn-info": "gibti-get-suspicious-ip-vpn-info",
            "gibtia-get-suspicious-ip-scanner-info": "gibti-get-suspicious-ip-scanner-info",
            "gibtia-get-malware-cnc-info": "gibti-get-malware-cnc-info",
            "gibtia-get-malware-malware-info": "gibti-get-malware-malware-info",
            "gibtia-get-available-collections": "gibti-get-available-collections",
            "gibtia-global-search": "gibti-global-search",
            "gibtia-local-search": "gibti-local-search",
        }
        command = command_aliases.get(raw_command, raw_command)
        demisto.debug(f"Command being called is {raw_command}, mapped to {command}")
        demisto.debug(
            "[main] Parsed params: "
            f"url={base_url}, proxy={proxy}, verify={verify_certificate}, "
            f"hunting_rules={hunting_rules}, first_fetch={incidents_first_fetch}, max_fetch={requests_count}, "
            f"collections={incident_collections}, combolist={combolist}, unique={unique}, "
            f"enable_probable_corporate_access={enable_probable_corporate_access}, limit={limit}"
        )

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy,
            headers={"Accept": "*/*"},
            limit=limit,
        )
        demisto.info("Client created successfully")

        deprecated_commands = [
            "gibtia-get-compromised-card-info",
            "gibtia-get-compromised-imei-info",
            "gibtia-get-malware-targeted-malware-info",
            "gibtia-get-phishing-info",
        ]
        if raw_command in deprecated_commands or command in deprecated_commands:
            raise Exception(f"{command} deprecated")

        if hunting_rules is True:
            list_hunting_rules_collections = client.poller.get_hunting_rules_collections()

            for collection in incident_collections:
                if collection not in list_hunting_rules_collections:
                    raise Exception(f"Collection {collection} Does't support hunting rules")
            hunting_rules = 1

        info_comands = {
            # new prefix
            "gibti-get-compromised-account-info": "compromised/account_group",
            "gibti-get-compromised-card-group-info": "compromised/bank_card_group",
            "gibti-get-compromised-mule-info": "compromised/mule",
            "gibti-get-compromised-breached-info": "compromised/breached",
            "gibti-get-phishing-kit-info": "attacks/phishing_kit",
            "gibti-get-phishing-group-info": "attacks/phishing_group",
            "gibti-get-osi-git-leak-info": "osi/git_repository",
            "gibti-get-osi-public-leak-info": "osi/public_leak",
            "gibti-get-osi-vulnerability-info": "osi/vulnerability",
            "gibti-get-attacks-ddos-info": "attacks/ddos",
            "gibti-get-attacks-deface-info": "attacks/deface",
            "gibti-get-threat-info": "threat",
            "gibti-get-threat-actor-info": "threat_actor",
            "gibti-get-suspicious-ip-tor-node-info": "suspicious_ip/tor_node",
            "gibti-get-suspicious-ip-open-proxy-info": "suspicious_ip/open_proxy",
            "gibti-get-suspicious-ip-socks-proxy-info": "suspicious_ip/socks_proxy",
            "gibti-get-suspicious-ip-vpn-info": "suspicious_ip/vpn",
            "gibti-get-suspicious-ip-scanner-info": "suspicious_ip/scanner",
            "gibti-get-malware-cnc-info": "malware/cnc",
            "gibti-get-malware-malware-info": "malware/malware",
        }

        other_commands = {
            # new prefix
            "gibti-get-available-collections": get_available_collections_command,
            "gibti-global-search": global_search_command,
            "gibti-local-search": local_search_command,
            "gibti-ip-scoring": gibti_ip_scoring_command,
        }
        reputation_commands = {
            "file": ReputationCommands.file,
            "domain": ReputationCommands.domain,
            "ip": ReputationCommands.ip,
        }

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif command == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents_command(
                client=client,
                last_run=last_run,
                first_fetch_time=incidents_first_fetch,
                incident_collections=incident_collections,
                max_requests=requests_count,
                hunting_rules=hunting_rules,
                combolist=combolist,
                unique=unique,
                enable_probable_corporate_access=enable_probable_corporate_access,
            )
            demisto.debug(f"[fetch-incidents] Incidents created this run: count={len(incidents)}")
            demisto.debug(f"next_run: {next_run}, last_run: {last_run}")
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            incident_collections = None
            if command in info_comands:
                endpoint = info_comands[command]
                result = get_info_by_id_command(endpoint)(client, args)
            elif command in reputation_commands:
                if not reputation_policy.is_enabled(command):
                    result = ReputationCommandPolicy.build_not_enabled_result(command)
                else:
                    result = reputation_commands[command](client, args, integration_reliability)  # type: ignore
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
