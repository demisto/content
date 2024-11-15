import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
from cyberintegrations import TIPoller
from traceback import format_exc

# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)

""" CONSTANTS """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


COMMON_MAPPING = {
    "compromised/account_group": {
        "types": {
            "event_url": "URL",
            "event_domain": "Domain",
            "events_ipv4_ip": "IP",
            "service_url":"URL",
        },
        "add_fields_types": {
            "event_url": {
                "id": "gibid",
            },
            "event_domain": {
                "id": "gibid",
            },
            "events_ipv4_ip": {
                "id": "gibid",
                "asn": "asn",
                "country_name": "geocountry",
                "region": "geolocation",
            },
            "service_url":{
                "id": "gibid",
            }
        },
        "parser_mapping": {
            "id": "id",
            "event_url": "events.cnc.url",
            "event_domain": "events.cnc.domain",
            "events_ipv4_ip": "events.cnc.ipv4.ip",
            "asn": "events.client.ipv4.asn",
            "country_name": "events.client.ipv4.countryName",
            "region": "events.client.ipv4.region",
            "service_url":"service.url",
        },
    },
    "compromised/bank_card_group": {
        "types": {
            "cnc_url": "URL",
            "cnc_domain": "Domain",
            "cnc_ipv4_ip": "IP",
        },
        "add_fields_types": {
            "cnc_url": {
                "id": "gibid",
            },
            "cnc_domain":{
                "id": "gibid",
            },
            "cnc_ipv4_ip": {
                "id": "gibid",
                "cnc_ipv4_asn": "asn",
                "cnc_ipv4_country_name": "geocountry",
                "cnc_ipv4_region": "geolocation",
            },
        },
        "parser_mapping": {
            "id": "id",
            "cnc_url": "events.cnc.url",
            "cnc_domain": "events.cnc.domain",
            "cnc_ipv4_ip": "events.cnc.ipv4.ip",
            "cnc_ipv4_asn": "events.cnc.ipv4.asn",
            "cnc_ipv4_country_name": "events.cnc.ipv4.countryName",
            "cnc_ipv4_region": "events.cnc.ipv4.region",
        },
    },
    "compromised/mule": {
        "types": {
            "account": "GIB Compromised Mule",
            "cnc_url": "URL",
            "cnc_domain": "Domain",
            "cnc_ipv4_ip": "IP",
        },
        "add_fields_types": {
            "account": {
                "id": "gibid",
                "date_add": "creationdate",
                "source_type": "source",
                "malware_name": "gibmalwarename",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
            "cnc_url": {
                "id": "gibid",
                "malware_name": "gibmalwarename",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
            "cnc_domain": {
                "id": "gibid",
                "malware_name": "gibmalwarename",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
            "cnc_ipv4_ip": {
                "id": "gibid",
                "cnc_ipv4_asn": "asn",
                "cnc_ipv4_country_name": "geocountry",
                "cnc_ipv4_region": "geolocation",
                "malware_name": "gibmalwarename",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
        },
        "parser_mapping": {
            "id": "id",
            "account": "account",
            "date_add": "dateAdd",
            "source_type": "sourceType",
            "malware_name": "malware.name",
            "threat_actor_name": "threatActor.name",
            "threat_actor_is_apt": "threatActor.isAPT",
            "threat_actor_id": "threatActor.id",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "cnc_url": "cnc.url",
            "cnc_domain": "cnc.domain",
            "cnc_ipv4_ip": "cnc.ipv4.ip",
            "cnc_ipv4_asn": "cnc.ipv4.asn",
            "cnc_ipv4_country_name": "cnc.ipv4.countryName",
            "cnc_ipv4_region": "cnc.ipv4.region",
        },
    },
    "attacks/ddos": {
        "types": {
            "cnc_url": "URL",
            "cnc_domain": "Domain",
            "cnc_ipv4_ip": "IP",
            "target_ipv4_ip": "GIB Victim IP",
        },
        "add_fields_types": {
            "cnc_url": {
                "id": "gibid",
                "malware_name": "gibmalwarename",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "date_begin": "firstseenbysource",
                "date_end": "lastseenbysource",
            },
            "cnc_domain": {
                "id": "gibid",
                "malware_name": "gibmalwarename",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "date_begin": "firstseenbysource",
                "date_end": "lastseenbysource",
            },
            "cnc_ipv4_ip": {
                "id": "gibid",
                "cnc_ipv4_asn": "asn",
                "cnc_ipv4_country_name": "geocountry",
                "cnc_ipv4_region": "geolocation",
                "malware_name": "gibmalwarename",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "date_begin": "firstseenbysource",
                "date_end": "lastseenbysource",
            },
            "target_ipv4_ip": {
                "id": "gibid",
                "target_ipv4_asn": "asn",
                "target_ipv4_country_name": "geocountry",
                "target_ipv4_region": "geolocation",
                "malware_name": "malware.name",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "date_begin": "firstseenbysource",
                "date_end": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
        },
        "parser_mapping": {
            "id": "id",
            "malware_name": "malware.name",
            "threat_actor_name": "threatActor.name",
            "threat_actor_is_apt": "threatActor.isAPT",
            "threat_actor_id": "threatActor.id",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "date_begin": "dateBegin",
            "date_end": "dateEnd",
            "cnc_url": "cnc.url",
            "cnc_domain": "cnc.domain",
            "cnc_ipv4_ip": "cnc.ipv4.ip",
            "cnc_ipv4_asn": "cnc.ipv4.asn",
            "cnc_ipv4_country_name": "cnc.ipv4.countryName",
            "cnc_ipv4_region": "cnc.ipv4.region",
            "target_ipv4_ip": "target.ipv4.ip",
            "target_ipv4_asn": "target.ipv4.asn",
            "target_ipv4_country_name": "target.ipv4.countryName",
            "target_ipv4_region": "target.ipv4.region",
        },
    },
    "attacks/deface": {
        "types": {"url": "URL", "target_domain": "Domain", "target_ip_ip": "IP"},
        "add_fields_types": {
            "url": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
            "target_domain": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
            "target_ip_ip": {
                "id": "gibid",
                "target_ip_asn": "asn",
                "target_ip_country_name": "geocountry",
                "target_ip_region": "geolocation",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
        },
        "parser_mapping": {
            "id": "id",
            "url": "url",
            "target_domain": "targetDomain",
            "target_ip_ip": "targetIp.ip",
            "target_ip_asn": "targetIp.asn",
            "target_ip_country_name": "targetIp.countryName",
            "target_ip_region": "targetIp.region",
            "threat_actor_name": "threatActor.name",
            "threat_actor_is_apt": "threatActor.isAPT",
            "threat_actor_id": "threatActor.id",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    },
    "attacks/phishing_kit": {
        "types": {
            "emails": "Email",
        },
        "add_fields_types": {
            "emails": {
                "id": "gibid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            }
        },
        "parser_mapping": {
            "id": "id",
            "emails": "emails",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    },
    "attacks/phishing_group": {
        "types": {
            "url": "URL",
            "phishing_domain_domain": "Domain",
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "url": {
                "id": "gibid",
            },
            "phishing_domain_domain": {
                "id": "gibid",
                "phishing_domain_registrar": "registrarname",
            },
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_country_name": "geocountry",
            },
        },
        "parser_mapping": {
            "id": "id",
            "url": "phishing.url",
            "phishing_domain_registrar": "domainInfo.registrar",
            "ipv4_ip": "phishing.ip.ip",
            "ipv4_country_mame": "phishing.ip.countryName",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    },
    "apt/threat": {
        "types": {
            "indicators_params_ipv4": "IP",
            "indicators_params_domain": "Domain",
            "indicators_params_url": "URL",
            "indicators_params_hashes_md5": "File",
        },
        "add_fields_types": {
            "indicators_params_ipv4": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "indicators_date_first_seen": "firstseenbysource",
                "indicators_date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "malware_list_names": "gibmalwarename",
            },
            "indicators_params_domain": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "indicators_date_first_seen": "firstseenbysource",
                "indicators_date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "malware_list_names": "gibmalwarename",
            },
            "indicators_params_url": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "indicators_date_first_seen": "firstseenbysource",
                "indicators_date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "malware_list_names": "gibmalwarename",
            },
            "indicators_params_hashes_md5": {
                "id": "gibid",
                "indicators_params_name": "gibfilename",
                "indicators_params_hashes_md5": "md5",
                "indicators_params_hashes_sha1": "sha1",
                "indicators_params_hashes_sha256": "sha256",
                "indicators_params_size": "size",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "indicators_date_first_seen": "firstseenbysource",
                "indicators_date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "malware_list_names": "gibmalwarename",
            },
        },
        "parser_mapping": {
            "id": "id",
            "indicators_params_ipv4": "indicators.params.ipv4",
            "indicators_params_domain": "indicators.params.domain",
            "indicators_params_url": "indicators.params.url",
            "indicators_params_hashes_md5": "indicators.params.hashes.md5",
            "threat_actor_name": "threatActor.name",
            "threat_actor_is_apt": "threatActor.isAPT",
            "threat_actor_id": "threatActor.id",
            "indicators_date_first_seen": "indicators.dateFirstSeen",
            "indicators_date_last_seen": "indicators.dateLastSeen",
            "indicators_params_name": "indicators.params.name",
            "indicators_params_hashes_sha1": "indicators.params.hashes.sha1",
            "indicators_params_hashes_sha256": "indicators.params.hashes.sha256",
            "indicators_params_size": "indicators.params.size",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "malware_list_names": "malwareList.name",
        },
    },
    "hi/threat": {
        "types": {
            "indicators_params_ipv4": "IP",
            "indicators_params_domain": "Domain",
            "indicators_params_url": "URL",
            "indicators_params_hashes_md5": "File",
        },
        "add_fields_types": {
            "indicators_params_ipv4": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "indicators_date_first_seen": "firstseenbysource",
                "indicators_date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "malware_list_names": "gibmalwarename",
            },
            "indicators_params_domain": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "indicators_date_first_seen": "firstseenbysource",
                "indicators_date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "malware_list_names": "gibmalwarename",
            },
            "indicators_params_url": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "indicators_date_first_seen": "firstseenbysource",
                "indicators_date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "malware_list_names": "gibmalwarename",
            },
            "indicators_params_hashes_md5": {
                "id": "gibid",
                "indicators_params_name": "gibfilename",
                "indicators_params_hashes_md5": "md5",
                "indicators_params_hashes_sha1": "sha1",
                "indicators_params_hashes_sha256": "sha256",
                "indicators_params_size": "size",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "indicators_date_first_seen": "firstseenbysource",
                "indicators_date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "malware_list_names": "gibmalwarename",
            },
        },
        "parser_mapping": {
            "id": "id",
            "indicators_params_ipv4": "indicators.params.ipv4",
            "indicators_params_domain": "indicators.params.domain",
            "indicators_params_url": "indicators.params.url",
            "indicators_params_hashes_md5": "indicators.params.hashes.md5",
            "threat_actor_name": "threatActor.name",
            "threat_actor_is_apt": "threatActor.isAPT",
            "threat_actor_id": "threatActor.id",
            "indicators_date_first_seen": "indicators.dateFirstSeen",
            "indicators_date_last_seen": "indicators.dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "indicators_params_name": "indicators.params.name",
            "indicators_params_hashes_sha1": "indicators.params.hashes.sha1",
            "indicators_params_hashes_sha256": "indicators.params.hashes.sha256",
            "indicators_params_size": "indicators.params.size",
            "malware_list_names": "malwareList.name",
        },
    },
    "suspicious_ip/tor_node": {
        "types": {
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_mame": "geocountry",
                "ipv4_region": "geolocation",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            }
        },
        "parser_mapping": {
            "id": "id",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_mame": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    },
    "suspicious_ip/open_proxy": {
        "types": {
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_mame": "geocountry",
                "ipv4_region": "geolocation",
                "port": "gibproxyport",
                "anonymous": "gibproxyanonymous",
                "source": "source",
                "date_first_seen": "firstseenbysource",
                "date_detected": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            }
        },
        "parser_mapping": {
            "id": "id",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_mame": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "port": "port",
            "anonymous": "anonymous",
            "source": "source",
            "date_first_seen": "dateFirstSeen",
            "date_detected": "dateDetected",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    },
    "suspicious_ip/socks_proxy": {
        "types": {
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_mame": "geocountry",
                "ipv4_region": "geolocation",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            }
        },
        "parser_mapping": {
            "id": "id",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_mame": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    },
    "suspicious_ip/vpn": {
        "types": {
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_mame": "geocountry",
                "ipv4_region": "geolocation",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            }
        },
        "parser_mapping": {
            "id": "id",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_mame": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    },
    "suspicious_ip/scanner": {
        "types": {
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_countr_mame": "geocountry",
                "ipv4_region": "geolocation",
            },
        },
        "parser_mapping": {
            "id": "id",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
        },
    },
    "malware/cnc": {
        "types": {
            "url": "URL",
            "domain": "Domain",
            "ipv4_ip": "IP",
        },
        "add_fields_types": {
            "url": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "date_detected": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_list_names": "gibmalwarename",
            },
            "domain": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "date_detected": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_list_names": "gibmalwarename",
            },
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_mame": "geocountry",
                "ipv4_region": "geolocation",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "date_detected": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_list_names": "gibmalwarename",
            },
        },
        "parser_mapping": {
            "id": "id",
            "url": "url",
            "domain": "domain",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_mame": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "threat_actor_name": "threatActor.name",
            "threat_actor_is_apt": "threatActor.isAPT",
            "threat_actor_id": "threatActor.id",
            "date_detected": "dateDetected",
            "date_last_seen": "dateLastSeen",
            "malware_list_names": "malwareList.name",
        },
    },
    "osi/vulnerability": {
        "types": {
            "id": "CVE",
        },
        "add_fields_types": {
            "id": {
                "id": "gibid",
                "cvss_score": "cvss",
                "cvss_vector": "gibcvssvector",
                "software_mixed": "gibsoftwaremixed",
                "description": "cvedescription",
                "date_modified": "cvemodified",
                "date_published": "published",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            }
        },
        "markdowns": {
            "software_mixed": (
                "| Software Name | Software Type | Software Version |\n"
                "| ------------- | ------------- | ---------------- |\n"
            )
        },
        "parser_mapping": {
            "id": "id",
            "cvss_score": "cvss.score",
            "cvss_vector": "cvss.vector",
            "software_mixed": {
                "names": "softwareMixed.softwareName",
                "types": "softwareMixed.softwareType",
                "versions": "softwareMixed.softwareVersion",
            },
            "description": "description",
            "date_modified": "dateModified",
            "date_published": "datePublished",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    },
    "osi/git_repository": {
        "types": {
            "contributors_emails": "Email",
            "hash": "GIB Hash",
        },
        "add_fields_types": {
            "contributors_emails": {
                "id": "gibid",
            },
            "hash": {
                "id": "gibid",
            },
        },
        "parser_mapping": {
            "id": "id",
            "hash": "files.revisions.hash",
            "contributors_emails": "contributors.authorEmail",
        },
    },
    "ioc/common": {
        "types": {
            "url": "URL",
            "domain": "Domain",
            "ip": "IP",
        },
        "add_fields_types": {
            "url": {
                "id": "gibid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
            },
            "domain": {
                "id": "gibid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
            },
            "ip": {
                "id": "gibid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
            },
        },
        "parser_mapping": {
            "id": "id",
            "url": "url",
            "domain": "domain",
            "ip": "ip",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
        },
    },
}

COLLECTIONS_THAT_ARE_REQUIRED_HUNTING_RULES = ["osi/git_repository", "osi/public_leak", "compromised/breached"]
class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

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


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    :param client: GIB_TI&A_Feed client
    :return: 'ok' if test passed, anything else will fail the test.
    """
    generator = client.poller.create_update_generator(
        collection_name="compromised/mule", limit=10
    )
    generator.__next__()
    return "ok"


""" Support functions """


class IndicatorBuilding:
    fields_list_for_parse = [
        "creationdate",
        "firstseenbysource",
        "lastseenbysource",
        "gibdatecompromised",
    ]

    def __init__(
        self,
        parsed_json: list[dict],
        collection_name: str,
        common_fields: dict,
        collection_mapping: dict,
        limit: int | None = None,
        build_for_comand: bool = False,
    ) -> None:
        self.parsed_json = parsed_json
        self.collection_name = collection_name
        self.common_fields = common_fields
        self.tags = common_fields.pop("tags", [])
        self.limit = limit
        self.collection_mapping = collection_mapping
        self.build_for_comand = build_for_comand

    @staticmethod
    def clean_data(data):
        def clean_list(lst):
            """Removes None, empty rows and empty lists from a list and unpacks nested lists."""
            cleaned = []
            for item in lst:
                if isinstance(item, list):
                    cleaned.extend(clean_list(item))
                elif item not in (None, "", []):
                    cleaned.append(item)
            return cleaned

        cleaned_data = []

        for item in data:
            cleaned_item = {}
            for key, value in item.items():
                if isinstance(value, list):
                    cleaned_item[key] = clean_list(value)
                else:
                    cleaned_item[key] = value
            cleaned_data.append(cleaned_item)

        return cleaned_data

    @staticmethod
    def invert_dict(data_dict: dict):
        return {v: k for k, v in data_dict.items()}

    @staticmethod
    def get_key_by_value(data_dict: dict, target_value: str):
        inverted_dict = IndicatorBuilding.invert_dict(data_dict)
        return inverted_dict.get(target_value)

    @staticmethod
    def get_human_readable_feed(
        indicators: list, type_: str, collection_name: str
    ) -> str:

        headers = ["value", "type"]

        collection_data = COMMON_MAPPING.get(collection_name)
        initial_type = IndicatorBuilding.get_key_by_value(collection_data["types"], type_)  # type: ignore
        additional_headers = collection_data["add_fields_types"].get(initial_type)  # type: ignore
        headers.extend(additional_headers.values())

        return tableToMarkdown(
            f"{type_} indicators", indicators, removeNull=True, headers=headers
        )

    @staticmethod
    def transform_list_to_str(data: list[dict]) -> list[dict]:
        def process_item(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(value, list):
                        item[key] = ", ".join(str(process_item(v)) for v in value)
                    else:
                        item[key] = process_item(value)
            return item

        return [process_item(item) for item in data]

    @staticmethod
    def sorting_indicators(
        indicators: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        sorted_indicators: dict[str, list[dict[str, Any]]] = {}

        for indicator in indicators:
            raw_json = indicator.get("rawJSON", {})
            indicator_type = raw_json.get("type")

            if indicator_type == "CVE":
                raw_json.pop("gibsoftwaremixed", None)

            sorted_indicators.setdefault(indicator_type, []).append(raw_json)

        return sorted_indicators

    def build_indicator_value_for_software_mixed(self, feed: dict) -> str:
        markdowns = self.collection_mapping.get("markdowns", {})
        software_mixed_data = feed.get("software_mixed", {})

        rows = markdowns.get("software_mixed", "")
        num_rows = len(next(iter(software_mixed_data.values())))

        if num_rows > 0:
            for i in range(num_rows):
                row = (
                    " | "
                    + " | ".join(
                        software_mixed_data[key][i]
                        for key in software_mixed_data
                    )
                    + " \n"
                )
                rows += row

            software_mixed = rows
        else:
            software_mixed = ""

        indicator_value = software_mixed
        return indicator_value

    def build_indicator_value_for_date_field(self, feed: dict, indicator_type_name: str):
        indicator_value = dateparser.parse(feed.get(indicator_type_name))  # type: ignore
        if indicator_value is not None:
            indicator_value = indicator_value.strftime(DATE_FORMAT)  # type: ignore
        return indicator_value

    def extract_single_value(self, value):
        """
        Extracts a single non-empty value from a potentially nested list.

        :param value: The value to process, which could be a single value or a list of values.
        :return: A single non-empty value or None if no valid value exists.
        """
        if isinstance(value, list):
            for item in value:
                # Recursively extract a value from nested lists
                result = self.extract_single_value(item)
                if result is not None and result != "":
                    return result
            return None
        else:
            return value if value is not None and value != "" else None

    def find_iocs_in_feed(self, feed: dict) -> list:
        """
        Finds IOCs in the feed and transforms them to the appropriate format to ingest them into Demisto.

        :param feed: feed from GIB TI&A.
        """
        indicators_types = self.collection_mapping.get("types", {})
        indicators_add_fields_types = self.collection_mapping.get("add_fields_types", {})

        indicators = []

        demisto.debug(f"Starting to process find_iocs_in_feed feed: {feed}, collection: {self.collection_name}")

        for indicator_type_name, indicator_type in indicators_types.items():
            add_fields = {}
            demisto.debug(
                f"Processing find_iocs_in_feed indicator type: {indicator_type_name}, corresponding type: {indicator_type}")

            if indicator_type in self.fields_list_for_parse:
                indicator_value = self.build_indicator_value_for_date_field(feed=feed, indicator_type_name=indicator_type_name)
                demisto.debug(f"Extracted date field find_iocs_in_feed indicator value: {indicator_value}")
            else:
                if indicator_type_name == "software_mixed":
                    indicator_value = self.build_indicator_value_for_software_mixed(feed=feed)
                    demisto.debug(f"Extracted software mixed find_iocs_in_feed indicator value: {indicator_value}")

                elif indicator_type_name in indicators_add_fields_types:
                    # Retrieve the initial indicator value
                    indicator_value = feed.get(indicator_type_name)
                    demisto.debug(f"Raw find_iocs_in_feed indicator value for {indicator_type_name}: {indicator_value}")

                    # If the value is a list, flatten it to get a single non-list value
                    indicator_value = self.extract_single_value(indicator_value)
                    demisto.debug(f"Flattened find_iocs_in_feed indicator value: {indicator_value}")

                    # Now process additional fields
                    for additional_field_name, additional_field_type in indicators_add_fields_types.get(indicator_type_name).items():  # noqa: E501
                        additional_field_value = feed.get(additional_field_name)

                        # Process additional_field_value similarly
                        additional_field_value = self.extract_single_value(additional_field_value)

                        demisto.debug(
                            f"Processed find_iocs_in_feed additional field '{additional_field_name}': {additional_field_value}")

                        # Only add to add_fields if additional_field_value is not None or empty
                        if additional_field_value is not None and additional_field_value != "":
                            add_fields[additional_field_type] = additional_field_value
                            demisto.debug(
                                f"Added additional field find_iocs_in_feed '{additional_field_type}': {additional_field_value}")

                    add_fields.update(
                        {
                            "trafficlightprotocol": self.common_fields.get("trafficlightprotocol"),
                            "gibcollection": self.collection_name,
                        }
                    )
                    demisto.debug(f"Updated find_iocs_in_feed additional fields: {add_fields}")

            # Create the raw JSON object
            if indicator_value is not None and indicator_value != "":
                raw_json = {
                    "value": indicator_value,
                    "type": indicator_type,
                    **add_fields,
                }
                if self.tags:
                    add_fields.update({"tags": self.tags})
                    raw_json.update({"tags": self.tags})

                indicators.append(
                    {
                        "value": indicator_value,
                        "type": indicator_type,
                        "rawJSON": raw_json,
                        "fields": add_fields,
                    }
                )
                demisto.debug(f"Added indicator find_iocs_in_feed: {indicator_value} of type: {indicator_type}")

        demisto.debug(f"Final list of find_iocs_in_feed indicators: {indicators}")

        indicators = IndicatorBuilding.transform_list_to_str(indicators)
        return indicators

    def get_indicators(self) -> list:
        indicators = []
        results = []
        for feed in self.parsed_json:
            indicators.extend(self.find_iocs_in_feed(feed))
            if (self.limit is not None) and len(indicators) >= self.limit:
                indicators = indicators[: self.limit]
                break

        indicators = IndicatorBuilding.clean_data(indicators)

        if self.build_for_comand:
            sorted_indicators = IndicatorBuilding.sorting_indicators(indicators)

            for type_, indicator in sorted_indicators.items():
                results.append(
                    CommandResults(
                        readable_output=IndicatorBuilding.get_human_readable_feed(
                            indicator, type_, self.collection_name
                        ),
                        raw_response=self.parsed_json,
                        ignore_auto_extract=True,
                    )
                )

        return results if self.build_for_comand is True else indicators


class DateHelper:

    @staticmethod
    def handle_first_time_fetch(last_run, collection_name, first_fetch_time):
        last_fetch = last_run.get("last_fetch", {}).get(collection_name)

        # Handle first time fetch
        date_from = None
        seq_update = None
        if not last_fetch:
            date_from_for_mypy = dateparser.parse(first_fetch_time)
            if date_from_for_mypy is None:
                raise DemistoException(
                    "Inappropriate indicators_first_fetch format, "
                    "please use something like this: 2020-01-01 or January 1 2020 or 3 days."
                    f"It's now been received: {date_from}"
                )
            date_from = date_from_for_mypy.strftime("%Y-%m-%d")
        else:
            seq_update = last_fetch

        return date_from, seq_update


def validate_launch_get_indicators_command(limit, collection_name):
    try:
        if limit > 50:
            raise Exception("A limit should be lower than 50.")
    except ValueError:
        raise Exception("A limit should be a number, not a string.")

    if collection_name not in COMMON_MAPPING.keys():
        raise Exception(
            "Incorrect collection name. Please, choose one of the displayed options."
        )


""" Commands """


def fetch_indicators_command(
    client: Client,
    last_run: dict,
    first_fetch_time: str,
    indicator_collections: list,
    requests_count: int,
    common_fields: dict,
) -> tuple[dict, list]:
    """
    This function will execute each interval (default is 1 minute).

    :param client: GIB_TI&A_Feed client.
    :param last_run: the greatest sequpdate we fetched from last fetch.
    :param first_fetch_time: if last_run is None then fetch all incidents since first_fetch_time.
    :param indicator_collections: list of collections enabled by client.
    :param requests_count: count of requests to API per collection.
    :param common_fields: fields defined by user.

    :return: next_run will be last_run in the next fetch-indicators; indicators will be created in Demisto.
    """
    indicators = []
    next_run: dict[str, dict[str, int | Any]] = {"last_fetch": {}}

    for collection_name in indicator_collections:
        mapping: dict = COMMON_MAPPING.get(collection_name, {})
        requests_sent = 0
        date_from, seq_update = DateHelper.handle_first_time_fetch(
            last_run=last_run,
            collection_name=collection_name,
            first_fetch_time=first_fetch_time,
        )

        if collection_name in COLLECTIONS_THAT_ARE_REQUIRED_HUNTING_RULES:
            hunting_rules = 1
        else:
            hunting_rules = None
            
        generator = client.poller.create_update_generator(
            collection_name=collection_name,
            date_from=date_from,
            sequpdate=seq_update,
            apply_hunting_rules=hunting_rules,
        )

        for portion in generator:
            seq_update = portion.sequpdate
            parsed_json: list[dict] = portion.parse_portion(keys=mapping.get("parser_mapping"))  # type: ignore
            builded_indicators = IndicatorBuilding(
                parsed_json=parsed_json,
                collection_name=collection_name,
                common_fields=common_fields,
                collection_mapping=mapping,
            ).get_indicators()
            
            indicators.extend(builded_indicators)
            requests_sent += 1
            if requests_sent >= requests_count:
                break

        next_run["last_fetch"][collection_name] = seq_update

    return next_run, indicators


def get_indicators_command(client: Client, args: dict[str, str]):
    """
    Returns limited portion of indicators to War Room.

    :param client: GIB_TI&A_Feed client.
    :param args: arguments, provided by client.
    """

    id_, collection_name, limit = (
        args.get("id"),
        args.get("collection", ""),
        int(args.get("limit", "50")),
    )

    validate_launch_get_indicators_command(limit, collection_name)
    mapping: dict = COMMON_MAPPING.get(collection_name, {})

    indicators = []

    if not id_:
        if collection_name in COLLECTIONS_THAT_ARE_REQUIRED_HUNTING_RULES:
            apply_hunting_rules = 1
        else:
            apply_hunting_rules = None
        portions = client.poller.create_update_generator(
            collection_name=collection_name, limit=limit, apply_hunting_rules=apply_hunting_rules
        )
        for portion in portions:
            parsed_json = portion.parse_portion(keys=mapping.get("parser_mapping"))
            builded_indicators = IndicatorBuilding(
                parsed_json=parsed_json,
                collection_name=collection_name,
                common_fields={},
                limit=limit,
                collection_mapping=mapping,
                build_for_comand=True,
            ).get_indicators()
            indicators.extend(builded_indicators)

            if len(indicators) >= limit:
                break
    else:
        portions = client.poller.search_feed_by_id(
            collection_name=collection_name, feed_id=id_
        )
        portions.get_iocs()
        parsed_json = portions.parse_portion(keys=mapping.get("parser_mapping"))
        builded_indicators = IndicatorBuilding(
            parsed_json=parsed_json,  # type: ignore
            collection_name=collection_name,
            common_fields={},
            limit=limit,
            collection_mapping=mapping,
            build_for_comand=True,
        ).get_indicators()
        indicators.extend(builded_indicators)

    return indicators


def main():  # pragma: no cover
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    credentials: dict = params.get("credentials")  # type: ignore
    username = credentials.get("identifier")
    password = credentials.get("password")
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)
    base_url = str(params.get("url"))

    indicator_collections = params.get("indicator_collections", [])
    indicators_first_fetch = params.get("indicators_first_fetch", "3 days").strip()
    requests_count = int(params.get("requests_count", 2))

    args = demisto.args()
    command = demisto.command()
    LOG(f"Command being called is {command}")
    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy,
            headers={"Accept": "*/*"},
        )

        commands = {"gibtia-get-indicators": get_indicators_command}

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif command == "fetch-indicators":
            # Set and define the fetch incidents command to run after activated via integration settings.
            tlp_color = params.get("tlp_color")
            tags = argToList(params.get("feedTags"))
            common_fields = {
                "trafficlightprotocol": tlp_color,
                "tags": tags,
            }
            next_run, indicators = fetch_indicators_command(
                client=client,
                last_run=get_integration_context(),
                first_fetch_time=indicators_first_fetch,
                indicator_collections=indicator_collections,
                requests_count=requests_count,
                common_fields=common_fields,
            )
            demisto.debug(f"fetch-indicators lenght indicators: {len(indicators)}")

            set_integration_context(next_run)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)  # type: ignore

        else:
            return_results(commands[command](client, args))

    # Log exceptions
    except Exception:
        return_error(
            f"Failed to execute {demisto.command()} command.\n"
            f"Indicator collections: {indicator_collections}.\n"
            f"Error: {format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
