import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


""" IMPORTS """


import fnmatch
import hashlib
import ipaddress
import re
import string
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from traceback import format_exc
from typing import Any, ClassVar

import dateparser  # type: ignore[import-untyped]
from ciaops import Parser, TICollections, TIPoller, TIRequestParams
from ciaops.exception import ConnectionException, NotFoundException
from ciaops.utils import RateLimiter


""" CONSTANTS """

# Group-IB fills an unknown date with a placeholder (0001-01-01; 1976-01-01 on osi/vulnerability): no date of a record
# lies before this year.
FIRST_RECORD_YEAR = 1980
# An e-mail value that ends in a page asset's extension ("logo@2x.png") is a file name, not an address.
ASSET_ADDRESS_RE = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|ico|bmp|css|js)$", re.IGNORECASE)
# Indicator types the catalog and the builder both name, without a platform constant. The target of a DDoS attack
# is a victim, not an indicator of compromise: the pack ships its own type for it.
CRYPTOCURRENCY_INDICATOR_TYPE = "Cryptocurrency Address"
VICTIM_IP_TYPE = "GIB Victim IP"


""" COLLECTIONS """


@dataclass(frozen=True)
class CollectionSpec:
    """How the feed reads one collection and turns its records into indicators."""

    # Observable parser key -> its indicator type, or a type chosen per record:
    # {"field": <parser key>, "map": {<API value>: <type>}, "default": <type>}.
    types: dict[str, Any]
    # Observable parser key -> {parser key: indicator field}, in War Room column order.
    indicator_fields: dict[str, dict[str, str]]
    # Parser key -> the record path ciaops reads it from.
    parser_mapping: dict[str, Any]
    # evaluation.severity says how urgent a record is, not how malicious its observables are (a Tor exit node is
    # "green"): each collection sets the verdict, Bad on the threat reports, malware/cnc, ioc/common and
    # osi/vulnerability, Suspicious on the others, whose observables are worth watching but not proven malicious.
    verdict: int = Common.DBotScore.SUSPICIOUS
    # The indicator field holding the observable's own Group-IB score, which decides the verdict when it is 0-100: Bad
    # from score_bad_from (80 by default: "confirmed malicious" on the risk score scale), Suspicious below.
    score_from: str | None = None
    score_bad_from: int = 80
    # The TLP a record of the collection takes when it carries none and the record's TLP applies (Use TLP from source
    # is on, or no instance color is set); None leaves the instance color.
    default_tlp: str | None = None
    # Observable key -> parser keys read along the same array: each observable takes its own element's values.
    aligned_fields: dict[str, list[str]] = field(default_factory=dict)
    # Parser key -> the parser keys that stand in when it is empty.
    attribute_fallbacks: dict[str, list[str]] = field(default_factory=dict)
    # Observable key -> the parser keys its value is read from before it, and after it.
    value_preferred: dict[str, list[str]] = field(default_factory=dict)
    value_fallbacks: dict[str, list[str]] = field(default_factory=dict)
    # Observable key -> the kind of array element it is read from, the kinds being listed under element_type_key.
    element_types: dict[str, str] = field(default_factory=dict)
    element_type_key: str = ""
    # The parser key of a hash list in no fixed order, sorted into its hash keys by length.
    hash_list_key: str | None = None
    # Parser key -> the values that stand for "no value".
    placeholder_values: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # Score parser key -> its vector key: a score of 0 whose vector is missing or "NONE" is unknown.
    unknown_scores: dict[str, str] = field(default_factory=dict)
    # Parser keys sent empty rather than left out, so the value of an earlier listing is cleared.
    explicit_empty: tuple[str, ...] = ()
    tags_from: tuple[str, ...] = ()
    # One tag per category whatever its case or its spaces, underscores and hyphens: "Brute-Force" and "brute force" are one.
    category_tags: bool = False
    relate_threat_actors: bool = True
    software_table_header: str = ""
    # {"key": <parser key>, "latest": <date key>, "collect": {<key>: <list key>}}: the records of one key are one.
    merge_records_by: dict[str, Any] | None = None
    # The list key holding a consensus history, read from its most recently seen state.
    newest_state_of: str | None = None
    # The flags (falsePositive, whitelist) that withdraw a record: its observables do not become indicators.
    dropped_record_flags: tuple[str, ...] = ()
    # The update-feed query a record is looked up by when its observables come from the update feed rather than
    # GET /{collection}/{id}, and the page size of that query.
    id_query: str | None = None
    id_query_page_size: int = 1
    checked_in_update_feed_on_refusal: bool = False
    # The update feed takes df as a filter on the update position: a first fetch without a sequence_list cursor
    # starts from the date. Elsewhere df is ignored or filters on a record's own date, so a read by date starts at the
    # collection's oldest record.
    starts_from_date: bool = False

    @staticmethod
    def refuse_retired(name: str) -> None:
        """Refuses a name of RETIRED_COLLECTIONS, naming the collection to use instead when there is one."""
        if name in RETIRED_COLLECTIONS:
            replacement = RETIRED_COLLECTIONS[name]
            if replacement and replacement not in COLLECTIONS:
                raise DemistoException(
                    f"Collection {name} is obsolete; its replacement {replacement} is fetched as incidents by the "
                    "Group-IB Threat Intelligence integration."
                )
            if replacement:
                raise DemistoException(f"Collection {name} is obsolete; use {replacement} instead.")
            raise DemistoException(f"Collection {name} is obsolete and has no replacement; do not select it.")


# apt/threat and hi/threat serve reports of one shape.
THREAT_REPORT = CollectionSpec(
    verdict=Common.DBotScore.BAD,
    # GET /{collection}/{id} answers 403 for a report Group-IB has not published, and the update feed does not list it.
    checked_in_update_feed_on_refusal=True,
    types={
        "indicators_params_ipv4": FeedIndicatorType.IP,
        "indicators_params_ipv6": FeedIndicatorType.IPv6,
        "indicators_params_domain": FeedIndicatorType.Domain,
        "indicators_params_url": FeedIndicatorType.URL,
        "indicators_params_hashes_sha256": FeedIndicatorType.File,
        "indicators_params_address": FeedIndicatorType.Email,
        "indicators_params_sender_ip": FeedIndicatorType.IP,
    },
    # A report's file entry carries many hash kinds, most of them empty: each file is keyed by its SHA-256, else its
    # SHA-1, else its MD5 (the order of the ioc/* collections), else its SHA-512.
    value_fallbacks={
        "indicators_params_hashes_sha256": [
            "indicators_params_hashes_sha1",
            "indicators_params_hashes_md5",
            "indicators_params_hashes_sha512",
        ]
    },
    # address and senderIp come from the email-message entries only. serverIp is not read: a report
    # does not say whose server it is.
    element_type_key="indicators_type",
    element_types={"indicators_params_address": "email-message", "indicators_params_sender_ip": "email-message"},
    # indicators.params.* yields one entry per element of the indicators array: a file's name, hashes and size
    # and every indicator's dates come from the observable's own element.
    aligned_fields={
        "indicators_params_ipv4": ["indicators_date_first_seen", "indicators_date_last_seen"],
        "indicators_params_ipv6": ["indicators_date_first_seen", "indicators_date_last_seen"],
        "indicators_params_domain": ["indicators_date_first_seen", "indicators_date_last_seen"],
        "indicators_params_url": ["indicators_date_first_seen", "indicators_date_last_seen"],
        "indicators_params_address": ["indicators_date_first_seen", "indicators_date_last_seen"],
        "indicators_params_sender_ip": ["indicators_date_first_seen", "indicators_date_last_seen"],
        "indicators_params_hashes_sha256": [
            "indicators_params_name",
            "indicators_params_hashes_md5",
            "indicators_params_hashes_sha1",
            "indicators_params_hashes_sha256",
            "indicators_params_hashes_sha512",
            "indicators_params_size",
            "indicators_date_first_seen",
            "indicators_date_last_seen",
        ],
    },
    indicator_fields={
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
        "indicators_params_ipv6": {
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
        "indicators_params_address": {
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
        "indicators_params_sender_ip": {
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
        "indicators_params_hashes_sha256": {
            "id": "gibid",
            "indicators_params_name": "gibfilename",
            "indicators_params_hashes_md5": "md5",
            "indicators_params_hashes_sha1": "sha1",
            "indicators_params_hashes_sha256": "sha256",
            "indicators_params_hashes_sha512": "sha512",
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
    parser_mapping={
        "id": "id",
        "indicators_type": "indicators.type",
        "indicators_params_ipv4": "indicators.params.ipv4",
        "indicators_params_ipv6": "indicators.params.ipv6",
        "indicators_params_address": "indicators.params.address",
        "indicators_params_sender_ip": "indicators.params.senderIp",
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
        "indicators_params_hashes_sha512": "indicators.params.hashes.sha512",
        "indicators_params_size": "indicators.params.size",
        "evaluation_reliability": "evaluation.reliability",
        "evaluation_credibility": "evaluation.credibility",
        "evaluation_admiralty_code": "evaluation.admiraltyCode",
        "evaluation_severity": "evaluation.severity",
        "evaluation_tlp": "evaluation.tlp",
        "malware_list_names": "malwareList.name",
        "report_type": "type",
        "date_published": "datePublished",
        "created_at": "createdAt",
        "sectors": "sectors",
        "regions": "regions",
        "countries": "countries",
        "targeted_companies": "targetedCompany",
        "target_domains": "targetDomain",
    },
)


# The fields every observable of an open threat post carries.
OPEN_THREAT_INDICATOR_FIELDS = {
    "id": "gibid",
    "source_name": "gibsource",
    "created_at": "firstseenbysource",
    "updated_at": "lastseenbysource",
    "malware_names": "gibmalwarename",
    "threat_actor_name": "gibthreatactorname",
    "threat_actor_id": "gibthreatactorid",
    "evaluation_reliability": "gibreliability",
    "evaluation_credibility": "gibcredibility",
    "evaluation_admiralty_code": "gibadmiraltycode",
    "evaluation_severity": "gibseverity",
}

COLLECTIONS: dict[str, CollectionSpec] = {
    TICollections.COMPROMISED_ACCOUNT_GROUP: CollectionSpec(
        # Only the C&C of each event is an indicator: events.client.* is the compromised user's device and the
        # service URL the victim's own login page. The service domain, the login's domain, the device's country and
        # the last compromise date are parsed for the filters alone.
        types={
            "event_url": FeedIndicatorType.URL,
            "event_domain": FeedIndicatorType.Domain,
            "event_ipv4": FeedIndicatorType.IP,
        },
        # The malware, actor, source and detection date of a C&C are those of the events naming it (the date that of
        # the first), not of every event of the record.
        aligned_fields={
            "event_url": ["malware_names", "threat_actor_names", "source_names", "event_date_detected"],
            "event_domain": ["malware_names", "threat_actor_names", "source_names", "event_date_detected"],
            "event_ipv4": ["malware_names", "threat_actor_names", "source_names", "event_date_detected"],
        },
        attribute_fallbacks={"event_date_detected": ["date_first_seen"]},
        indicator_fields={
            "event_url": {
                "id": "gibid",
                "malware_names": "gibmalwarename",
                "threat_actor_names": "gibthreatactorname",
                "event_date_detected": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "source_names": "gibsource",
            },
            "event_domain": {
                "id": "gibid",
                "malware_names": "gibmalwarename",
                "threat_actor_names": "gibthreatactorname",
                "event_date_detected": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "source_names": "gibsource",
            },
            "event_ipv4": {
                "id": "gibid",
                "malware_names": "gibmalwarename",
                "threat_actor_names": "gibthreatactorname",
                "event_date_detected": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "source_names": "gibsource",
            },
        },
        parser_mapping={
            "id": "id",
            "event_url": "events.cnc.url",
            "event_domain": "events.cnc.domain",
            "event_ipv4": "events.cnc.ipv4.ip",
            "malware_names": "events.malware.name",
            "threat_actor_names": "events.threatActor.name",
            "event_date_detected": "events.dateDetected",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
            "source_names": "events.source.type",
            "date_last_compromised": "dateLastCompromised",
            "service_domain": "service.domain",
            "login_domain": "parsedLogin.domain",
            "event_country_code": "events.client.ipv4.countryCode",
        },
    ),
    TICollections.ATTACKS_DDOS: CollectionSpec(
        starts_from_date=True,
        types={
            "cnc_url": FeedIndicatorType.URL,
            "cnc_domain": FeedIndicatorType.Domain,
            "cnc_ipv4_ip": FeedIndicatorType.IP,
            "target_ipv4_ip": VICTIM_IP_TYPE,
        },
        indicator_fields={
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
                "malware_name": "gibmalwarename",
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
        parser_mapping={
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
            "target_ipv4_country_code": "target.ipv4.countryCode",
            "target_port": "target.port",
            "type": "type",
            "protocol": "protocol",
            "evaluation_tlp": "evaluation.tlp",
        },
    ),
    TICollections.ATTACKS_DEFACE: CollectionSpec(
        # Only the defaced URL is an observable: targetDomain and targetIp are the victim's own site, parsed for
        # the target_domains and countries filters alone.
        types={"url": "URL"},
        # The defacer handle is a grouping key, not an attribution: it stays in the fields and makes no
        # Threat Actor, relationship or tag.
        relate_threat_actors=False,
        indicator_fields={
            "url": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "date": "firstseenbysource",
                "source": "gibsource",
            },
        },
        parser_mapping={
            "id": "id",
            "url": "url",
            "threat_actor_name": "threatActor.name",
            "threat_actor_is_apt": "threatActor.isAPT",
            "threat_actor_id": "threatActor.id",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
            "date": "date",
            "source": "source",
            "target_domain": "targetDomain",
            "target_ip_country_code": "targetIp.countryCode",
        },
    ),
    TICollections.ATTACKS_PHISHING_KIT: CollectionSpec(
        starts_from_date=True,
        # The SHA-256 of the kit archive is the primary indicator; the operator e-mails are pivots, and older
        # kits carry none.
        types={
            "hash": FeedIndicatorType.File,
            "emails": FeedIndicatorType.Email,
        },
        indicator_fields={
            "hash": {
                "id": "gibid",
                "hash": "sha256",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
            "emails": {
                "id": "gibid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
        },
        parser_mapping={
            "id": "id",
            "hash": "hash",
            "emails": "emails",
            "target_brand": "targetBrand",
            "source": "source",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
        },
    ),
    TICollections.ATTACKS_PHISHING_GROUP: CollectionSpec(
        # The group's phishing list comes from the update feed.
        id_query="id:{id}",
        dropped_record_flags=("false_positive", "whitelist"),
        # Only the phishing URLs are observables: the domain and the hosting IP are often shared infrastructure
        # that also serves legitimate sites.
        types={
            "url": FeedIndicatorType.URL,
        },
        # Each phishing[] entry carries its own objective and detection date; the group's values stand in for an
        # entry without them.
        aligned_fields={"url": ["phishing_objective", "phishing_date_detected"]},
        attribute_fallbacks={"phishing_objective": ["objective"], "phishing_date_detected": ["date_detected"]},
        indicator_fields={
            "url": {
                "id": "gibid",
                "evaluation_severity": "gibseverity",
                "phishing_date_detected": "firstseenbysource",
                "date_updated": "lastseenbysource",
                "brand": "gibphishingbrand",
                "phishing_objective": "gibphishingobjectives",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_id": "gibthreatactorid",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
            },
        },
        tags_from=("brand",),
        # "Index of" (a directory listing) and "Not specified" name no brand.
        placeholder_values={"brand": ("Index of", "Not specified")},
        parser_mapping={
            "id": "id",
            "false_positive": "falsePositive",
            "whitelist": "whitelist",
            "url": "phishing.url",
            "phishing_objective": "phishing.objective",
            "phishing_date_detected": "phishing.date.detected",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
            "date_detected": "date.detected",
            "date_updated": "date.updated",
            "brand": "brand",
            "objective": "objective",
            "threat_actor_name": "threatActor.name",
            "threat_actor_id": "threatActor.id",
            "threat_actor_is_apt": "threatActor.isAPT",
            "source": "source",
        },
    ),
    TICollections.APT_THREAT: THREAT_REPORT,
    TICollections.HI_THREAT: THREAT_REPORT,
    TICollections.SUSPICIOUS_IP_TOR_NODE: CollectionSpec(
        id_query="{id}",
        types={
            "ipv4_ip": FeedIndicatorType.IP,
        },
        indicator_fields={
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
                "source": "gibsource",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "ipv4_provider": "organization",
            }
        },
        # Where ipv4.* has no country, region, AS or provider, they come from the most recently seen consensus state in
        # nodes[].
        newest_state_of="nodes",
        attribute_fallbacks={
            "ipv4_country_name": ["ipv4_country_code", "nodes_country_name", "nodes_country_code"],
            "ipv4_region": ["nodes_region"],
            "ipv4_asn": ["nodes_as"],
            "ipv4_provider": ["nodes_as_name"],
        },
        parser_mapping={
            "id": "id",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "source": "source",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
            "ipv4_country_code": "ipv4.countryCode",
            "ipv4_provider": "ipv4.provider",
            "nodes_country_name": "nodes.states.data.countryName",
            "nodes_country_code": "nodes.states.data.country",
            "nodes_region": "nodes.states.data.region",
            "nodes_as": "nodes.states.data.as",
            "nodes_as_name": "nodes.states.data.asName",
            "nodes_flags": "nodes.states.data.flags",
        },
    ),
    TICollections.SUSPICIOUS_IP_OPEN_PROXY: CollectionSpec(
        id_query="{id}",
        # One address can have several listings: its lookup reads every listing of the address.
        id_query_page_size=TICollections.get_page_limit(TICollections.SUSPICIOUS_IP_OPEN_PROXY) or 1,
        types={
            "ipv4_ip": FeedIndicatorType.IP,
        },
        indicator_fields={
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
                "port": "gibproxyport",
                "ports": "gibproxyports",
                "anonymous": "gibproxyanonymous",
                "source": "gibsource",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "ipv4_provider": "organization",
            }
        },
        attribute_fallbacks={"ipv4_country_name": ["ipv4_country_code"]},
        # A repeated id is the same IP listed again, on the same or another port, in no stable order: the listings of one
        # IP become one indicator with the attributes of the latest listing and every port.
        merge_records_by={"key": "ipv4_ip", "latest": "date_last_seen", "collect": {"port": "ports"}},
        # "1" or "" on every listing: an empty value is sent too, so a stale "1" is cleared.
        explicit_empty=("anonymous",),
        parser_mapping={
            "id": "id",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "port": "port",
            "anonymous": "anonymous",
            "type": "type",
            "source_names": "sources",
            "source": "source",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
            "ipv4_country_code": "ipv4.countryCode",
            "ipv4_provider": "ipv4.provider",
        },
    ),
    TICollections.SUSPICIOUS_IP_SOCKS_PROXY: CollectionSpec(
        id_query="{id}",
        types={
            "ipv4_ip": FeedIndicatorType.IP,
        },
        indicator_fields={
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "ipv4_provider": "organization",
                "source": "gibsource",
            }
        },
        attribute_fallbacks={"ipv4_country_name": ["ipv4_country_code"]},
        parser_mapping={
            "id": "id",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
            "ipv4_country_code": "ipv4.countryCode",
            "ipv4_provider": "ipv4.provider",
            "source": "source",
        },
    ),
    TICollections.SUSPICIOUS_IP_VPN: CollectionSpec(
        types={
            "ipv4_ip": FeedIndicatorType.IP,
        },
        indicator_fields={
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
                "ipv4_provider": "organization",
                "source_names": "gibsource",
            }
        },
        attribute_fallbacks={"ipv4_country_name": ["ipv4_country_code"]},
        tags_from=("vpn_names",),
        parser_mapping={
            "id": "id",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
            "ipv4_country_code": "ipv4.countryCode",
            "ipv4_provider": "ipv4.provider",
            "source_names": "sources",
            "vpn_names": "names",
            "vpn_types": "types",
        },
    ),
    TICollections.SUSPICIOUS_IP_SCANNER: CollectionSpec(
        # A record carries ipv4 or ipv6, never both.
        types={
            "ipv4_ip": FeedIndicatorType.IP,
            "ipv6_ip": FeedIndicatorType.IPv6,
        },
        indicator_fields={
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
                "ipv4_provider": "organization",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "source_names": "gibsource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
            "ipv6_ip": {
                "id": "gibid",
                "ipv6_asn": "asn",
                "ipv6_country_name": "geocountry",
                "ipv6_region": "geolocation",
                "ipv6_provider": "organization",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "source_names": "gibsource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
        },
        attribute_fallbacks={"ipv4_country_name": ["ipv4_country_code"], "ipv6_country_name": ["ipv6_country_code"]},
        tags_from=("categories",),
        category_tags=True,
        parser_mapping={
            "id": "id",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "evaluation_tlp": "evaluation.tlp",
            "ipv4_country_code": "ipv4.countryCode",
            "ipv4_provider": "ipv4.provider",
            "ipv6_ip": "ipv6.ip",
            "ipv6_asn": "ipv6.asn",
            "ipv6_country_name": "ipv6.countryName",
            "ipv6_country_code": "ipv6.countryCode",
            "ipv6_region": "ipv6.region",
            "ipv6_provider": "ipv6.provider",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "source_names": "sources",
            "categories": "categories",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    ),
    TICollections.MALWARE_CNC: CollectionSpec(
        verdict=Common.DBotScore.BAD,
        types={
            "url": FeedIndicatorType.URL,
            "domain": FeedIndicatorType.Domain,
            "ipv4_ip": FeedIndicatorType.IP,
            "ipv6_ip": FeedIndicatorType.IPv6,
        },
        indicator_fields={
            "url": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_list_names": "gibmalwarename",
            },
            "domain": {
                "id": "gibid",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_list_names": "gibmalwarename",
            },
            "ipv4_ip": {
                "id": "gibid",
                "ipv4_asn": "asn",
                "ipv4_country_name": "geocountry",
                "ipv4_region": "geolocation",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_list_names": "gibmalwarename",
                "ipv4_provider": "organization",
            },
            "ipv6_ip": {
                "id": "gibid",
                "ipv6_asn": "asn",
                "ipv6_country_name": "geocountry",
                "ipv6_region": "geolocation",
                "threat_actor_name": "gibthreatactorname",
                "threat_actor_is_apt": "gibthreatactorisapt",
                "threat_actor_id": "gibthreatactorid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_list_names": "gibmalwarename",
                "ipv6_provider": "organization",
            },
        },
        # ipv4[] holds one object per resolved address, each with its own geo; ipv6[] is read the same way.
        aligned_fields={
            "ipv4_ip": ["ipv4_asn", "ipv4_country_name", "ipv4_country_code", "ipv4_region", "ipv4_provider"],
            "ipv6_ip": ["ipv6_asn", "ipv6_country_name", "ipv6_country_code", "ipv6_region", "ipv6_provider"],
        },
        attribute_fallbacks={
            "ipv4_country_name": ["ipv4_country_code"],
            "ipv6_country_name": ["ipv6_country_code"],
            "date_first_seen": ["date_detected"],
        },
        parser_mapping={
            "id": "id",
            "url": "url",
            "domain": "domain",
            "ipv4_ip": "ipv4.ip",
            "ipv4_asn": "ipv4.asn",
            "ipv4_country_name": "ipv4.countryName",
            "ipv4_region": "ipv4.region",
            "ipv6_ip": "ipv6.ip",
            "ipv6_asn": "ipv6.asn",
            "ipv6_country_name": "ipv6.countryName",
            "ipv6_country_code": "ipv6.countryCode",
            "ipv6_region": "ipv6.region",
            "ipv6_provider": "ipv6.provider",
            "threat_actor_name": "threatActor.name",
            "threat_actor_is_apt": "threatActor.isAPT",
            "threat_actor_id": "threatActor.id",
            "date_first_seen": "dateFirstSeen",
            "date_detected": "dateDetected",
            "date_last_seen": "dateLastSeen",
            "malware_list_names": "malwareList.name",
            "platform": "platform",
            "ipv4_country_code": "ipv4.countryCode",
            "ipv4_provider": "ipv4.provider",
        },
    ),
    TICollections.OSI_VULNERABILITY: CollectionSpec(
        verdict=Common.DBotScore.BAD,
        types={
            "id": FeedIndicatorType.CVE,
        },
        # mergedCvss is the score across CVSS versions; cvss.* is the legacy one. A score of 0 with no
        # vector (or "NONE") is unknown, not a score of 0.
        attribute_fallbacks={"merged_cvss_score": ["cvss_score"], "merged_cvss_vector": ["cvss_vector"]},
        unknown_scores={
            "merged_cvss": "merged_cvss_vector",
            "merged_cvss_score": "merged_cvss_vector",
            "cvss_score": "cvss_vector",
        },
        indicator_fields={
            "id": {
                "id": "gibid",
                "merged_cvss_score": "cvss",
                "merged_cvss_vector": "gibcvssvector",
                "merged_cvss": "gibmergedcvss",
                "epss": "gibepss",
                "epss_percentile": "gibepsspercentile",
                "has_exploit": "gibhasexploit",
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
        software_table_header=(
            "| Software Name | Software Type | Software Version |\n| ------------- | ------------- | ---------------- |\n"
        ),
        parser_mapping={
            "id": "id",
            "cvss_score": "cvss.score",
            "cvss_vector": "cvss.vector",
            "merged_cvss": "mergedCvss",
            "merged_cvss_score": "mergedCvss",
            "merged_cvss_vector": "mergedCvssVector",
            "epss": "epss.epss",
            "epss_percentile": "epss.percentile",
            "has_exploit": "hasExploit",
            "seen_in_the_wild": "seenInTheWild",
            "type": "type",
            "cpe_vendors": "cpeTable.vendor",
            "cpe_products": "cpeTable.product",
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
            "evaluation_tlp": "evaluation.tlp",
        },
    ),
    TICollections.OSI_GIT_REPOSITORY: CollectionSpec(
        # One indicator per leak: the repository URL (the record's name). The file revision hashes
        # and the committers' e-mails a leak lists are not indicators of an attack.
        types={
            "repository": FeedIndicatorType.URL,
        },
        indicator_fields={
            "repository": {
                "id": "gibid",
                "date_created": "firstseenbysource",
                "date_detected": "lastseenbysource",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
        },
        parser_mapping={
            "id": "id",
            "repository": "name",
            "evaluation_tlp": "evaluation.tlp",
            "date_created": "dateCreated",
            "date_detected": "dateDetected",
            "file_severities": "files.evaluation.severity",
            "file_data_found": "files.dataFound",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
        },
    ),
    TICollections.HI_OPEN_THREATS: CollectionSpec(
        # A public post about a threat with the IOCs Group-IB extracted from it: its IPs, domains, files, standalone hashes,
        # CVEs and crypto wallets become indicators, and its e-mail addresses stay on the record. Public-tier OSINT, worth
        # watching, not proven malicious.
        types={
            "data_ip": FeedIndicatorType.IP,
            "data_domain": FeedIndicatorType.Domain,
            "data_file_sha256": FeedIndicatorType.File,
            "data_hash": FeedIndicatorType.File,
            "data_cve": FeedIndicatorType.CVE,
            "data_wallet": CRYPTOCURRENCY_INDICATOR_TYPE,
        },
        # A file entry carries several hash kinds, most of them empty: each file is keyed by its SHA-256, else its
        # SHA-1, else its MD5, else its SHA-512.
        value_fallbacks={"data_file_sha256": ["data_file_sha1", "data_file_md5", "data_file_sha512"]},
        aligned_fields={
            "data_file_sha256": [
                "data_file_name",
                "data_file_md5",
                "data_file_sha1",
                "data_file_sha256",
                "data_file_sha512",
                "data_file_size",
            ],
        },
        tags_from=("data_tags",),
        indicator_fields={
            "data_ip": OPEN_THREAT_INDICATOR_FIELDS,
            "data_domain": OPEN_THREAT_INDICATOR_FIELDS,
            "data_file_sha256": {
                "id": "gibid",
                "data_file_name": "gibfilename",
                "data_file_md5": "md5",
                "data_file_sha1": "sha1",
                "data_file_sha256": "sha256",
                "data_file_sha512": "sha512",
                "data_file_size": "size",
                **{key: value for key, value in OPEN_THREAT_INDICATOR_FIELDS.items() if key != "id"},
            },
            "data_hash": OPEN_THREAT_INDICATOR_FIELDS,
            "data_cve": OPEN_THREAT_INDICATOR_FIELDS,
            "data_wallet": OPEN_THREAT_INDICATOR_FIELDS,
        },
        parser_mapping={
            "id": "id",
            "data_ip": "data.ip.ip",
            "data_domain": "data.domains.value",
            "data_file_sha256": "data.files.hashes.sha256",
            "data_file_sha1": "data.files.hashes.sha1",
            "data_file_md5": "data.files.hashes.md5",
            "data_file_sha512": "data.files.hashes.sha512",
            "data_file_name": "data.files.name",
            "data_file_size": "data.files.size",
            "data_hash": "data.hashes.value",
            "data_cve": "data.cve.id",
            "data_email": "data.emails",
            "data_wallet": "data.cryptoWallets.wallets",
            "data_tags": "data.tags",
            "malware_names": "data.malware.name",
            "threat_actor_name": "threatActors.name",
            "threat_actor_id": "threatActors.id",
            "source_name": "source",
            "source_type": "sourceType",
            "date_detected": "dateDetected",
            "hunting_rule_ids": "data.rules",
            "created_at": "createdAt",
            "updated_at": "updatedAt",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
        },
    ),
    TICollections.IOC_COMMON: CollectionSpec(
        verdict=Common.DBotScore.BAD,
        default_tlp="AMBER",
        # A record is either network (domain/ip) or file (a `hash` list holding md5, sha1 and
        # sha256 in no fixed order; the hashes are told apart by length, see `hash_list_key`).
        types={
            "domain": FeedIndicatorType.Domain,
            "ip": FeedIndicatorType.IP,
            "hash_sha256": FeedIndicatorType.File,
        },
        hash_list_key="hash_list",
        value_fallbacks={"hash_sha256": ["hash_sha1", "hash_md5"]},
        indicator_fields={
            "domain": {
                "id": "gibid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_names": "gibmalwarename",
                "threat_names": "gibthreatname",
            },
            "ip": {
                "id": "gibid",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_names": "gibmalwarename",
                "threat_names": "gibthreatname",
            },
            "hash_sha256": {
                "id": "gibid",
                "hash_md5": "md5",
                "hash_sha1": "sha1",
                "hash_sha256": "sha256",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_names": "gibmalwarename",
                "threat_names": "gibthreatname",
            },
        },
        parser_mapping={
            "id": "id",
            "domain": "domain",
            "ip": "ip",
            "hash_list": "hash",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "malware_names": "malwareList.name",
            "threat_names": "threatList.name",
        },
    ),
    TICollections.IOC_PRIMARY: CollectionSpec(
        verdict=Common.DBotScore.SUSPICIOUS,
        default_tlp="AMBER",
        # A record is network (url[]/domain[]/ip[], each element with its own riskScore when it has one) or file (one
        # hash): every element is an indicator whose risk score is its own, and the rest of the record is shared.
        types={
            "url": FeedIndicatorType.URL,
            "domain": FeedIndicatorType.Domain,
            "ip": FeedIndicatorType.IP,
            "hash_sha256": FeedIndicatorType.File,
        },
        value_fallbacks={"hash_sha256": ["hash_sha1", "hash_md5"]},
        aligned_fields={
            "url": ["url_risk_score"],
            "domain": ["domain_risk_score"],
            "ip": ["ip_risk_score"],
        },
        score_from="gibriskscore",
        # A risk score of 1 or more is Bad, a risk score of 0 Suspicious; an observable without one keeps the
        # collection's verdict.
        score_bad_from=1,
        indicator_fields={
            "url": {
                "id": "gibid",
                "url_risk_score": "gibriskscore",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_names": "gibmalwarename",
                "threat_names": "gibthreatname",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
            },
            "domain": {
                "id": "gibid",
                "domain_risk_score": "gibriskscore",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_names": "gibmalwarename",
                "threat_names": "gibthreatname",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
            },
            "ip": {
                "id": "gibid",
                "ip_risk_score": "gibriskscore",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_names": "gibmalwarename",
                "threat_names": "gibthreatname",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
            },
            "hash_sha256": {
                "id": "gibid",
                "hash_md5": "md5",
                "hash_sha1": "sha1",
                "hash_sha256": "sha256",
                "file_risk_score": "gibriskscore",
                "date_first_seen": "firstseenbysource",
                "date_last_seen": "lastseenbysource",
                "malware_names": "gibmalwarename",
                "threat_names": "gibthreatname",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
            },
        },
        parser_mapping={
            "id": "id",
            "url": "url.url",
            "url_risk_score": "url.riskScore",
            "domain": "domain.domain",
            "domain_risk_score": "domain.riskScore",
            "ip": "ip.ip",
            "ip_risk_score": "ip.riskScore",
            "hash_md5": "hash.md5",
            "hash_sha1": "hash.sha1",
            "hash_sha256": "hash.sha256",
            "file_risk_score": "riskScore",
            "date_first_seen": "dateFirstSeen",
            "date_last_seen": "dateLastSeen",
            "malware_names": "malwareList.name",
            "threat_names": "threatList.name",
            "tags": "tags",
            # evaluation.TLP and evaluation.TTL are upper-case keys on this collection, the other evaluation keys
            # lower-case; both spellings of TLP are read.
            "evaluation_tlp": "evaluation.TLP",
            "evaluation_tlp_alt": "evaluation.tlp",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
        },
    ),
    TICollections.COMPROMISED_SPD: CollectionSpec(
        # One payment identifier per record: a crypto wallet is the Cryptocurrency pack's Cryptocurrency Address type,
        # any other identifier this pack's GIB Suspicious Payment Detail type.
        types={
            "value": {
                "field": "spd_type",
                "map": {"Cryptocurrency Wallet": CRYPTOCURRENCY_INDICATOR_TYPE},
                "default": "GIB Suspicious Payment Detail",
            },
        },
        # value.value keeps an e-mail address in its observed casing; value.email.value is the same
        # address in lowercase, the key to match on.
        value_preferred={"value": ["email_value"]},
        score_from="gibspdillegalscore",
        tags_from=("spd_tags",),
        indicator_fields={
            "value": {
                "id": "gibid",
                "spd_type": "gibspdtype",
                "service_type": "gibspdservicetype",
                "illegal_score": "gibspdillegalscore",
                "country": "gibspdcountry",
                "source_names": "gibsource",
                "first_seen_at": "firstseenbysource",
                "last_seen_at": "lastseenbysource",
                "malware_names": "gibmalwarename",
                "threat_actor_names": "gibthreatactorname",
                "evaluation_reliability": "gibreliability",
                "evaluation_credibility": "gibcredibility",
                "evaluation_admiralty_code": "gibadmiraltycode",
                "evaluation_severity": "gibseverity",
            },
        },
        parser_mapping={
            "id": "id",
            "value": "value.value",
            "email_value": "value.email.value",
            "spd_type": "type",
            "service_type": "serviceType",
            "illegal_score": "illegalScore",
            "country": "country",
            "spd_tags": "tags",
            "source_names": "sources.name",
            "first_seen_at": "firstSeenAt",
            "last_seen_at": "lastSeenAt",
            "malware_names": "malware.name",
            "threat_actor_names": "threatActor.name",
            "evaluation_reliability": "evaluation.reliability",
            "evaluation_credibility": "evaluation.credibility",
            "evaluation_admiralty_code": "evaluation.admiraltyCode",
            "evaluation_severity": "evaluation.severity",
            "evaluation_tlp": "evaluation.tlp",
        },
    ),
}

# Collection names the integration refuses, with the collection to use instead (None: there is none).
RETIRED_COLLECTIONS: dict[str, str | None] = {
    "compromised/breached": TICollections.COMPROMISED_BREACHEDDB,
    TICollections.COMPROMISED_MULE: TICollections.COMPROMISED_SPD,
    "compromised/bank_card": TICollections.COMPROMISED_BANK_CARD_GROUP,
    "compromised/card": TICollections.COMPROMISED_BANK_CARD_GROUP,
    "compromised/account": TICollections.COMPROMISED_ACCOUNT_GROUP,
    "compromised/masked_cards": TICollections.COMPROMISED_MASKED_CARD,
    "attacks/phishing": TICollections.ATTACKS_PHISHING_GROUP,
    "bp/phishing": None,
    "bp/phishing_kit": None,
    "compromised/imei": None,
}


""" SETTINGS """


SEVERITY_RANKS = {"green": 1, "orange": 2, "red": 3, "low": 1, "medium": 2, "high": 3}
SEVERITY_OPTIONS = ("Low", "Medium", "High")
# The file grades of osi/git_repository: gray and yellow rank with green, as Low.
FILE_SEVERITY_RANKS = {"gray": 1, "yellow": 1, "green": 1, "orange": 2, "red": 3}
SPD_TYPES = (
    "Cryptocurrency Wallet",
    "Bank Account Number",
    "Mobile Number",
    "Bank Card",
    "IBAN",
    "Email",
    "QR Payment String",
    "Unknown",
)
OPEN_THREAT_SOURCE_TYPES = ("Blog", "Social Network")


def text_values(value: Any) -> list[str]:
    """The texts a parsed value holds: nested lists flattened, blanks dropped, repeats kept once."""
    return [str(item).strip() for item in IndicatorBuilder._flat_values(value) if str(item).strip()]


def number_value(value: Any) -> float | None:
    """The first value as a number; None when there is none, it is a boolean or it is no number."""
    first = IndicatorBuilder._first_value(value)
    if first is None or isinstance(first, bool):
        return None
    try:
        return float(first)
    except (TypeError, ValueError):
        return None


def record_value(record: dict, path: str) -> Any:
    """The value under a dotted ``path`` of a parsed record."""
    value: Any = record
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def values_at(*paths: str) -> Callable[[dict], list[str]]:
    """A reader of the texts under the first of ``paths`` that holds any."""

    def read(record: dict) -> list[str]:
        for path in paths:
            found = text_values(record_value(record, path))
            if found:
                return found
        return []

    return read


def all_values_at(*paths: str) -> Callable[[dict], list[str]]:
    """A reader of the texts under every one of ``paths``."""

    def read(record: dict) -> list[str]:
        return text_values([record_value(record, path) for path in paths])

    return read


def number_at(*paths: str, scale: float = 1.0) -> Callable[[dict], float | None]:
    """A reader of the number under the first of ``paths`` that holds one, times ``scale``."""

    def read(record: dict) -> float | None:
        for path in paths:
            number = number_value(record_value(record, path))
            if number is not None:
                return number * scale
        return None

    return read


def cvss_at(*pairs: tuple[str, str]) -> Callable[[dict], float | None]:
    """A reader of the first known score of ``(score, vector)`` paths; 0 with no vector (or "NONE") is unknown."""

    def read(record: dict) -> float | None:
        for score_path, vector_path in pairs:
            number = number_value(record_value(record, score_path))
            vector = IndicatorBuilder._first_value(record_value(record, vector_path))
            if number is None or (number == 0 and str(vector or "NONE").upper() == "NONE"):
                continue
            return number
        return None

    return read


def count_at(*paths: str) -> Callable[[dict], float | None]:
    """A reader of how many texts ``paths`` hold."""

    def read(record: dict) -> float | None:
        return float(len(all_values_at(*paths)(record)))

    return read


def domains_at(*paths: str) -> Callable[[dict], list[str]]:
    """A reader of the domains under ``paths`` and their parent domains: a filter value matches its subdomains too."""

    def read(record: dict) -> list[str]:
        found: list[str] = []
        for name in all_values_at(*paths)(record):
            labels = name.strip(".").split(".")
            found.extend(".".join(labels[i:]) for i in range(len(labels)))
        return found

    return read


def rank_at(*paths: str, ranks: dict[str, int] | None = None) -> Callable[[dict], int]:
    """A reader of the highest severity rank among a record's values by ``ranks`` (SEVERITY_RANKS by default); unrated is 1."""

    def read(record: dict) -> int:
        table = ranks or SEVERITY_RANKS
        return max((table.get(value.lower(), 1) for value in all_values_at(*paths)(record)), default=1)

    return read


def present_at(*paths: str) -> Callable[[dict], bool]:
    """A reader of whether ``paths`` hold any text."""

    def read(record: dict) -> bool:
        return bool(all_values_at(*paths)(record))

    return read


def observables_at(collection_name: str) -> Callable[[dict], bool]:
    """A reader of whether a record holds an observable of the collection, a fallback hash included."""
    spec = COLLECTIONS[collection_name]
    keys = [*spec.types]
    for extra in (*spec.value_preferred.values(), *spec.value_fallbacks.values()):
        keys.extend(extra)
    return present_at(*dict.fromkeys(keys))


def flag_at(path: str) -> Callable[[dict], bool]:
    """A reader of whether the boolean under ``path`` is set."""

    def read(record: dict) -> bool:
        return IndicatorBuilder._first_value(record_value(record, path)) is True

    return read


def split_values(*paths: str, separator: str = ",") -> Callable[[dict], list[str]]:
    """A reader of the texts under ``paths``, each split on ``separator`` (a proxy listed as "SOCKS4, SOCKS5")."""

    def read(record: dict) -> list[str]:
        return text_values([part for value in all_values_at(*paths)(record) for part in value.split(separator)])

    return read


def normalize_asn(value: str) -> str:
    """An autonomous system number without its AS prefix and case: "AS64501" and "64501" are one."""
    return value.casefold().removeprefix("as").strip()


def normalize_name(value: str) -> str:
    """A name without its separators and case: "Brute-Force" and "brute force" are one."""
    return " ".join(re.sub(r"[^0-9a-z]+", " ", value.casefold()).split())


def platform_names(record: dict) -> list[str]:
    """The platform of a C&C record, with the value "Winsows" read as Windows."""
    return ["windows" if value.casefold() == "winsows" else value for value in values_at("platform")(record)]


def tor_exit(record: dict) -> bool:
    """Whether the relay's newest consensus flags make it a usable exit: Exit among them, BadExit not."""
    flags = {flag.casefold() for flag in values_at("nodes_flags")(record)}
    return "exit" in flags and "badexit" not in flags


def vendor_products(record: dict) -> list[str]:
    """The vendors of a vulnerability's CPE table and each vendor:product pair."""
    vendors, products = record.get("cpe_vendors"), record.get("cpe_products")
    vendors = vendors if isinstance(vendors, list) else [vendors]
    products = products if isinstance(products, list) else [products]
    found = text_values(vendors)
    for vendor, product in zip(vendors, products, strict=False):
        if vendor not in (None, "") and product not in (None, ""):
            found.append(f"{vendor}:{product}")
    return found


@dataclass(frozen=True)
class FilterSpec:
    """One filter of a collection: its name in "Collection filters", how it decides and what it reads."""

    name: str
    # include: a record needs one of the values; exclude: a record with one of them is skipped; contains: a record
    # needs a value holding one of the texts; min: a number, a record without one passes; age: days back from the
    # fetch by the record's date, a record without one passes; severity: Low, Medium or High, an unrated record
    # counts as Low; flag: true keeps the records the condition holds for; networks: addresses and CIDR networks a
    # record's address must not be in; kinds: the indicator types to create; score: the lowest risk score an
    # observable needs, with skip_unscored for the ones without.
    kind: str
    help: str
    read: Callable[[dict], Any] = field(default=lambda record: None, repr=False, compare=False)
    # The values the filter takes, when the set is closed.
    options: tuple[str, ...] = ()
    # How a filter value and a record value are written before they are compared.
    normalize: Callable[[str], str] = field(default=str.casefold, repr=False, compare=False)


def _include(
    name: str,
    help: str,
    read: Callable[[dict], Any],
    options: tuple[str, ...] = (),
    normalize: Callable[[str], str] = str.casefold,
) -> FilterSpec:
    return FilterSpec(name, "include", help, read, options, normalize)


def _exclude(name: str, help: str, read: Callable[[dict], Any], normalize: Callable[[str], str] = str.casefold) -> FilterSpec:
    return FilterSpec(name, "exclude", help, read, normalize=normalize)


def _contains(name: str, help: str, read: Callable[[dict], Any]) -> FilterSpec:
    return FilterSpec(name, "contains", help, read)


def _min(name: str, help: str, read: Callable[[dict], Any]) -> FilterSpec:
    return FilterSpec(name, "min", help, read)


def _flag(name: str, help: str, read: Callable[[dict], Any]) -> FilterSpec:
    return FilterSpec(name, "flag", help, read)


def _severity(
    help: str = "The lowest Group-IB severity a record needs.", read: Callable[[dict], Any] | None = None
) -> FilterSpec:
    return FilterSpec("min_severity", "severity", help, read or rank_at("evaluation_severity"), SEVERITY_OPTIONS)


def _age(help: str, *paths: str) -> FilterSpec:
    return FilterSpec("max_age_days", "age", help, values_at(*paths))


def _networks(read: Callable[[dict], Any]) -> FilterSpec:
    return FilterSpec(
        "excluded_networks", "networks", "Addresses and CIDR networks; a record whose address lies in one is skipped.", read
    )


def _kinds(
    collection_name: str, help_text: str = "Indicator types to create; observables of other types are skipped."
) -> FilterSpec:
    """The indicator types a collection can create, to keep the feed to some of them."""
    names: list[str] = []
    for type_spec in COLLECTIONS[collection_name].types.values():
        if isinstance(type_spec, dict):
            names.extend(name for name in [*type_spec.get("map", {}).values(), type_spec.get("default")] if name)
        else:
            names.append(type_spec)
    if {FeedIndicatorType.IP, FeedIndicatorType.Domain} & set(names):
        # An IP or domain field that holds an IPv6 address gives an IPv6 indicator.
        names.append(FeedIndicatorType.IPv6)
    return FilterSpec("kinds", "kinds", help_text, options=tuple(dict.fromkeys(names)))


def _actors(path: str = "threat_actor_name") -> FilterSpec:
    return _include("actors", "Threat actor names a record needs one of.", values_at(path))


def _malware(path: str, what: str = "a record") -> tuple[FilterSpec, FilterSpec]:
    return (
        _include("malware", f"Malware family names {what} needs one of.", values_at(path)),
        _exclude("excluded_malware", f"Malware family names that skip {what}.", values_at(path)),
    )


def _listing_filters(
    country: Callable[[dict], Any],
    asn: Callable[[dict], Any],
    address: Callable[[dict], Any],
    *extra: FilterSpec,
) -> tuple[FilterSpec, ...]:
    """The filters every suspicious_ip/* collection takes."""
    sources = all_values_at("source", "source_names")
    return (
        _severity(),
        _age("Days back from the fetch by the date the address was last seen listed.", "date_last_seen"),
        _include("countries", "ISO 3166-1 alpha-2 country codes a listing needs one of.", country),
        _exclude("excluded_countries", "Country codes that skip a listing.", country),
        _include(
            "asns",
            "Autonomous system numbers a listing needs one of, with or without the AS prefix.",
            asn,
            normalize=normalize_asn,
        ),
        _exclude("excluded_asns", "Autonomous system numbers that skip a listing.", asn, normalize=normalize_asn),
        _include("sources", "Source names a listing needs one of.", sources),
        _exclude("excluded_sources", "Source names that skip a listing.", sources),
        _networks(address),
        *extra,
    )


def _ioc_filters(collection_name: str, *extra: FilterSpec) -> tuple[FilterSpec, ...]:
    """The filters of ioc/primary and ioc/common."""
    return (
        _age(
            "Days back from the fetch by the date the observables were last seen, else the date they were first seen.",
            "date_last_seen",
            "date_first_seen",
        ),
        *_malware("malware_names"),
        _include("threats", "Threat names a record needs one of.", values_at("threat_names")),
        *extra,
        _kinds(collection_name),
    )


def _report_filters(collection_name: str) -> tuple[FilterSpec, ...]:
    """The filters of the threat report collections."""
    return (
        _severity(),
        _age(
            "Days back from the fetch by the report's publication date, else the date it was created.",
            "date_published",
            "created_at",
        ),
        _include(
            "report_types", "Report types a report needs one of: threat (analyst-authored) or event.", values_at("report_type")
        ),
        _include("sectors", "Sectors a report needs one of.", values_at("sectors")),
        _include("regions", "Regions or country names a report needs one of.", all_values_at("regions", "countries")),
        _actors(),
        _exclude("excluded_actors", "Threat actor names that skip a report.", values_at("threat_actor_name")),
        *_malware("malware_list_names", "a report"),
        _contains("targeted_companies", "Text one of the targeted company names must contain.", values_at("targeted_companies")),
        _include(
            "target_domains", "Domains among the report's target domains, subdomains included.", domains_at("target_domains")
        ),
        _flag(
            "with_iocs_only",
            "true keeps only the reports that carry indicators.",
            observables_at(collection_name),
        ),
        _kinds(collection_name),
    )


# The filters of each collection, in the order the README lists them.
FILTERS: dict[str, dict[str, FilterSpec]] = {
    name: {spec.name: spec for spec in specs}
    for name, specs in {
        TICollections.IOC_PRIMARY: _ioc_filters(
            TICollections.IOC_PRIMARY,
            _include("tags", "Tags a record needs one of.", values_at("tags")),
            FilterSpec(
                "min_risk_score", "score", "The lowest Group-IB risk score (0-100) an observable needs; an unscored one passes."
            ),
            FilterSpec("skip_unscored", "flag", "true skips the observables without a risk score.", lambda record: True),
        ),
        TICollections.IOC_COMMON: _ioc_filters(TICollections.IOC_COMMON),
        TICollections.COMPROMISED_ACCOUNT_GROUP: (
            _severity(),
            _age(
                "Days back from the fetch by the date the account was last compromised, else the date it was first seen.",
                "date_last_compromised",
                "date_first_seen",
            ),
            *_malware("malware_names", "an account"),
            _include("source_types", "Source types an account's events need one of.", values_at("source_names")),
            _include(
                "service_domains",
                "Domains of the service the account belongs to, subdomains included.",
                domains_at("service_domain"),
            ),
            _include("login_domains", "Domains of the login's e-mail address, subdomains included.", domains_at("login_domain")),
            _include(
                "victim_countries",
                "Country codes of the compromised device, from the account's events.",
                values_at("event_country_code"),
            ),
            _kinds(TICollections.COMPROMISED_ACCOUNT_GROUP),
        ),
        TICollections.COMPROMISED_SPD: (
            _severity(),
            _age("Days back from the fetch by the date the payment detail was last seen.", "last_seen_at"),
            _include("types", "Payment detail types a record needs one of.", values_at("spd_type"), SPD_TYPES),
            _include("service_types", "Service types a record needs one of.", values_at("service_type")),
            _min("min_illegal_score", "The lowest illegal score a record needs.", number_at("illegal_score")),
            _include("countries", "Country codes a record needs one of.", values_at("country")),
            _include("malware", "Malware family names a record needs one of.", values_at("malware_names")),
            _include("actors", "Threat actor names a record needs one of.", values_at("threat_actor_names")),
            _kinds(TICollections.COMPROMISED_SPD),
        ),
        TICollections.ATTACKS_DDOS: (
            _severity(),
            _age("Days back from the fetch by the date the attack began.", "date_begin"),
            _include("types", "Attack types a record needs one of.", values_at("type")),
            _include("protocols", "Protocols a record needs one of.", values_at("protocol")),
            _include("target_countries", "Country codes of the attack's target.", values_at("target_ipv4_country_code")),
            _include("target_ports", "Target ports a record needs one of.", values_at("target_port")),
            _include("malware", "Malware family names a record needs one of.", values_at("malware_name")),
            _actors(),
            _kinds(
                TICollections.ATTACKS_DDOS,
                "Indicator types to create; observables of other types are skipped. GIB Victim IP, the attacked host, "
                "is created only when listed.",
            ),
        ),
        TICollections.ATTACKS_DEFACE: (
            _severity(),
            _age("Days back from the fetch by the date of the defacement.", "date"),
            _include("target_domains", "Domains of the defaced site, subdomains included.", domains_at("target_domain")),
            _include("countries", "Country codes of the defaced site's address.", values_at("target_ip_country_code")),
            _actors(),
            _include("sources", "Source names a record needs one of.", values_at("source")),
            _kinds(TICollections.ATTACKS_DEFACE),
        ),
        TICollections.ATTACKS_PHISHING_KIT: (
            _severity(),
            _age(
                "Days back from the fetch by the date the kit was last seen, else the date it was first seen.",
                "date_last_seen",
                "date_first_seen",
            ),
            _include("brands", "Brands a kit needs to target one of.", values_at("target_brand")),
            _include("sources", "Source names a kit needs one of.", values_at("source")),
            _kinds(TICollections.ATTACKS_PHISHING_KIT),
        ),
        TICollections.ATTACKS_PHISHING_GROUP: (
            _severity(),
            _age(
                "Days back from the fetch by the date the group was detected, else the date it was updated.",
                "date_detected",
                "date_updated",
            ),
            _include("brands", "Brands a group needs to impersonate one of.", values_at("brand")),
            _exclude("excluded_brands", "Brands whose groups are skipped.", values_at("brand")),
            _include("objectives", "Phishing objectives a group needs one of.", values_at("objective")),
            _actors(),
            _include("sources", "Source names a group needs one of.", values_at("source")),
            _kinds(TICollections.ATTACKS_PHISHING_GROUP),
        ),
        TICollections.APT_THREAT: _report_filters(TICollections.APT_THREAT),
        TICollections.HI_THREAT: _report_filters(TICollections.HI_THREAT),
        TICollections.SUSPICIOUS_IP_TOR_NODE: _listing_filters(
            all_values_at("ipv4_country_code", "nodes_country_code"),
            all_values_at("ipv4_asn", "nodes_as"),
            values_at("ipv4_ip"),
            _flag(
                "exit_only",
                "true keeps only the relays whose newest consensus flags make them a usable exit (Exit without BadExit).",
                tor_exit,
            ),
            _include(
                "flags", "Consensus flags (Exit, Guard, ...) a relay's newest state needs one of.", values_at("nodes_flags")
            ),
        ),
        TICollections.SUSPICIOUS_IP_OPEN_PROXY: _listing_filters(
            values_at("ipv4_country_code"),
            values_at("ipv4_asn"),
            values_at("ipv4_ip"),
            _include("types", "Proxy protocols (HTTP, HTTPS, SOCKS4, SOCKS5) a listing needs one of.", split_values("type")),
            _include("ports", "Ports a listing needs one of.", all_values_at("port", "ports")),
            _min("min_sources", "The lowest number of public lists the address must appear on.", count_at("source_names")),
        ),
        TICollections.SUSPICIOUS_IP_SOCKS_PROXY: _listing_filters(
            values_at("ipv4_country_code"), values_at("ipv4_asn"), values_at("ipv4_ip")
        ),
        TICollections.SUSPICIOUS_IP_VPN: _listing_filters(
            values_at("ipv4_country_code"),
            values_at("ipv4_asn"),
            values_at("ipv4_ip"),
            _include(
                "types", "Deployment types (commercial, self-hosted, public, ...) a gateway needs one of.", values_at("vpn_types")
            ),
            _include("names", "VPN product names a gateway needs one of.", values_at("vpn_names")),
            _exclude("excluded_names", "VPN product names that skip a gateway.", values_at("vpn_names")),
        ),
        TICollections.SUSPICIOUS_IP_SCANNER: _listing_filters(
            all_values_at("ipv4_country_code", "ipv6_country_code"),
            all_values_at("ipv4_asn", "ipv6_asn"),
            all_values_at("ipv4_ip", "ipv6_ip"),
            _include(
                "categories",
                "Activity categories a listing needs one of, whatever their case and separators.",
                values_at("categories"),
                normalize=normalize_name,
            ),
            _exclude(
                "excluded_categories",
                "Activity categories that skip a listing.",
                values_at("categories"),
                normalize=normalize_name,
            ),
            _kinds(TICollections.SUSPICIOUS_IP_SCANNER),
        ),
        TICollections.MALWARE_CNC: (
            _age(
                "Days back from the fetch by the date the C&C was last seen, else the date it was detected.",
                "date_last_seen",
                "date_detected",
            ),
            _actors(),
            *_malware("malware_list_names", "a C&C"),
            _include(
                "countries",
                "Country codes of the C&C's resolved addresses.",
                all_values_at("ipv4_country_code", "ipv6_country_code"),
            ),
            _exclude(
                "excluded_countries", "Country codes that skip a C&C.", all_values_at("ipv4_country_code", "ipv6_country_code")
            ),
            _include("platforms", "Platforms (Windows, Android, Web) a C&C needs one of.", platform_names),
            _networks(all_values_at("ipv4_ip", "ipv6_ip")),
            _kinds(TICollections.MALWARE_CNC),
        ),
        TICollections.OSI_VULNERABILITY: (
            _severity(),
            _age(
                "Days back from the fetch by the publication date; an older record updated in the window is skipped.",
                "date_published",
            ),
            _include(
                "types", "Record types to read (cve, mscve, nessus, redhat, ...); asked of the API as well.", values_at("type")
            ),
            _exclude(
                "excluded_types",
                "Record types to skip; a single type is asked of the API as well when types is empty.",
                values_at("type"),
            ),
            _flag(
                "has_exploit",
                "true keeps only the records with a known exploit, asked of the API as well.",
                flag_at("has_exploit"),
            ),
            _flag(
                "seen_in_the_wild", "true keeps only the vulnerabilities seen exploited in the wild.", flag_at("seen_in_the_wild")
            ),
            _min(
                "min_cvss",
                "The lowest CVSS score a record needs: the merged cross-version score, else the legacy CVSS score.",
                cvss_at(("merged_cvss_score", "merged_cvss_vector"), ("cvss_score", "cvss_vector")),
            ),
            _min(
                "min_epss_percentile",
                "The lowest EPSS percentile (0-100) a record needs.",
                number_at("epss_percentile", scale=100),
            ),
            _include("vendors", "CPE vendors, or vendor:product pairs, a record's CPE table needs one of.", vendor_products),
            _include("products", "CPE products a record's CPE table needs one of.", values_at("cpe_products")),
        ),
        TICollections.OSI_GIT_REPOSITORY: (
            _severity("The lowest Group-IB severity of the repository record; the files carry their own grades."),
            _age("Days back from the fetch by the date the leak was detected.", "date_detected"),
            FilterSpec(
                "min_file_severity",
                "severity",
                "The lowest grade one of the repository's files needs (gray and yellow count as Low).",
                rank_at("file_severities", ranks=FILE_SEVERITY_RANKS),
                SEVERITY_OPTIONS,
            ),
            _flag(
                "secrets_only",
                "true keeps only the repositories where a file holds a detected secret.",
                present_at("file_data_found"),
            ),
            _include(
                "secret_types",
                "Secret types (password, api_key, ...) a repository's files need one of.",
                values_at("file_data_found"),
            ),
        ),
        TICollections.HI_OPEN_THREATS: (
            _severity(),
            _age(
                "Days back from the fetch by the date the post was created, else the date it was detected.",
                "created_at",
                "date_detected",
            ),
            _include("source_types", "Blog, Social Network or both.", values_at("source_type"), OPEN_THREAT_SOURCE_TYPES),
            _include("sources", "Site or network names a post needs one of.", values_at("source_name")),
            _exclude("excluded_sources", "Site or network names that skip a post.", values_at("source_name")),
            _include("actors", "Threat actor names a post needs one of.", values_at("threat_actor_name")),
            _include("malware", "Malware family names a post needs one of.", values_at("malware_names")),
            _include("tags", "Tags a post needs one of.", values_at("data_tags")),
            _flag(
                "with_iocs_only",
                "true keeps only the posts Group-IB extracted indicators from.",
                observables_at(TICollections.HI_OPEN_THREATS),
            ),
            _flag(
                "matched_rules_only",
                "true keeps only the posts one of your hunting rules matched.",
                present_at("hunting_rule_ids"),
            ),
            _kinds(TICollections.HI_OPEN_THREATS),
        ),
    }.items()
}


@dataclass(frozen=True)
class RecordFilter:
    """The instance's filters: which records and observables become indicators, and the request parameters that narrow a read."""

    # A record a filter drops is not read later: the cursor moves past it.

    SETTING: ClassVar[str] = "Collection filters"
    # Setting key, its label, the filter it sets and the collections it applies to: None for every collection with
    # the filter.
    SETTINGS: ClassVar[tuple[tuple[str, str, str, tuple[str, ...] | None], ...]] = (
        ("min_severity", "Minimum severity", "min_severity", None),
        ("max_record_age_days", "Skip records older than (days)", "max_age_days", None),
        ("vulnerability_types", "Vulnerability types to read", "types", (TICollections.OSI_VULNERABILITY,)),
        ("vulnerability_excluded_types", "Vulnerability types to skip", "excluded_types", (TICollections.OSI_VULNERABILITY,)),
        ("vulnerability_has_exploit", "Vulnerabilities with an exploit only", "has_exploit", (TICollections.OSI_VULNERABILITY,)),
        ("spd_types", "Payment detail types to read", "types", (TICollections.COMPROMISED_SPD,)),
        ("ioc_min_risk_score", "IOC minimum risk score", "min_risk_score", (TICollections.IOC_PRIMARY,)),
        ("open_threats_source_types", "Open threat source types", "source_types", (TICollections.HI_OPEN_THREATS,)),
    )
    # The payment detail types as the API's type parameter spells them, by their lowercase name.
    SPD_SERVER_TYPES: ClassVar[dict[str, str]] = {name.casefold(): name for name in SPD_TYPES}
    TRUE_WORDS: ClassVar[frozenset[str]] = frozenset({"true", "yes", "on", "1"})
    FALSE_WORDS: ClassVar[frozenset[str]] = frozenset({"false", "no", "off", "0"})

    # Collection -> filter name -> its normalized value.
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> "RecordFilter":
        """The filters of the settings, the lines of "Collection filters" applied over them."""
        rules: dict[str, dict[str, Any]] = {}
        for key, label, name, collections in cls.SETTINGS:
            raw = params.get(key)
            if raw in (None, "", []):
                continue
            for collection in collections or cls._collections_with(name):
                cls._set(rules, collection, FILTERS[collection][name], raw, f"'{label}'")
        for line_number, pattern, name, raw in cls._lines(params.get("collection_filters")):
            where = f"{cls.SETTING}, line {line_number}"
            matched = [collection for collection in FILTERS if fnmatch.fnmatchcase(collection, pattern.casefold())]
            if not matched:
                raise DemistoException(f"{where}: unknown collection {pattern!r}. Collections: {', '.join(FILTERS)}.")
            with_filter = [collection for collection in matched if name in FILTERS[collection]]
            if not with_filter:
                known = ", ".join(FILTERS[matched[0]]) if len(matched) == 1 else "see the README"
                raise DemistoException(f"{where}: {pattern} has no filter {name!r}; its filters: {known}.")
            for collection in with_filter:
                cls._set(rules, collection, FILTERS[collection][name], raw, where)
        return cls(rules)

    @staticmethod
    def _collections_with(name: str) -> list[str]:
        return [collection for collection, specs in FILTERS.items() if name in specs]

    @classmethod
    def _lines(cls, text: Any) -> list[tuple[int, str, str, str]]:
        """The (line number, collection pattern, filter name, value) of each line of "Collection filters"."""
        lines = []
        for number, raw_line in enumerate(str(text or "").splitlines(), start=1):
            # A comment is a whole line; a # inside a value is part of it.
            line = "" if raw_line.lstrip().startswith("#") else raw_line.strip()
            if not line:
                continue
            pattern, colon, rest = line.partition(":")
            name, equals, value = rest.partition("=")
            pattern, name = pattern.strip(), name.strip().casefold()
            if not colon or not equals or not pattern or not re.fullmatch(r"[a-z_]+", name):
                raise DemistoException(
                    f"{cls.SETTING}, line {number}: expected 'collection: filter = value', got {raw_line.strip()!r}."
                )
            lines.append((number, pattern, name, value.strip()))
        return lines

    @classmethod
    def _set(cls, rules: dict[str, dict[str, Any]], collection: str, spec: FilterSpec, raw: Any, where: str) -> None:
        """Stores the normalized ``raw``, or clears the filter when it sets none (empty, an age of 0, Low, false)."""
        value = cls._normalized(spec, raw, where)
        if value is None:
            rules.get(collection, {}).pop(spec.name, None)
        else:
            rules.setdefault(collection, {})[spec.name] = value

    @classmethod
    def _normalized(cls, spec: FilterSpec, raw: Any, where: str) -> Any:
        """The value of a filter as ``accepts`` and ``request_params`` read it; None for no filter."""
        if isinstance(raw, str):
            text = raw.strip()
        elif isinstance(raw, list):
            text = ", ".join(str(item).strip() for item in raw if str(item).strip())
        else:
            text = "" if raw is None else str(raw).strip()
        if spec.kind in ("include", "exclude", "contains", "kinds"):
            values = frozenset(spec.normalize(item.strip()) for item in text.split(",") if item.strip())
            allowed = {spec.normalize(option) for option in spec.options}
            unknown = sorted(values - allowed) if allowed else []
            if unknown:
                raise DemistoException(f"{where}: {spec.name} takes {', '.join(spec.options)}, got {', '.join(unknown)}.")
            return values or None
        if spec.kind in ("min", "age", "score"):
            if not text:
                return None
            try:
                number = int(text) if spec.kind == "age" else float(text)
            except ValueError:
                expected = "a whole number of days" if spec.kind == "age" else "a number"
                raise DemistoException(f"{where}: {spec.name} takes {expected}, got {text!r}.") from None
            if number < 0:
                raise DemistoException(f"{where}: {spec.name} must be zero or positive.")
            return (number or None) if spec.kind == "age" else number
        if spec.kind == "severity":
            if not text:
                return None
            rank = SEVERITY_RANKS.get(text.casefold())
            if rank is None or text.casefold() not in {option.casefold() for option in spec.options}:
                raise DemistoException(f"{where}: {spec.name} takes Low, Medium or High, got {text!r}.")
            return rank if rank > 1 else None
        if spec.kind == "flag":
            word = text.casefold()
            if not word or word in cls.FALSE_WORDS:
                return None
            if word in cls.TRUE_WORDS:
                return True
            raise DemistoException(f"{where}: {spec.name} takes true or false, got {text!r}.")
        networks = []
        for item in (part.strip() for part in text.split(",") if part.strip()):
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                raise DemistoException(f"{where}: {spec.name} takes addresses and CIDR networks, got {item!r}.") from None
        return tuple(networks) or None

    def accepts(self, collection_name: str, record: dict, now: datetime | None = None) -> bool:
        """Whether the record passes every record-level filter of its collection."""
        specs = FILTERS.get(collection_name, {})
        moment = now or datetime.fromtimestamp(self.clock(), tz=UTC)
        return all(
            self._passes(specs[name], value, record, moment)
            for name, value in self.rules.get(collection_name, {}).items()
            if specs[name].kind not in ("kinds", "score") and name != "skip_unscored"
        )

    def accepts_entry(self, collection_name: str, indicator_type: str, fields: dict[str, Any]) -> bool:
        """Whether an observable of a kept record becomes an indicator: a wanted type, with any required risk score."""
        rules = self.rules.get(collection_name, {})
        kinds = rules.get("kinds")
        if kinds and indicator_type.casefold() not in kinds:
            return False
        if not kinds and indicator_type == VICTIM_IP_TYPE:
            # A DDoS target is the attacked host: it becomes an indicator only when 'kinds' names its type.
            return False
        minimum, skip_unscored = rules.get("min_risk_score"), rules.get("skip_unscored")
        if minimum is None and not skip_unscored:
            return True
        score = number_value(fields.get("gibriskscore"))
        if score is None:
            return not skip_unscored
        return minimum is None or score >= minimum

    @classmethod
    def _passes(cls, spec: FilterSpec, value: Any, record: dict, now: datetime) -> bool:
        found = spec.read(record)
        if spec.kind == "include":
            return bool(value & {spec.normalize(str(item)) for item in found})
        if spec.kind == "exclude":
            return not value & {spec.normalize(str(item)) for item in found}
        if spec.kind == "contains":
            return any(text in spec.normalize(str(item)) for item in found for text in value)
        if spec.kind == "min":
            return found is None or found >= value
        if spec.kind == "severity":
            return found >= value
        if spec.kind == "age":
            moment = cls._moment(found)
            return moment is None or moment >= now - timedelta(days=value)
        if spec.kind == "flag":
            return bool(found)
        return not cls._listed(found, value)

    @staticmethod
    def _query_value(value: str) -> str:
        """A filter value as the quoted form of a ``q`` query reads it."""
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _moment(found: Any) -> datetime | None:
        text = IndicatorBuilder._first_value(found)
        moment = dateparser.parse(str(text)) if text not in (None, "") else None
        # A placeholder of an unknown date: a record carrying it has no date.
        if moment is None or moment.year < FIRST_RECORD_YEAR:
            return None
        return moment if moment.tzinfo else moment.replace(tzinfo=UTC)

    @staticmethod
    def _listed(addresses: Any, networks: tuple) -> bool:
        """Whether one of the addresses lies in one of the networks; a text that is no address does not."""
        for text in text_values(addresses):
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            if any(address in network for network in networks):
                return True
        return False

    def request_params(self, collection_name: str) -> dict[str, Any]:
        """The request parameters that ask the API for the filtered view; the records are checked again as they arrive."""
        rules = self.rules.get(collection_name, {})
        extra: dict[str, Any] = {}
        if collection_name == TICollections.OSI_VULNERABILITY:
            if rules.get("has_exploit"):
                extra["apply_has_exploit"] = 1
            types, excluded = rules.get("types"), rules.get("excluded_types")
            if types:
                extra["query"] = " OR ".join(f'type:"{self._query_value(name)}"' for name in sorted(types))
            elif excluded and len(excluded) == 1:
                extra["query"] = f'-type:"{self._query_value(next(iter(excluded)))}"'
        elif collection_name == TICollections.COMPROMISED_SPD and len(rules.get("types") or ()) == 1:
            extra["type"] = self.SPD_SERVER_TYPES[next(iter(rules["types"]))]
            # The type goes out as the API spells it; ciaops validates against its own spellings.
            extra["ignore_validation"] = True
        return extra

    def describe(self, collection_name: str) -> str:
        """The collection's filters as one line for the debug log."""
        parts = []
        for name, value in self.rules.get(collection_name, {}).items():
            if isinstance(value, frozenset):
                parts.append(f"{name}={','.join(sorted(value))}")
            elif isinstance(value, tuple):
                parts.append(f"{name}={','.join(str(network) for network in value)}")
            else:
                parts.append(f"{name}={value}")
        return "; ".join(parts)


@dataclass(frozen=True)
class Settings:
    """The instance settings: where the API is, what a fetch reads and what the indicators carry."""

    # Just above the API's limit of one request per second per route.
    DEFAULT_RATE_LIMIT_DELAY: ClassVar[float] = 1.2

    url: str = ""
    proxy: Any = False
    verify: bool = True
    collections: list = field(default_factory=list)
    first_fetch: str = "3 days"
    requests_count: int = 2
    limit: int = 100
    rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY
    hunting_rules: bool = False
    # The instance color applies to every indicator unless the TLP comes from the source.
    tlp_color: Any = None
    use_tlp_from_source: bool = False
    # Set by for_fetch (both) and for_command (relationships only): a bad "Create relationships" value fails only the
    # commands that build indicators.
    tags: tuple = ()
    create_relationships: bool = False
    record_filter: RecordFilter = field(default_factory=RecordFilter)
    params: dict[str, Any] = field(default_factory=dict, repr=False)

    @staticmethod
    def credentials(params: dict[str, Any]) -> tuple[Any, Any]:
        credentials: dict = params.get("credentials") or {}
        return credentials.get("identifier"), credentials.get("password")

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> "Settings":
        return cls(
            url=str(params.get("url")),
            proxy=params.get("proxy", False),
            verify=not params.get("insecure", False),
            collections=params.get("indicator_collections", []),
            first_fetch=(params.get("indicators_first_fetch") or "").strip() or "3 days",
            requests_count=cls._whole_number(params, "requests_count", "Number of requests per collection", 2),
            limit=cls._whole_number(params, "limit", "Limit (items per request)", 100),
            rate_limit_delay=cls._rate_limit_delay(params),
            hunting_rules=argToBoolean(params.get("hunting_rules", False)),
            tlp_color=params.get("tlp_color"),
            use_tlp_from_source=params.get("use_tlp_from_source") is True,
            record_filter=RecordFilter.from_params(params),
            params=params,
        )

    def for_fetch(self) -> "Settings":
        return replace(
            self,
            tags=tuple(argToList(self.params.get("feedTags"))),
            create_relationships=argToBoolean(self.params.get("create_relationships", True)),
        )

    def for_command(self) -> "Settings":
        """As for a fetch, without the feed tags."""
        return replace(self, create_relationships=argToBoolean(self.params.get("create_relationships", True)))

    def first_fetch_date(self) -> str:
        """The "Indicator first fetch" date a collection without a cursor starts from."""
        parsed = dateparser.parse(self.first_fetch)
        if parsed is None:
            raise DemistoException(
                f"Invalid 'Indicator first fetch' value {self.first_fetch!r}: use a date such as 2020-01-01, "
                "January 1 2020 or 3 days."
            )
        return parsed.strftime("%Y-%m-%d")

    @staticmethod
    def _whole_number(params: dict[str, Any], name: str, label: str, default: int) -> int:
        raw = params.get(name)
        if raw in (None, ""):
            return default
        try:
            value = int(str(raw).strip())
        except ValueError:
            raise DemistoException(f"Invalid '{label}' value: expected a whole number, got {raw!r}.") from None
        if value < 0:
            raise DemistoException(f"'{label}' must be zero or positive.")
        return value

    @classmethod
    def _rate_limit_delay(cls, params: dict[str, Any]) -> float:
        raw = params.get("rate_limit_delay")
        if raw in (None, ""):
            return cls.DEFAULT_RATE_LIMIT_DELAY
        try:
            delay = float(str(raw).strip())
        except (TypeError, ValueError) as e:
            raise DemistoException(
                f"Invalid 'Delay between API requests (seconds)' value: expected a number of seconds, got {raw!r}."
            ) from e
        if delay < 0:
            raise DemistoException("'Delay between API requests (seconds)' must be zero or positive.")
        return delay


def seq_update_number(value: Any) -> int | None:
    """A stored or served seqUpdate as a number: an int, a float or a string of digits; None otherwise."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


""" CLIENT """


class BoundaryPages:
    """The update feed of a collection whose records share cursor positions; a position the largest page holds loses no record."""

    # The server serves positions above the cursor it is sent. A read resumed from the cursor a page answers therefore
    # skips the rest of a position that the page edge cut; on darkweb/forums, whose page answers its lowest position,
    # it repeats records of the page. So each page has a generator of its own, asked from just below the highest
    # position read, and the records read again at that position are dropped by digest.
    # Cursor values per position: the suspicious_ip/* feeds filter on the millisecond of a microsecond cursor.
    UNITS = {
        "suspicious_ip/tor_node": 1000,
        "suspicious_ip/open_proxy": 1000,
        "suspicious_ip/socks_proxy": 1000,
        "suspicious_ip/vpn": 1000,
        "suspicious_ip/scanner": 1000,
        "compromised/spd": 1,
        "malware/cnc": 1,
        "osi/public_leak": 1,
        "darkweb/forums": 1,
    }
    # The most records one page of the collection is asked for.
    LARGEST_PAGES = {
        "suspicious_ip/tor_node": 1000,
        "suspicious_ip/open_proxy": 1000,
        "suspicious_ip/socks_proxy": 1000,
        "suspicious_ip/vpn": 1000,
        "suspicious_ip/scanner": 1000,
        "compromised/spd": 1000,
        "malware/cnc": 1000,
        "osi/public_leak": 100,
        "darkweb/forums": 1000,
    }
    # The answers that say a page is too large, rather than that the read failed this time.
    SIZE_REFUSAL_RE = re.compile(r"(?:HTTP |Unexpected HTTP status code: )(?:400|413)\b")
    BELOW_CURSOR = "HTTP 200 with a page below the cursor sent"
    UNREADABLE_CURSOR = "the stored seqUpdate is not a number"

    def __init__(
        self,
        poller: Any,
        collection_name: str,
        request_params: TIRequestParams,
        cursor: int | str | None,
        seen_keys: Iterable[str],
        rate_limit_delay: float,
    ) -> None:
        self._poller = poller
        self._collection_name = collection_name
        self._request_params = request_params
        self._cursor = seq_update_number(cursor)
        if self._cursor is None and cursor is not None:
            raise ConnectionException(self.UNREADABLE_CURSOR)
        self._unit = self.UNITS[collection_name]
        self._largest_page = self.LARGEST_PAGES[collection_name]
        self._limiter = RateLimiter(rate_limit_delay)
        # The digests of the records read at the position the cursor stands just below: stored with the cursor.
        self.seen_keys: list[str] = sorted(seen_keys)
        # One message per position that gave nothing new while the server held more of it, or more behind it.
        self.stalls: list[str] = []
        self._failed_read: ConnectionException | None = None

    def __iter__(self) -> Iterator[Parser]:
        cursor, params, seen = self._cursor, self._request_params, set(self.seen_keys)
        while True:
            page, records, wider = self._read(cursor, params)
            if page is None:
                return
            positions = [self._position(record, page) for record in records]
            top, held = max(positions), None if cursor is None else (cursor + 1) // self._unit
            if held is not None and top < held:
                raise ConnectionException(self.BELOW_CURSOR)
            kept = [
                record
                for record, position in zip(records, positions)
                if held is None or position > held or (position == held and self._digest(record) not in seen)
            ]
            if not kept and self._failed_read is not None:
                raise self._failed_read
            at_top = [record for record, position in zip(records, positions) if position == top]
            # With nothing new on the page, one more read of this position would answer the same.
            stalled = not kept and (wider or (isinstance(page.count, int) and page.count > len(records)))
            if stalled:
                resume, seen = max(self._cursor_of(record, page) for record in at_top), set()
                self.stalls.append(
                    f"Group-IB served {len(records)} {self._collection_name} records at one cursor position ({resume}) "
                    "and nothing new; any further records at that position were skipped."
                )
            else:
                resume = top * self._unit - 1
                # A position served in another order can show other records of it: what was read there stays known.
                seen = {self._digest(record) for record in at_top} | (seen if top == held else set())
            if cursor is not None:
                resume = max(resume, cursor)
            self.seen_keys = sorted(seen)
            if not kept and not stalled:
                return
            yield Parser({**page.raw_dict, "items": kept, "seqUpdate": resume}, page.keys, page.iocs_keys)
            if resume == cursor:
                return
            cursor, params = resume, replace(params, date_from=None, date_to=None)

    def _read(self, cursor: int | None, params: TIRequestParams) -> tuple[Any, list[dict], bool]:
        """The page at ``cursor`` and its records, read larger while one position fills it; True when it can grow no more."""
        requested = int(params.limit or 0)
        limit = min(requested, self._largest_page) if requested > 0 else self._largest_page
        smaller: tuple[Any, list[dict]] | None = None
        self._failed_read = None
        while True:
            self._limiter.wait()
            try:
                pages = self._poller.create_update_generator(
                    collection_name=self._collection_name,
                    request_params=replace(params, limit=limit),
                    sequpdate=cursor,
                    rate_limit_delay=0,
                )
                page = next(iter(Client._pages(pages)), None)
            except ConnectionException as exc:
                if smaller is None:
                    raise
                if self.SIZE_REFUSAL_RE.match(str(exc)):
                    return (*smaller, True)
                self._failed_read = exc
                return (*smaller, False)
            if page is None:
                return (*smaller, True) if smaller else (None, [], False)
            items = page.raw_dict.get("items")
            records = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
            if not records:
                raise ConnectionException(Client.NOT_A_PAGE)
            all_ahead = isinstance(page.count, int) and page.count <= len(records)
            if all_ahead or len(records) < limit or len({self._position(record, page) for record in records}) > 1:
                return page, records, False
            if limit >= self._largest_page:
                return page, records, True
            smaller = (page, records)
            limit = min(limit * 2, self._largest_page)

    @staticmethod
    def _cursor_of(record: dict, page: Any) -> int:
        cursor = seq_update_number(record.get("seqUpdate"))
        return cursor if cursor is not None else seq_update_number(page.sequpdate) or 0

    def _position(self, record: dict, page: Any) -> int:
        return self._cursor_of(record, page) // self._unit

    @staticmethod
    def _digest(record: dict) -> str:
        return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()


class Client(BaseClient):
    """Every Group-IB TI request of the feed, through the ciaops poller."""

    PRODUCT_TYPE = "SOAR"
    PRODUCT_NAME = "CortexSOAR"
    INTEGRATION_NAME = "Group-IB Threat Intelligence"
    INTEGRATION_VERSION = "4.0.0"
    # Data kept between command runs goes in the integration context, so the grant list is cached there.
    GRANTS_CACHE_KEY = "granted_collections_cache"
    GRANTS_CACHE_TTL_SECONDS = 300
    NOT_A_PAGE = "HTTP 200 with a body that is not a page of records"

    def __init__(
        self,
        base_url,
        verify=True,
        proxy=False,
        auth=None,
        rate_limit_delay: float = Settings.DEFAULT_RATE_LIMIT_DELAY,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

        self._auth: tuple[str, str]
        self.poller = TIPoller(username=self._auth[0], api_key=self._auth[1], api_url=base_url)
        # The poller's session takes the proxy from the environment BaseClient sets up but checks certificates on its
        # own (verify=True by default), so "Trust any certificate (not secure)" is passed to it here.
        self.poller.set_verify(verify)
        self.rate_limit_delay = rate_limit_delay
        self._granted: list[dict[str, Any]] | None = None
        self._grants_failure: ConnectionException | None = None
        self.poller.set_product(
            product_type=self.PRODUCT_TYPE,
            product_name=self.PRODUCT_NAME,
            product_version=demisto.demistoVersion().get("version", "unknown"),
            integration_name=self.INTEGRATION_NAME,
            integration_version=self.INTEGRATION_VERSION,
        )
        demisto.info(f"[Client.__init__] TI Feed client initialized: url={base_url}, verify={verify}, proxy={proxy}")

    def granted_collections(self, refresh: bool = False) -> list[dict[str, Any]]:
        """``GET /user/granted_collections``, answered from this command's copy or the cache unless ``refresh``, and cached."""
        if not refresh:
            if self._granted is not None:
                return self._granted
            if self._grants_failure is not None:
                raise self._grants_failure
            cached = self._cached_grants()
            if cached is not None:
                self._granted = cached
                return cached
        try:
            raw = self.poller.send_request(endpoint="user/granted_collections", params={})
        except ConnectionException as exc:
            # A failed grants read is not repeated within one command.
            self._grants_failure = exc
            raise
        self._grants_failure = None
        items = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
        self._granted = items
        self._cache_grants(items)
        return items

    def hunting_rules_collections(self) -> frozenset[str]:
        """Collections whose grant has hunting rules enabled."""
        known = TICollections.INFO.keys()
        return frozenset(
            str(item.get("collection"))
            for item in self.granted_collections()
            if item.get("huntingRulesUsed") and item.get("collection") in known
        )

    def hunting_rules_flag(self, collection_name: str, enabled: bool) -> int | None:
        """1 when the setting is on and the collection takes ``apply_hunting_rules`` with hunting rules granted; else None."""
        if not enabled:
            return None
        if collection_name not in TICollections.APPLY_HUNTING_RULES:
            demisto.debug(f"[hunting-rules] {collection_name} takes no apply_hunting_rules parameter")
            return None
        if collection_name not in self.hunting_rules_collections():
            demisto.debug(f"[hunting-rules] no hunting rules granted for {collection_name}; the parameter is not sent")
            return None
        return 1

    def start_cursor(self, collection_name: str, date_from: str, apply_hunting_rules: int | None) -> int | None:
        """sequence_list's cursor for ``date_from``; None to start from the date, ConnectionException to wait for a cursor."""
        failure, remedy = f"gave no start cursor for {date_from} (an empty answer)", "; the next read asks again"
        try:
            demisto.debug(
                "[Client.start_cursor] Resolving initial seqUpdate via sequence_list: "
                f"collection={collection_name}, date_from={date_from}, apply_hunting_rules={apply_hunting_rules}",
            )
            seq_map = self.poller.get_seq_update_dict(
                date=date_from,
                collection_name=collection_name,
                apply_hunting_rules=apply_hunting_rules,
            )
            resolved = seq_map.get(collection_name)
        except Exception as e:
            resolved, failure = None, f"gave no start cursor for {date_from} ({e})"
        if resolved == 1:
            # 1 is the first update position: a read from it starts at the collection's oldest record, not at the date.
            failure = f"answered 1 for {date_from}, the start of the collection rather than a cursor for that date"
            remedy = "; the next read asks again"
        elif resolved == 0:
            failure = f"answered {resolved} for {date_from}"
            remedy = (
                ". A later 'Indicator first fetch' date gives it a cursor, though changing the setting restarts "
                "every selected collection from the new date"
            )
        if isinstance(resolved, int) and resolved > 1:
            demisto.debug(f"[Client.start_cursor] Using resolved seqUpdate={resolved}; dropping date_from")
            return resolved
        if COLLECTIONS[collection_name].starts_from_date:
            demisto.debug(f"[Client.start_cursor] sequence_list {failure}; falling back to date_from")
            return None
        raise ConnectionException(
            f"sequence_list {failure}; the collection cannot start from a date, so it waits for a sequence_list cursor "
            f"instead of being read from its oldest record{remedy}"
        )

    def update_feed(
        self,
        collection_name: str,
        seq_update: Any = None,
        date_from: str | None = None,
        apply_hunting_rules: int | None = None,
        limit: int | str | None = None,
        filter_params: dict[str, Any] | None = None,
        seen_keys: Iterable[str] = (),
    ) -> Iterable[Any]:
        """The update feed's pages from ``seq_update`` or ``date_from``, with the instance filters' ``filter_params``."""
        demisto.debug(
            "[Client.update_feed] Creating update generator: "
            f"collection={collection_name}, date_from={date_from}, sequpdate={seq_update}, "
            f"apply_hunting_rules={apply_hunting_rules}, limit={limit}, filter_params={filter_params}"
        )
        request_params = TIRequestParams(
            date_from=date_from,
            # Sent as 0 or 1, the form the API's binary filters take.
            apply_hunting_rules=None if apply_hunting_rules is None else int(bool(apply_hunting_rules)),
            limit=self._page_size(collection_name, limit),
            **(filter_params or {}),
        )
        if collection_name in BoundaryPages.UNITS:
            return BoundaryPages(self.poller, collection_name, request_params, seq_update, seen_keys, self.rate_limit_delay)
        return self._pages(
            self.poller.create_update_generator(
                collection_name=collection_name,
                request_params=request_params,
                sequpdate=seq_update,
                rate_limit_delay=self.rate_limit_delay,
            )
        )

    @staticmethod
    def _pages(pages: Iterable[Any]) -> Iterator[Any]:
        """The pages of an update feed; a body that is no page, or a page without a cursor, raises a ConnectionException."""
        try:
            for page in pages:
                # ciaops asks for the next page from the cursor a page answers: without one it reads from the oldest record.
                if seq_update_number(page.sequpdate) is None:
                    raise ConnectionException("HTTP 200 with a page that carries no seqUpdate")
                yield page
        except (AttributeError, TypeError):
            # ciaops raises AttributeError on a null or list body, and TypeError on a page whose items are null or a number.
            raise ConnectionException(Client.NOT_A_PAGE) from None

    def search(self, collection_name: str, query: str, limit: int | None = None) -> Iterable[Any]:
        """The collection's update feed filtered by ``q``."""
        return self._pages(
            self.poller.create_update_generator(
                collection_name=collection_name,
                request_params=TIRequestParams(query=query, limit=self._page_size(collection_name, limit)),
                rate_limit_delay=self.rate_limit_delay,
            )
        )

    def record(self, collection_name: str, record_id: str) -> Any:
        """GET /{collection}/{id}: the page holding the record."""
        try:
            return self.poller.search_feed_by_id(collection_name=collection_name, feed_id=record_id)
        except (AttributeError, TypeError):
            # ciaops raises AttributeError on a by-id body that is null or a list.
            raise ConnectionException(Client.NOT_A_PAGE) from None

    def _page_size(self, collection_name: str, limit: int | str | None) -> int | None:
        """The caller's limit up to the page size ciaops documents for the collection; that size without a limit."""
        cap = TICollections.get_page_limit(collection_name)
        if limit is None or limit == "":
            return cap
        size = int(limit)
        return min(size, cap) if cap is not None else size

    def _cached_grants(self) -> list[dict[str, Any]] | None:
        """The cached grants, or None when absent or older than the TTL."""
        context = get_integration_context() or {}
        entry = context.get(self.GRANTS_CACHE_KEY)
        if not isinstance(entry, dict):
            return None
        fetched_at = entry.get("fetched_at")
        items = entry.get("items")
        if not isinstance(fetched_at, int | float) or not isinstance(items, list):
            return None
        if time.time() - fetched_at > self.GRANTS_CACHE_TTL_SECONDS:
            return None
        return [item for item in items if isinstance(item, dict)]

    def _cache_grants(self, items: list[dict[str, Any]]) -> None:
        # The context also holds the fetch cursors: the cache is merged into it.
        try:
            context = get_integration_context() or {}
            context.update({self.GRANTS_CACHE_KEY: {"fetched_at": time.time(), "items": items}})
            set_integration_context(context)
        except Exception as exc:  # pragma: no cover - a cache write failure must not break a command
            demisto.debug(f"[granted_collections] failed to persist the cache: {exc}")


""" BUILDERS """


class IndicatorBuilder:
    """Turns the records of one collection into indicator entries under the instance settings, and merges entries."""

    # Keys of each hash kind for a record whose hashes come as one list in no order; a SHA-512 has none and is dropped.
    HASH_KEYS = {"md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256"}
    # Defanged notation (hxxps://host[.]tld) never matches traffic; some report indicators carry it.
    DEFANGED_PARTS = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://"), ("[@]", "@"))
    # The types whose values are refanged and screened for placeholders. A payment detail is free text: a QR payment
    # string names its payee with spaces.
    NETWORK_TYPES = frozenset(
        {FeedIndicatorType.URL, FeedIndicatorType.Domain, FeedIndicatorType.IP, FeedIndicatorType.IPv6, FeedIndicatorType.Email}
    )
    IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    # osi/vulnerability also carries Nessus, Red Hat, Microsoft, Oracle and WordPress advisories under their own ids,
    # which are not CVE indicators.
    CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
    BITCOIN_PREFIX = "bitcoin:"
    BASE58_DIGITS = "".join(c for c in string.digits + string.ascii_uppercase + string.ascii_lowercase if c not in "0OIl")
    BECH32_RE = re.compile(r"bc1[ac-hj-np-z02-9]{11,71}", re.IGNORECASE)
    DATE_FIELD_TYPES = frozenset({"firstseenbysource", "lastseenbysource", "published", "cvemodified"})
    # Parser keys whose value is a list of names or codes: every element is kept, not the first one.
    LIST_FIELD_NAMES = frozenset(
        {
            "malware_names",
            "threat_names",
            "threat_actor_names",
            "source_names",
            "malware_list_names",
            "threat_actor_name",
            "threat_actor_id",
            "objective",
            "country",
            "ports",
        }
    )
    TLP_COLORS = ("RED", "AMBER", "GREEN", "WHITE")
    # TLP 2.0 names outside the four colors: CLEAR is stored as WHITE, AMBER+STRICT as AMBER (the nearest of the four).
    TLP_ALIASES = {"CLEAR": "WHITE", "AMBER+STRICT": "AMBER"}
    # From the most to the least shareable: an entry merged from several takes the most restrictive color.
    TLP_STRICTNESS = {"WHITE": 0, "GREEN": 1, "AMBER": 2, "RED": 3}
    # The verdict Cortex XSOAR's own threat-intel feeds give these objects.
    OBJECT_SCORES = {
        ThreatIntel.ObjectsNames.MALWARE: ThreatIntel.ObjectsScore.MALWARE,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: ThreatIntel.ObjectsScore.THREAT_ACTOR,
    }
    # The keys whose lists are kept; any other list is written as its values joined with ", ".
    LIST_KEYS = ("tags", "malwarefamily", "relationships")
    # Fields holding a ", "-joined list of names: a merged entry lists the names of both entries.
    MERGED_NAME_FIELDS = ("gibmalwarename", "gibthreatactorname", "gibthreatactorid", "gibthreatname")
    # The fields only a suspicious_ip/open_proxy listing writes.
    PROXY_LISTING_FIELDS = frozenset({"gibproxyport", "gibproxyports"})

    def __init__(self, collection_name: str, settings: Settings):
        self.collection_name = collection_name
        self.spec = COLLECTIONS[collection_name]
        self._settings = settings

    def parse(self, portion: Any) -> list[dict]:
        """The records of a ciaops page, read with the collection's parser mapping."""
        container = self.spec.newest_state_of
        if container:
            # A <key>.states.data.* path yields the values of every state: the record is rewritten so only the newest
            # state is read.
            raw = portion.raw_dict
            for record in raw["items"] if isinstance(raw.get("items"), list) else [raw]:
                if isinstance(record, dict) and isinstance(record.get(container), list):
                    newest = self._newest_state(record[container])
                    record[container] = [{"states": [{"data": newest}]}] if newest else []
        return portion.parse_portion(keys=self.spec.parser_mapping)

    def build(self, records: list) -> list[dict]:
        """The entries of a page's parsed records, one per type and value."""
        entries: list[dict] = []
        for record in self._kept_records(records):
            entries.extend(self._record_entries(record))
        return self.merge(entries)

    @classmethod
    def merge(cls, entries: list) -> list:
        """One entry per type and value, with the highest verdict; a GIB Victim IP that is also an IP indicator is dropped."""
        merged = cls._merged_duplicates(cls._merged_duplicates(entries, by_collection=True))
        addresses = {entry.get("value") for entry in merged if entry.get("type") == FeedIndicatorType.IP}
        return [entry for entry in merged if not (entry.get("type") == VICTIM_IP_TYPE and entry.get("value") in addresses)]

    @staticmethod
    def _newest_state(nodes: list) -> dict:
        """The data of the most recently seen state of a relay's consensus snapshots, {} without one."""
        states: list[dict] = [
            state["data"]
            for node in nodes
            if isinstance(node, dict)
            for state in node.get("states") or []
            if isinstance(state, dict) and isinstance(state.get("data"), dict)
        ]
        return max(states, key=lambda data: str(data.get("dateLastSeen") or data.get("lastSeen") or ""), default={})

    def _kept_records(self, parsed: list) -> list:
        """The records, merged by ``merge_records_by``, that carry no drop flag and pass the instance filters."""
        dropped_flags = self.spec.dropped_record_flags
        record_filter = self._settings.record_filter
        return [
            record
            for record in self._merged_records(parsed)
            if not (isinstance(record, dict) and any(record.get(flag) is True for flag in dropped_flags))
            and record_filter.accepts(self.collection_name, record)
        ]

    def _merged_records(self, parsed: list) -> list:
        spec = self.spec.merge_records_by
        if not spec:
            return parsed
        groups: dict[Any, list[dict]] = {}
        for position, record in enumerate(parsed):
            key = self._first_value(record.get(spec["key"]))
            groups.setdefault(key if isinstance(key, str) else position, []).append(record)
        records = []
        for group in groups.values():
            newest: dict = max(group, key=lambda record: str(record.get(spec["latest"]) or ""))
            latest = dict(newest)
            for source, target in spec["collect"].items():
                values = self._flat_values([record.get(source) for record in group])
                latest[target] = sorted(values, key=lambda value: int(value) if str(value).isdigit() else -1)
            records.append(latest)
        return records

    def _normalize(self, record: dict) -> None:
        """Sorts an unordered hash list into its hash keys and clears the values that stand for "no value"."""
        if self.spec.hash_list_key:
            for value in self._flat_values(record.get(self.spec.hash_list_key)):
                key = self.HASH_KEYS.get(get_hash_type(str(value)))
                if key and not record.get(key):
                    record[key] = str(value)
        for key, markers in self.spec.placeholder_values.items():
            if isinstance(record.get(key), str) and record[key].strip().casefold() in {marker.casefold() for marker in markers}:
                record[key] = None
        unknown = [
            (score, vector)
            for score, vector in self.spec.unknown_scores.items()
            if record.get(score) == 0 and str(record.get(vector) or "NONE").upper() == "NONE"
        ]
        for score, vector in unknown:
            record[score] = record[vector] = None

    def _record_entries(self, record: dict) -> list[dict]:
        """The entries of one record, one per observable, followed by the objects behind their relationships."""
        self._normalize(record)
        # One TLP per record: an unknown value is logged once, not once per observable of a report.
        tlp = self._record_tlp(record)
        demisto.debug(f"[IndicatorBuilder] collection={self.collection_name} record={record.get('id')}")
        entries = []
        for type_key, xsoar_type, value, positions, count in self._observables(record):
            indicator = self._indicator(xsoar_type, value)
            if indicator is None:
                continue
            fields = {
                **self._fields(record, type_key, positions, count),
                "trafficlightprotocol": tlp,
                "gibcollection": self.collection_name,
            }
            if not self._settings.record_filter.accepts_entry(self.collection_name, indicator[0], fields):
                continue
            entries.append(self._entry(record, *indicator, fields))
        entries.extend(self._objects(entries))
        demisto.debug(f"[IndicatorBuilder] record={record.get('id')} indicators={len(entries)}")
        return self._flattened(entries)

    def _entry(self, record: dict, xsoar_type: str, value: str, fields: dict[str, Any]) -> dict:
        # A DDoS victim keeps the attack's malware and actor names as fields, but it is no indicator of compromise:
        # no verdict, no tags of its attackers, no relationships.
        is_victim = xsoar_type == VICTIM_IP_TYPE
        malware_names = [] if is_victim else [str(v) for v in self._flat_values(fields.get("gibmalwarename"))]
        actor_names = (
            [str(v) for v in self._flat_values(fields.get("gibthreatactorname"))]
            if self.spec.relate_threat_actors and not is_victim
            else []
        )
        threat_names = [] if is_victim else [str(v) for v in self._flat_values(fields.get("gibthreatname"))]
        if malware_names:
            # The platform's own multi-select field, next to the Group-IB one.
            fields["malwarefamily"] = malware_names
        if xsoar_type == FeedIndicatorType.File:
            kind = get_hash_type(value)
            if kind in ("md5", "sha1", "sha256", "sha512") and not fields.get(kind):
                fields[kind] = value
        tags = self._tags(record, malware_names, actor_names, threat_names)
        if tags:
            fields["tags"] = tags
        raw_json = {"value": value, "type": xsoar_type, **fields}
        entry: dict[str, Any] = {"value": value, "type": xsoar_type, "rawJSON": raw_json, "fields": fields}
        relationships = [] if is_victim else self._relationships(value, xsoar_type, malware_names, actor_names)
        if relationships:
            entry["relationships"] = relationships
        # Both places: the indicator object for the server, rawJSON for mappers; an Indicator Reputation set on the
        # instance replaces it.
        score = self._verdict(fields, is_victim)
        entry["score"] = score
        raw_json["score"] = score
        return entry

    def _observables(self, record: dict) -> list[tuple[str, str, Any, tuple[int, ...], int]]:
        """``(observable key, type, value, positions, count)`` per value; ``positions`` index the elements holding it."""
        found: list[tuple[str, str, Any, tuple[int, ...], int]] = []
        for type_key, type_spec in self.spec.types.items():
            xsoar_type = self._resolve_type(type_spec, record)
            if not xsoar_type:
                continue
            values, count = self._values(record, type_key)
            found.extend((type_key, xsoar_type, value, positions, count) for value, positions in values)
        return found

    @staticmethod
    def _resolve_type(type_spec: Any, record: dict) -> str | None:
        if isinstance(type_spec, str):
            return type_spec
        if not isinstance(type_spec, dict):
            return None
        raw = record.get(type_spec.get("field", ""))
        if isinstance(raw, list):
            raw = next((item for item in raw if item not in (None, "")), None)
        return type_spec.get("map", {}).get(raw, type_spec.get("default")) if isinstance(raw, str) else type_spec.get("default")

    def _values(self, record: dict, type_key: str) -> tuple[list[tuple[Any, tuple[int, ...]]], int]:
        """Each value of the preferred, own or fallback keys, the positions of the elements holding it, and the element count."""
        keys = [*self.spec.value_preferred.get(type_key, []), type_key, *self.spec.value_fallbacks.get(type_key, [])]
        raw = self._first_present_per_element([record.get(key) for key in keys])
        if raw is None:
            return [], 0
        elements = raw if isinstance(raw, list) else [raw]
        # An observable read only from the elements of one kind (indicators[].type of a report).
        element_type = self.spec.element_types.get(type_key)
        kinds = record.get(self.spec.element_type_key) if element_type else None
        values: list = []
        positions: list[list[int]] = []
        for position, element in enumerate(elements):
            if element_type and not (isinstance(kinds, list) and len(kinds) == len(elements) and kinds[position] == element_type):
                continue
            for value in self._flat_values(element):
                if value in values:
                    positions[values.index(value)].append(position)
                else:
                    values.append(value)
                    positions.append([position])
        return [(value, tuple(found)) for value, found in zip(values, positions)], len(elements)

    @classmethod
    def _first_present_per_element(cls, columns: list[Any]) -> Any:
        """The first column holding a value, chosen per element when the columns are lists of one length."""
        present = [column for column in columns if cls._flat_values(column)]
        if present and all(isinstance(column, list) for column in present) and len({len(column) for column in present}) == 1:
            return [
                next((column[position] for column in present if cls._flat_values(column[position])), None)
                for position in range(len(present[0]))
            ]
        return present[0] if present else None

    def _indicator(self, xsoar_type: str, value: Any) -> tuple[str, str] | None:
        """``(type, value)`` of the indicator an observable becomes, or None when the value is no indicator."""
        # Only a string is an observable value; an object element is skipped.
        if not isinstance(value, str) or value == "":
            return None
        if xsoar_type in self.NETWORK_TYPES:
            value = self._refang(value)
        if (
            (xsoar_type in self.NETWORK_TYPES and self._is_template(value))
            or (xsoar_type == FeedIndicatorType.CVE and not self.CVE_ID_RE.match(str(value)))
            or (xsoar_type == FeedIndicatorType.Email and ASSET_ADDRESS_RE.search(value))
        ):
            return None
        if xsoar_type == CRYPTOCURRENCY_INDICATOR_TYPE:
            value = self._wallet_value(value)
        # An address in a domain field is an IP indicator; an IPv6 address in a domain or IP field is an IPv6 one.
        effective_type = FeedIndicatorType.IP if xsoar_type == FeedIndicatorType.Domain and self._is_ipv4(value) else xsoar_type
        if xsoar_type in (FeedIndicatorType.Domain, FeedIndicatorType.IP) and self._is_ipv6(value):
            effective_type = FeedIndicatorType.IPv6
        return effective_type, value

    @classmethod
    def _refang(cls, value: Any) -> Any:
        """``hxxps://evil[.]example/x`` -> ``https://evil.example/x``; a string is trimmed, a non-string is returned as it is."""
        if not isinstance(value, str):
            return value
        text = value.strip()
        if text[:4].lower() == "hxxp":
            text = "http" + text[4:]
        for defanged, fanged in cls.DEFANGED_PARTS:
            text = text.replace(defanged, fanged)
        return text

    @staticmethod
    def _is_template(value: Any) -> bool:
        """Whether a value is a placeholder (``/contents/{machineId}/``): it holds braces or blanks; brackets alone are real."""
        return isinstance(value, str) and (any(char in value for char in "{}") or any(char.isspace() for char in value))

    def _is_ipv4(self, value: Any) -> bool:
        return isinstance(value, str) and bool(self.IPV4_RE.match(value.strip()))

    @staticmethod
    def _is_ipv6(value: Any) -> bool:
        try:
            return isinstance(value, str) and ipaddress.ip_address(value.strip()).version == 6
        except ValueError:
            return False

    def _wallet_value(self, value: str) -> str:
        """A Bitcoin address with the ``bitcoin:`` prefix, as extraction writes a base58check one; any other wallet as it is."""
        address = value.strip()
        if address.lower().startswith(self.BITCOIN_PREFIX):
            address = address[len(self.BITCOIN_PREFIX) :]
        return f"{self.BITCOIN_PREFIX}{address}" if self._is_bitcoin_address(address) else address

    def _is_bitcoin_address(self, address: str) -> bool:
        """Base58check starting with 1 or 3 (what extraction and CryptoCurrenciesFormat accept) or bech32 starting with bc1."""
        if self.BECH32_RE.fullmatch(address):
            return True
        if address[:1] not in ("1", "3") or not 26 <= len(address) <= 35:
            return False
        number = 0
        for char in address:
            digit = self.BASE58_DIGITS.find(char)
            if digit < 0:
                return False
            number = number * 58 + digit
        try:
            raw = number.to_bytes(25, "big")
        except OverflowError:
            return False
        return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]

    def _fields(self, record: dict, type_key: str, positions: tuple[int, ...], count: int) -> dict[str, Any]:
        """An observable's fields in ``indicator_fields`` order, an aligned field from the observable's own elements."""
        aligned = set(self.spec.aligned_fields.get(type_key, []))
        fallbacks = self.spec.attribute_fallbacks
        fields: dict = {}
        for field_name, field_type in self.spec.indicator_fields.get(type_key, {}).items():
            value: Any = None
            if field_name == "software_mixed":
                value = self._software_table(record) or None
            else:
                for key in (field_name, *fallbacks.get(field_name, [])):
                    value = self._field_value(record.get(key), key in aligned, key in self.LIST_FIELD_NAMES, positions, count)
                    if field_type in self.DATE_FIELD_TYPES and self._is_placeholder_date(value):
                        value = None
                    if value is not None and value != "":
                        break
            if value is not None and value != "":
                fields[field_type] = value
            elif field_name in self.spec.explicit_empty:
                fields[field_type] = ""
        if len(self._flat_values(fields.get("gibthreatactorname"))) != 1:
            # The APT flag of an empty threatActor block describes no actor, and the flag of the
            # first of several actors (a C&C's threatActor[]) does not describe the others.
            fields.pop("gibthreatactorisapt", None)
        return fields

    def _field_value(self, raw: Any, aligned: bool, list_field: bool, positions: tuple[int, ...], count: int) -> Any:
        if aligned and isinstance(raw, list) and len(raw) == count:
            values = self._flat_values([raw[position] for position in (positions if list_field else positions[:1])])
            return values[0] if len(values) == 1 else values or None
        if list_field:
            return self._flat_values(raw) or None
        return self._first_value(raw)

    def _software_table(self, record: dict) -> str:
        """The affected software of a vulnerability as a Markdown table; empty when the record lists none."""
        data = record.get("software_mixed")
        if not isinstance(data, dict) or not data:
            return ""
        columns = [column if isinstance(column, list) else [] for column in data.values()]
        rows = ["| " + " | ".join("" if value is None else str(value) for value in row) + " |" for row in zip(*columns)]
        return self.spec.software_table_header + "\n".join(rows) + "\n" if rows else ""

    @staticmethod
    def _is_placeholder_date(value: Any) -> bool:
        """A placeholder the API writes for "no date", such as ``0001-01-01T00:00:00+00:00``."""
        match = re.match(r"\s*(\d{4})-\d{1,2}-\d{1,2}(?!\d)", value) if isinstance(value, str) else None
        return match is not None and int(match.group(1)) < FIRST_RECORD_YEAR

    def _record_tlp(self, record: dict) -> Any:
        """The instance color unless the TLP comes from the source; else the record's TLP, the default, the instance color."""
        fallback_tlp = self._settings.tlp_color
        # Without an instance color a record's own TLP applies: a TLP:RED report must not become an indicator anyone
        # may share.
        if fallback_tlp and not self._settings.use_tlp_from_source:
            return fallback_tlp
        raw_tlp = record.get("evaluation_tlp")
        if raw_tlp in (None, "", []):
            raw_tlp = record.get("evaluation_tlp_alt")
        return self._tlp_color(self._first_value(raw_tlp)) or self.spec.default_tlp or fallback_tlp

    @classmethod
    def _tlp_color(cls, value: Any) -> str | None:
        """Group-IB's TLP (``amber``, ``TLP:RED``, ``clear``) as a Cortex XSOAR color; an unknown name is RED."""
        if not value or not isinstance(value, str):
            return None
        normalized = value.strip().upper()
        if normalized.startswith("TLP:"):
            normalized = normalized[4:].strip()
        if not normalized:
            return None
        normalized = cls.TLP_ALIASES.get(normalized, normalized)
        if normalized in cls.TLP_COLORS:
            return normalized
        demisto.info(f"[IndicatorBuilder] unknown TLP {value!r}: the indicator gets RED")
        return "RED"

    @classmethod
    def _strictest_tlp(cls, colors: list[str]) -> str:
        return max(colors, key=lambda color: cls.TLP_STRICTNESS.get(color, len(cls.TLP_STRICTNESS)))

    def _tags(self, record: dict, malware_names: list[str], actor_names: list[str], threat_names: list[str]) -> list[str]:
        """The instance tags, the collection, the malware, actor and threat names, then the record's tag values."""
        tags = list(self._settings.tags)
        for tag in [self.collection_name, *malware_names, *actor_names, *threat_names]:
            if tag and tag not in tags:
                tags.append(tag)
        for tags_key in self.spec.tags_from:
            for value in self._flat_values(record.get(tags_key)):
                tag = re.sub(r"[\s_-]+", "-", str(value).strip()).casefold() if self.spec.category_tags else str(value)
                if tag and tag not in tags:
                    tags.append(tag)
        return tags

    def _verdict(self, fields: dict[str, Any], is_victim: bool) -> int:
        """The verdict of the observable's own Group-IB score, else the collection's; a DDoS victim gets none."""
        if is_victim:
            return Common.DBotScore.NONE
        score_from = self.spec.score_from
        score = self._score_verdict(fields.get(score_from), self.spec.score_bad_from) if score_from else None
        return self.spec.verdict if score is None else score

    @staticmethod
    def _score_verdict(value: Any, bad_from: float) -> int | None:
        """A 0-100 score as Bad from ``bad_from``, else Suspicious; None without a score in that range."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if number < 0 or number > 100:
            return None
        return Common.DBotScore.BAD if number >= bad_from else Common.DBotScore.SUSPICIOUS

    def _relationships(self, value: str, xsoar_type: str, malware_names: list[str], actor_names: list[str]) -> list[dict]:
        """The observable is an indicator-of each malware family and related-to each threat actor its record names."""
        if not self._settings.create_relationships:
            return []
        relationships: list[dict] = []
        for name in malware_names:
            relationships.append(
                EntityRelationship(
                    name=EntityRelationship.Relationships.INDICATOR_OF,
                    reverse_name=EntityRelationship.Relationships.INDICATED_BY,
                    entity_a=value,
                    entity_a_type=xsoar_type,
                    entity_b=name,
                    entity_b_type=ThreatIntel.ObjectsNames.MALWARE,
                ).to_indicator()
            )
        for name in actor_names:
            relationships.append(
                EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    reverse_name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=value,
                    entity_a_type=xsoar_type,
                    entity_b=name,
                    entity_b_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                ).to_indicator()
            )
        return relationships

    def _objects(self, entries: list[dict]) -> list[dict]:
        """One Malware or Threat Actor object per relationship target, so every relationship has its object."""
        if not self._settings.create_relationships:
            return []
        objects: dict[tuple[str, str], dict] = {}
        for entry in entries:
            fields = entry.get("fields") or {}
            for relationship in entry.get("relationships") or []:
                key = (relationship["entityBType"], relationship["entityB"])
                if key in objects:
                    continue
                object_fields: dict = {
                    "gibcollection": self.collection_name,
                    "tags": [*self._settings.tags, self.collection_name],
                }
                if fields.get("trafficlightprotocol"):
                    object_fields["trafficlightprotocol"] = fields["trafficlightprotocol"]
                if key[0] == ThreatIntel.ObjectsNames.THREAT_ACTOR and self._flat_values(fields.get("gibthreatactorname")) == [
                    key[1]
                ]:
                    # The id and APT flag are unambiguous only when the record names one actor.
                    for attribute in ("gibthreatactorid", "gibthreatactorisapt"):
                        value = self._first_value(fields.get(attribute))
                        if value not in (None, ""):
                            object_fields[attribute] = value
                score = self.OBJECT_SCORES[key[0]]
                objects[key] = {
                    "value": key[1],
                    "type": key[0],
                    "rawJSON": {"value": key[1], "type": key[0], "score": score, **object_fields},
                    "fields": object_fields,
                    "score": score,
                }
        return list(objects.values())

    @classmethod
    def _flattened(cls, entries: list[dict]) -> list[dict]:
        """Entries with every list outside LIST_KEYS written as its non-empty values joined with ", "."""
        return [cls._flattened_item(entry) for entry in entries]

    @classmethod
    def _flattened_item(cls, item: Any) -> Any:
        if isinstance(item, dict):
            for key, value in item.items():
                if key in cls.LIST_KEYS:
                    continue
                if isinstance(value, list):
                    item[key] = ", ".join(str(cls._flattened_item(v)) for v in value if v is not None and v != "")
                else:
                    item[key] = cls._flattened_item(value)
        return item

    @classmethod
    def _merged_duplicates(cls, entries: list, by_collection: bool = False) -> list:
        """The entries of one type and value (and collection, if ``by_collection``) merged, in first-seen order."""
        merged: dict[tuple, dict] = {}
        for entry in entries:
            key: tuple = (entry.get("type"), entry.get("value"))
            if by_collection:
                key += ((entry.get("fields") or {}).get("gibcollection"),)
            kept = merged.get(key)
            merged[key] = entry if kept is None else cls._merged(kept, entry)
        return list(merged.values())

    @classmethod
    def _merged(cls, kept: dict, other: dict) -> dict:
        """Two entries as one, with the fields of the higher verdict; on a tie, of the later entry or later-seen proxy listing."""
        listings = all(cls.PROXY_LISTING_FIELDS & set(entry.get("fields") or {}) for entry in (kept, other))

        def rank(entry: dict) -> tuple:
            last_seen = (entry.get("fields") or {}).get("lastseenbysource") if listings else None
            return (entry.get("score") or 0, str(last_seen or ""))

        first, second = (kept, other) if rank(kept) > rank(other) else (other, kept)
        first_fields, second_fields = first.get("fields") or {}, second.get("fields") or {}
        fields = {**second_fields, **first_fields}
        for name in ("tags", "malwarefamily"):
            values = [*first_fields.get(name, []), *second_fields.get(name, [])]
            if values:
                fields[name] = list(dict.fromkeys(values))
        for name in cls.MERGED_NAME_FIELDS:
            names = cls._names(first_fields.get(name), second_fields.get(name))
            if names:
                fields[name] = ", ".join(names)
        if len(cls._names(fields.get("gibthreatactorname"))) > 1:
            # One APT flag does not describe several actors.
            fields.pop("gibthreatactorisapt", None)
        if listings:
            ports = cls._names(first_fields.get("gibproxyports"), second_fields.get("gibproxyports"))
            fields["gibproxyports"] = ", ".join(sorted(ports, key=lambda port: int(port) if port.isdigit() else -1))
        colors = [
            entry["fields"]["trafficlightprotocol"]
            for entry in (first, second)
            if (entry.get("fields") or {}).get("trafficlightprotocol")
        ]
        if colors:
            fields["trafficlightprotocol"] = cls._strictest_tlp(colors)
        raw_json = {"value": first.get("value"), "type": first.get("type"), **fields, "score": first.get("score")}
        entry = {**first, "fields": fields, "rawJSON": raw_json}
        relationships = {
            (r.get("name"), r.get("entityB"), r.get("entityBType")): r
            for r in [*first.get("relationships", []), *second.get("relationships", [])]
        }
        if relationships:
            entry["relationships"] = list(relationships.values())
        return entry

    @staticmethod
    def _names(*values: Any) -> list[str]:
        """The distinct names of ", "-joined name lists, in order."""
        return list(dict.fromkeys(name for value in values if value not in (None, "") for name in str(value).split(", ")))

    @staticmethod
    def _flat_values(value: Any) -> list:
        """All non-empty non-list values of a possibly nested list, in order, without duplicates."""
        found: list = []

        def walk(item: Any) -> None:
            if isinstance(item, list):
                for element in item:
                    walk(element)
            elif item not in (None, "") and item not in found:
                found.append(item)

        walk(value)
        return found

    @classmethod
    def _first_value(cls, value: Any) -> Any:
        """The first non-empty non-list value of a possibly nested list, or of the value itself; None without one."""
        values = cls._flat_values(value)
        return values[0] if values else None


""" COMMANDS """


class FetchIndicatorsCommand:
    """fetch-indicators: up to ``requests_count`` pages of each selected collection from its cursor or the first-fetch date."""

    BATCH_SIZE = 2000
    # Fingerprints of the two settings that decide where the cursors lead: a change of either drops the cursors.
    FIRST_FETCH_KEY = "first_fetch_time"
    HUNTING_RULES_KEY = "hunting_rules"
    # The digests of the records read at each BoundaryPages cursor, stored with it.
    BOUNDARY_KEYS_KEY = "boundary_keys"

    def __init__(self, client: Client, settings: Settings):
        self._client = client
        self._settings = settings
        self._boundary_keys: dict[str, list[str]] = {}
        self._stalls: list[str] = []

    def execute(self) -> None:
        """Runs from the stored state, creates the indicators, then stores the next state."""
        next_run, indicators = self.run(get_integration_context())
        demisto.debug(f"[fetch-indicators] Indicators created this run: count={len(indicators)}")
        for chunk in batch(indicators, batch_size=self.BATCH_SIZE):
            demisto.createIndicators(chunk)  # type: ignore
        demisto.info("[fetch-indicators] Indicators created successfully")
        # The cursors move only once the indicators are stored, and the context also holds the grant cache.
        context = get_integration_context() or {}
        context.update(next_run)
        set_integration_context(context)
        demisto.debug(f"[fetch-indicators] Updated integration context: {next_run}")

    def run(self, last_run: dict[str, Any] | None) -> tuple[dict[str, Any], list]:
        """The next fetch state and the indicators to create, from the state of the previous run."""
        settings = self._settings
        demisto.debug(
            "[fetch-indicators] Starting fetch: "
            f"collections={settings.collections}, requests_count={settings.requests_count}, first_fetch={settings.first_fetch}, "
            f"tlp_color={settings.tlp_color}, use_tlp_from_source={settings.use_tlp_from_source}, tags={settings.tags}, "
            f"create_relationships={settings.create_relationships}"
        )
        self._check_collections(settings.collections)
        state = self._restarted_if_changed(last_run or {})
        cursors: dict[str, Any] = {}
        indicators: list = []
        refusals: list[str] = []
        for collection_name in settings.collections:
            stored = state.get("last_fetch", {}).get(collection_name)
            demisto.debug(f"[fetch-indicators] collection={collection_name}, cursor={stored}, first_fetch={settings.first_fetch}")
            date_from = None if stored else settings.first_fetch_date()
            seen_keys = (state.get(self.BOUNDARY_KEYS_KEY) or {}).get(collection_name) or () if stored else ()
            try:
                apply_hunting_rules = self._client.hunting_rules_flag(collection_name, settings.hunting_rules)
            except ConnectionException as exc:
                refusals.append(f"The fetch of {collection_name} failed: {exc}.")
                cursors[collection_name] = stored or None
                if seen_keys:
                    self._boundary_keys[collection_name] = list(seen_keys)
                continue
            cursors[collection_name], entries = self._read(
                collection_name, stored or None, date_from, apply_hunting_rules, refusals, seen_keys
            )
            indicators.extend(entries)
            demisto.debug(f"[fetch-indicators] collection={collection_name} next cursor={cursors[collection_name]}")
        self._report(refusals, indicators)
        next_run = {
            "last_fetch": cursors,
            self.FIRST_FETCH_KEY: settings.first_fetch,
            self.HUNTING_RULES_KEY: bool(settings.hunting_rules),
        }
        if self._boundary_keys:
            next_run[self.BOUNDARY_KEYS_KEY] = self._boundary_keys
        # One value from several collections is one indicator: the entries of the run are merged.
        return next_run, IndicatorBuilder.merge(indicators)

    def _check_collections(self, names: list[str]) -> None:
        """Refuses retired names and the collections the feed builds no indicators from; grants are not checked here."""
        for name in names:
            CollectionSpec.refuse_retired(name)
        unsupported = [name for name in names if name not in COLLECTIONS]
        if unsupported:
            noun, pronoun = ("collection", "it") if len(unsupported) == 1 else ("collections", "them")
            raise DemistoException(
                f"The feed does not build indicators from {', '.join(unsupported)}; remove the {noun} from the instance "
                f"settings (the Group-IB Threat Intelligence integration fetches {pronoun} as incidents)."
            )

    def _restarted_if_changed(self, last_run: dict[str, Any]) -> dict[str, Any]:
        """The stored state, without its cursors when "Indicator first fetch" or "Hunting Rules" changed since it was stored."""
        first_fetch, hunting_rules = self._settings.first_fetch, self._settings.hunting_rules
        previous = last_run.get(self.FIRST_FETCH_KEY)
        previous_hunting = last_run.get(self.HUNTING_RULES_KEY)
        first_fetch_changed = previous is not None and previous != first_fetch
        hunting_changed = previous_hunting is not None and bool(previous_hunting) != hunting_rules
        if not first_fetch_changed and not hunting_changed:
            return last_run
        reason = (
            f"'Indicator first fetch' changed from {previous!r} to {first_fetch!r}"
            if first_fetch_changed
            else f"'Hunting Rules' changed from {bool(previous_hunting)} to {hunting_rules}"
        )
        demisto.info(
            f"[fetch-indicators] {reason}; dropping the stored seqUpdate cursors "
            "so every collection restarts from the first-fetch date."
        )
        return {**last_run, "last_fetch": {}}

    def _read(
        self,
        collection_name: str,
        cursor: Any,
        date_from: str | None,
        apply_hunting_rules: int | None,
        refusals: list[str],
        seen_keys: Iterable[str] = (),
    ) -> tuple[Any, list]:
        """The next cursor (the last page's, the stored one or sequence_list's) and the entries of the collection's pages."""
        builder = IndicatorBuilder(collection_name, self._settings)
        entries: list = []
        start_cursor = None
        if date_from is not None:
            try:
                start_cursor = self._client.start_cursor(collection_name, date_from, apply_hunting_rules)
            except ConnectionException as exc:
                refusals.append(f"{collection_name} is not fetched yet: {exc}.")
                return cursor, entries
        record_filter = self._settings.record_filter
        if record_filter.rules.get(collection_name):
            demisto.debug(f"[fetch-indicators] {collection_name}: filters {record_filter.describe(collection_name)}")
        pages: Any = None
        try:
            seq_update = cursor or start_cursor
            pages = self._client.update_feed(
                collection_name=collection_name,
                seq_update=seq_update,
                date_from=None if seq_update else date_from,
                apply_hunting_rules=apply_hunting_rules,
                limit=self._settings.limit,
                filter_params=record_filter.request_params(collection_name),
                seen_keys=seen_keys,
            )
            previous = seq_update_number(seq_update)
            for pages_read, portion in enumerate(pages, start=1):
                page_cursor = seq_update_number(portion.sequpdate)
                demisto.debug(
                    f"[fetch-indicators] Portion received: collection={collection_name}, seqUpdate={portion.sequpdate}, "
                    f"portion_size={portion.portion_size}, count={portion.count}"
                )
                if page_cursor is None or (
                    previous is not None and page_cursor <= previous and not isinstance(pages, BoundaryPages)
                ):
                    # ciaops asks for the next page from the cursor a page answers: an unchanged one repeats the page.
                    refusals.append(
                        f"Group-IB answered {collection_name} with a page whose seqUpdate does not advance; the "
                        "collection is read no further this run."
                    )
                    break
                cursor = previous = page_cursor
                entries.extend(builder.build(builder.parse(portion)))
                if pages_read >= self._settings.requests_count:
                    break
        except ConnectionException as exc:
            # A collection whose request fails does not hold back the others; the pages before the failure are kept and
            # the cursor stops after them.
            refusals.append(f"The fetch of {collection_name} failed: {exc}.")
        if isinstance(pages, BoundaryPages):
            self._boundary_keys[collection_name] = pages.seen_keys
            self._stalls.extend(pages.stalls)
        if cursor is None:
            # No page followed the start cursor from sequence_list: the next run starts there.
            cursor = start_cursor
        return cursor, entries

    def _report(self, refusals: list[str], indicators: list) -> None:
        """Fails the run when each collection failed or waits for a cursor and none gave indicators; else sets instance health."""
        if not refusals and not self._stalls:
            return
        message = " ".join(refusals + self._stalls)
        if len(refusals) == len(self._settings.collections) and not indicators:
            raise DemistoException(message)
        demisto.error(f"[fetch-indicators] {message}")
        demisto.updateModuleHealth(message, is_error=True)


class GetIndicatorsCommand:
    """gibti-get-indicators: the first ``limit`` indicators of a collection, or every indicator of one record."""

    # Records without observables (a compromised account without a C&C) add nothing: a command must not walk the
    # whole collection looking for some.
    MAX_PAGES = 5

    def __init__(self, client: Client, settings: Settings):
        self._client = client
        self._settings = settings

    def run(self, args: dict[str, Any]) -> list[CommandResults]:
        record_id, collection_name, limit = self._arguments(args)
        builder = IndicatorBuilder(collection_name, self._settings)
        entries = self._record_entries(builder, record_id) if record_id else self._sample_entries(builder, limit)
        if not entries:
            target = f"record {record_id!r} of {collection_name}" if record_id else collection_name
            return [CommandResults(readable_output=f"No indicators were found in {target}.")]
        return self._tables(builder.spec, IndicatorBuilder.merge(entries))

    def _arguments(self, args: dict[str, Any]) -> tuple[Any, str, int]:
        """The id, collection and limit; the limit is checked before the collection, with or without an id."""
        record_id, collection_name, raw_limit = args.get("id"), args.get("collection", ""), args.get("limit", "50")
        demisto.debug(f"[gibti-get-indicators] id={record_id}, collection={collection_name}, limit={raw_limit}")
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            raise DemistoException("Limit should be a number.")
        if limit <= 0:
            raise DemistoException("Limit should be greater than 0.")
        if limit > 50:
            raise DemistoException("Limit should be at most 50.")
        CollectionSpec.refuse_retired(collection_name)
        if collection_name not in COLLECTIONS:
            raise DemistoException("Unknown collection name; choose one of the listed collections.")
        return record_id, collection_name, limit

    def _sample_entries(self, builder: IndicatorBuilder, limit: int) -> list[dict]:
        """Every entry of the first ``limit`` observables and objects from the first-fetch date, duplicates kept for the merge."""
        collection_name = builder.collection_name
        apply_hunting_rules = self._client.hunting_rules_flag(collection_name, self._settings.hunting_rules)
        date_from = self._settings.first_fetch_date()
        try:
            seq_update = self._client.start_cursor(collection_name, date_from, apply_hunting_rules)
        except ConnectionException as exc:
            raise DemistoException(f"{collection_name} cannot be read yet: {exc}.") from None
        pages = self._refused_as_message(
            collection_name,
            self._client.update_feed(
                collection_name=collection_name,
                seq_update=seq_update,
                date_from=None if seq_update else date_from,
                apply_hunting_rules=apply_hunting_rules,
                limit=limit,
                filter_params=self._settings.record_filter.request_params(collection_name),
            ),
        )
        entries: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for pages_read, portion in enumerate(pages, start=1):
            page_entries = builder.build(builder.parse(portion))
            for entry in page_entries:
                key = (str(entry.get("type")), str(entry.get("value")))
                if key not in seen and len(seen) < limit:
                    seen.add(key)
                if key in seen:
                    entries.append(entry)
            demisto.debug(f"[gibti-get-indicators] Portion processed: built={len(page_entries)}, total={len(seen)}")
            if len(seen) >= limit:
                break
            if pages_read >= self.MAX_PAGES:
                demisto.debug(f"[gibti-get-indicators] Stopped after {pages_read} pages with {len(seen)} indicators")
                break
        return entries

    def _record_entries(self, builder: IndicatorBuilder, record_id: Any) -> list[dict]:
        """Every indicator of the record, whatever the limit: a threat report may name more of them."""
        not_found = DemistoException(f"No record with id {record_id!r} was found in {builder.collection_name}.")
        portion = self._record_page(builder, record_id, not_found)
        if portion is None:
            raise not_found
        parsed = builder.parse(portion)
        if not parsed:
            raise not_found
        return builder.build(parsed)

    @staticmethod
    def _refused_as_message(collection_name: str, pages: Iterable[Any]) -> Iterator[Any]:
        """The pages of a read; a failure while paging is raised as one message naming the collection."""
        try:
            yield from pages
        except ConnectionException as exc:
            raise DemistoException(f"The read of {collection_name} failed: {exc}.") from None

    def _record_page(self, builder: IndicatorBuilder, record_id: Any, not_found: DemistoException) -> Any:
        collection_name, spec = builder.collection_name, builder.spec
        if spec.id_query is not None:
            return self._first_page(collection_name, spec.id_query.format(id=record_id), spec.id_query_page_size)
        try:
            return self._client.record(collection_name, record_id)
        except NotFoundException:
            raise not_found from None
        except ConnectionException as exc:
            # A 403 may be a report Group-IB has not published, which its update feed tells apart from a key without
            # access to the collection.
            if not (str(exc).startswith("HTTP 403") and spec.checked_in_update_feed_on_refusal):
                raise
            try:
                return self._first_page(collection_name, f"id:{record_id}")
            except ConnectionException:
                # The update feed fails as well: the 403 stands.
                raise exc from None

    def _first_page(self, collection_name: str, query: str, limit: int = 1) -> Any:
        """The first page of the collection's update feed filtered by ``query``, or None."""
        pages = self._client.search(collection_name, query=query, limit=limit) or []
        return next((portion for portion in pages if portion is not None), None)

    def _tables(self, spec: CollectionSpec, entries: list[dict[str, Any]]) -> list[CommandResults]:
        """One War Room table per indicator type."""
        rows: dict[Any, list[dict[str, Any]]] = {}
        for entry in entries:
            raw_json = entry.get("rawJSON", {})
            xsoar_type = raw_json.get("type")
            if xsoar_type == FeedIndicatorType.CVE:
                raw_json.pop("gibsoftwaremixed", None)
            rows.setdefault(xsoar_type, []).append(raw_json)
        return [
            CommandResults(
                readable_output=tableToMarkdown(
                    f"{xsoar_type} indicators", type_rows, removeNull=True, headers=self._table_headers(spec, xsoar_type)
                ),
                raw_response=type_rows,
                ignore_auto_extract=True,
            )
            for xsoar_type, type_rows in rows.items()
        ]

    def _table_headers(self, spec: CollectionSpec, xsoar_type: Any) -> list[str]:
        """The columns of an indicator type: value, type, its fields in ``indicator_fields`` order, then the TLP."""
        fields: dict[str, str] = {}
        for type_key, type_spec in spec.types.items():
            # A type chosen per record names its types in its map and default.
            if type_spec == xsoar_type or (
                isinstance(type_spec, dict) and xsoar_type in (*type_spec.get("map", {}).values(), type_spec.get("default"))
            ):
                fields = spec.indicator_fields.get(type_key) or {}
                break
        return ["value", "type", *fields.values(), "trafficlightprotocol"]


class TestModuleCommand:
    """test-module: one authenticated request past the grants cache; "ok" when the API grants at least one collection."""

    def __init__(self, client: Client):
        self._client = client

    def run(self) -> str:
        if not self._client.granted_collections(refresh=True):
            return "No collections are available; ask Group-IB support to grant them."
        return "ok"


# The legacy gibtia-* name: it runs its gibti-* command and warns in the War Room.
COMMAND_ALIASES = {"gibtia-get-indicators": "gibti-get-indicators"}


def main():
    """Parses the instance settings, builds the client and runs the command."""
    indicator_collections = None
    try:
        params = demisto.params()
        username, password = Settings.credentials(params)
        indicator_collections = params.get("indicator_collections", [])
        settings = Settings.from_params(params)
        raw_command = demisto.command()
        command = COMMAND_ALIASES.get(raw_command, raw_command)
        if raw_command != command:
            return_warning(
                f"Command '{raw_command}' is deprecated. Use '{command}' in your playbooks and scripts instead.",
                exit=False,
            )
        demisto.debug(f"Command being called is {raw_command}, mapped to {command}")
        client = Client(
            base_url=settings.url,
            verify=settings.verify,
            proxy=settings.proxy,
            auth=(username, password),
            rate_limit_delay=settings.rate_limit_delay,
        )
        demisto.info("[main] TI Feed client created successfully")
        # Factories: a setting only some commands parse fails those commands alone.
        commands: dict[str, Callable[[], Any]] = {
            "test-module": lambda: return_results(TestModuleCommand(client).run()),
            "fetch-indicators": lambda: FetchIndicatorsCommand(client, settings.for_fetch()).execute(),
            "gibti-get-indicators": lambda: return_results(
                GetIndicatorsCommand(client, settings.for_command()).run(demisto.args())
            ),
        }
        commands[command]()
    except Exception as exc:
        # An expected failure (unknown id, obsolete collection, bad argument, a failed Group-IB request): the message is the
        # error. Anything else keeps its traceback.
        expected = isinstance(exc, DemistoException | ConnectionException)
        return_error(
            f"Failed to execute {demisto.command()} command.\n"
            f"Indicator collections: {indicator_collections}.\n"
            f"Error: {exc if expected else format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
