import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


""" IMPORTS """


import fnmatch
import hashlib
import html
import ipaddress
import json
import queue
import re
import string
import threading
import unicodedata
import time
import urllib.parse
from collections.abc import Callable, Iterable, Iterator
from copy import copy, deepcopy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from functools import cached_property, lru_cache, partial
from traceback import format_exc
from typing import Any, ClassVar, TypeGuard

from ciaops import Parser, ParserHelper, TICollections, TIPoller, TIRequestParams, Validator
from ciaops.exception import ConnectionException, InputException, NotFoundException
from ciaops.utils import RateLimiter
from dateparser import parse as dateparser_parse  # type: ignore[import-untyped]

""" CONSTANTS """

DBOT_VENDOR_NAME = "GroupIBTI"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Group-IB fills an unknown date with a placeholder (0001-01-01; 1976-01-01 on osi/vulnerability): no date of a record
# lies before this year.
FIRST_RECORD_YEAR = 1980
# An e-mail value that ends in a page asset's extension ("logo@2x.png") is a file name, not an address.
ASSET_ADDRESS_RE = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|ico|bmp|css|js)$", re.IGNORECASE)
CRYPTOCURRENCY_TYPE = "Cryptocurrency"


""" HELPERS """


def texts(value: Any) -> list[str]:
    """The texts a record value holds: nested lists flattened, blanks dropped, the first of equal texts kept."""
    found: dict[str, None] = {}

    def walk(item: Any) -> None:
        if isinstance(item, list):
            for element in item:
                walk(element)
        elif item not in (None, ""):
            text = str(item).strip()
            if text:
                found.setdefault(text, None)

    walk(value)
    return list(found)


def first_value(value: Any) -> Any:
    """The first non-empty element of a list (a number stays a number), or the value itself."""
    if isinstance(value, list):
        return next((item for item in value if item not in (None, "")), None)
    return None if value in (None, "") else value


def as_number(value: Any) -> float | None:
    """The first value as a float; None when it is missing, a boolean or no number."""
    number = first_value(value)
    if number is None or isinstance(number, bool):
        return None
    try:
        return float(number)
    except (TypeError, ValueError):
        return None


def json_text(value: Any) -> str:
    """A value as single-line JSON for the War Room and the context; ``str(value)`` when it cannot be serialized."""
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        return str(value)


def argument_values(args: dict, keys: Iterable[str], label: str, unique: bool = False) -> list[str]:
    """The stripped values of the first of ``keys`` that has any; ``unique`` drops repeated values."""
    for key in keys:
        values = [str(item).strip() for item in argToList(args.get(key)) if str(item).strip()]
        if values:
            return list(dict.fromkeys(values)) if unique else values
    raise DemistoException(f"Argument '{label}' is required.")


class CredentialsRefused(DemistoException):
    """Group-IB refused the instance's key: the whole command fails, not one value."""


def value_result(lookup: Callable[[str], CommandResults], value: str) -> CommandResults:
    """``lookup(value)``, or an error entry for that value alone; refused credentials fail the whole command."""
    try:
        return lookup(value)
    except CredentialsRefused:
        raise
    except DemistoException as exc:
        return CommandResults(
            entry_type=EntryType.ERROR, readable_output=str(exc), raw_response={"indicator": value, "error": str(exc)}
        )


# The verdict names of the War Room score tables, lowercase (CommonServerPython's scoreToReputation capitalizes them).
SCORE_NAMES = {
    Common.DBotScore.NONE: "unknown",
    Common.DBotScore.GOOD: "good",
    Common.DBotScore.SUSPICIOUS: "suspicious",
    Common.DBotScore.BAD: "bad",
}


def score_table(
    title: str,
    value: str,
    score: Any,
    reliability: Any = None,
    numerical_score: Any = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """The War Room table of a scoring or reputation result."""
    table_data = {"Indicator": value, "Score": SCORE_NAMES.get(score, score)}
    if reliability is not None:
        table_data["Reliability"] = reliability
    if numerical_score is not None:
        table_data["Numerical Score"] = numerical_score
    for label, extra_value in (extra or {}).items():
        if extra_value not in (None, "", []):
            table_data[label] = ", ".join(extra_value) if isinstance(extra_value, list) else extra_value
    return tableToMarkdown(title, table_data, removeNull=True)


""" COLLECTIONS """


@dataclass(frozen=True)
class CollectionSpec:
    """What the integration knows about one Group-IB collection; the defaults are those of a collection it does not read."""

    # The prefix of an incident's name; without its blanks, the GIBTI.<prefix> context root of a lookup.
    incident_prefix: str = ""
    # The record fields an incident's occurred time comes from: the first that holds a date.
    occurred_fields: tuple[str, ...] = ()
    # The nested objects an incident shows as grid fields, one row per element.
    grid_tables: tuple[str, ...] = ()
    # The narratives Group-IB writes in HTML, shown as text; html_when_marked_up only when the text holds markup, so a
    # description that quotes "<script>" keeps it.
    html_fields: tuple[str, ...] = ()
    html_when_marked_up: tuple[str, ...] = ()
    # The incident severity of a record without a graded evaluation and threat level.
    default_severity: int = IncidentSeverity.UNKNOWN
    # The scale the record's files are graded on; the worst file raises the incident severity.
    file_severities: dict[str, int] = field(default_factory=dict)
    # The incident severity of a record by its threatLevel, lowercase.
    threat_level_severities: dict[str, int] = field(default_factory=dict)
    # The flags (falsePositive, whitelist) that withdraw a record: it yields no indicator and, unless flagged groups go to
    # the pre-processing rule, no incident.
    dropped_record_flags: tuple[str, ...] = ()
    # What the API writes into the brand when there is none, lowercase: neither a tag nor part of an incident name.
    brand_markers: frozenset[str] = frozenset()
    # The API filters the collection by the customer's hunting rules on every request this integration sends (it never
    # sends apply_hunting_rules=0).
    server_scoped: bool = False
    # The fetch always asks the API for the hunting-rules filter.
    forces_hunting_rules: bool = False
    # The update feed takes df as a filter on the update position: a first fetch without a sequence_list cursor
    # starts from the date. Elsewhere df is ignored or filters on a record's own date, so a read by date starts at the
    # collection's oldest record.
    starts_from_date: bool = False
    # A dark web post (a Telegram, Discord or forum message): its text follows "Mask dark web post text".
    darkweb_post: bool = False
    # The update feed answers the lowest seqUpdate of a page rather than the highest, so a second page repeats records of
    # the first: a search reads one page and goes on from the highest of its records, and a fetch reads one page per run.
    cursor_from_items: bool = False
    # What names a record in the duplicate cache, after the collection.
    dedup_fields: tuple[str, ...] = ("id",)
    # How a lookup reads the record of an id: "get" (GET /{collection}/{id}), "route" (GET /{by_id_route}/{id}),
    # "id query" (the update feed with q=id:<id>), "text query" (with q=<id>) or "listings" (every record of the id).
    lookup_route: str = "get"
    by_id_route: str | None = None
    # The fields that tell apart the records a lookup id names ("listings").
    listing_keys: tuple[str, ...] = ()
    # GET by id answers 403 for a record Group-IB has not published; the update feed tells that apart from a key
    # without access to the collection.
    checks_update_feed_on_refusal: bool = False
    # The verdict of an observable a record names, unless its illegal score (compromised/spd) sets one. Evaluation
    # severity is the urgency of the event for the customer, never how malicious the observable is.
    verdict: int = Common.DBotScore.SUSPICIOUS
    # The indicator is a page on the victim's own site.
    victim_site: bool = False
    # The reputation commands that read the collection's records, the reliability a match lends a result, and the keys
    # a domain's records are parsed with.
    reputation_kinds: frozenset[str] = frozenset()
    reputation_reliability: str | None = None
    domain_reputation_keys: dict[str, str] | None = None
    # The record paths of the names and the TLP a reputation result reads; None for REPUTATION_CONTEXT_KEYS.
    reputation_context_keys: dict[str, str] | None = None
    # Whether the collection is in the default selection of "Collections that keep an IP at least Suspicious", and the days
    # after dateLastSeen its listing counts when "Suspicious IP listing recency (days)" is empty; None or 0 for any age.
    floor_by_default: bool = False
    floor_max_age_days: int | None = None
    # The observables of a record's "indicators" block: their types and attributes, and how they are read.
    indicator_types: dict[str, Any] = field(default_factory=dict)
    # The keys a record is parsed with (ciaops ParserHelper.find_by_template).
    mapping: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def of(cls, name: str) -> "CollectionSpec":
        return COLLECTIONS.get(name) or cls()

    @staticmethod
    def validate(name: str) -> None:
        """Refuse a name of RETIRED_COLLECTIONS, naming the collection to use instead when there is one (a DemistoException)."""
        if name in RETIRED_COLLECTIONS:
            replacement = RETIRED_COLLECTIONS[name]
            if replacement:
                raise DemistoException(f"Collection {name} is obsolete; use {replacement} instead.")
            raise DemistoException(f"Collection {name} is obsolete and has no replacement; do not select it.")

    @property
    def context_prefix(self) -> str:
        return f"GIBTI.{self.incident_prefix.replace(' ', '')}"

    def withdrawal_flags(self, record: dict) -> list[str]:
        """The dropped_record_flags the record carries."""
        return [flag for flag in self.dropped_record_flags if record.get(flag) is True]


# The evaluation block of the collections that grade their records (GIB Admiralty Code, GIB Credibility, GIB Reliability,
# GIB Severity, GIB TLP); malware/*, the actor profiles and the dark web posts carry none.
EVALUATION_KEYS = {
    "admiraltyCode": "evaluation.admiraltyCode",
    "credibility": "evaluation.credibility",
    "reliability": "evaluation.reliability",
    "severity": "evaluation.severity",
    "tlp": "evaluation.tlp",
}
# The observable of a suspicious_ip/* listing whose record carries an IPv4 address only.
SUSPICIOUS_IPV4_INDICATOR_KEYS = {
    "ipv4_ip": "ipv4.ip",
    "ipv4_asn": "ipv4.asn",
    "ipv4_country_name": "ipv4.countryName",
    "ipv4_country_code": "ipv4.countryCode",
    "ipv4_region": "ipv4.region",
    "ipv4_provider": "ipv4.provider",
}
SUSPICIOUS_IPV4_INDICATOR_TYPES = {
    "types": {"ipv4_ip": FeedIndicatorType.IP},
    "add_fields_types": {
        "ipv4_ip": {
            "ipv4_asn": "asn",
            "ipv4_country_name": "geocountry",
            "ipv4_country_code": "geocountrycode",
            "ipv4_region": "geolocation",
            "ipv4_provider": "organization",
        }
    },
}
# The observables of a threat report (hi/threat, apt/threat): its indicators[] array, element by element.
THREAT_REPORT_INDICATOR_TYPES = {
    "types": {
        "ipv4": FeedIndicatorType.IP,
        "ipv6": FeedIndicatorType.IP,
        "domain": FeedIndicatorType.Domain,
        "url": FeedIndicatorType.URL,
        "hashes_sha256": FeedIndicatorType.File,
        "email_address": FeedIndicatorType.Email,
        "email_sender_ip": FeedIndicatorType.IP,
    },
    # A report's file entry carries many hash kinds, most of them empty: each file is keyed by its SHA-256, else its
    # SHA-1, else its MD5, else its SHA-512.
    "value_fallbacks": {"hashes_sha256": ["hashes_sha1", "hashes_md5", "hashes_sha512"]},
    # The address and senderIp of an email-message entry; its serverIp is left out, since nothing says which side of
    # the exchange that server is on.
    "element_kinds": {"email_address": "email-message", "email_sender_ip": "email-message"},
    "add_fields_types": {
        "ipv4": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "ipv6": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "domain": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "url": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "hashes_sha256": {
            "name": "gibfilename",
            "hashes_md5": "md5",
            "hashes_sha1": "sha1",
            "hashes_sha256": "sha256",
            "hashes_sha512": "sha512",
            "size": "size",
            "malware_names": "malware_family",
            "threat_actor_names": "threat_actor_names",
        },
        "email_address": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "email_sender_ip": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
    },
}
# The observables of an open threat post: the IOCs Group-IB extracted from it under ``data``, apart from its e-mail addresses.
OPEN_THREAT_INDICATOR_TYPES = {
    "types": {
        "ip": FeedIndicatorType.IP,
        "domain": FeedIndicatorType.Domain,
        "file_sha256": FeedIndicatorType.File,
        "hash": FeedIndicatorType.File,
        "cve": FeedIndicatorType.CVE,
        "wallet": CRYPTOCURRENCY_TYPE,
    },
    # A file entry carries several hash kinds, most of them empty: each file is keyed by its SHA-256, else its SHA-1,
    # else its MD5, else its SHA-512. A standalone hash is a file known by that hash alone.
    "value_fallbacks": {"file_sha256": ["file_sha1", "file_md5", "file_sha512"]},
    # Each wallet list names its own chain.
    "per_element_fields": ("service_type",),
    "add_fields_types": {
        "ip": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "domain": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "file_sha256": {
            "file_name": "gibfilename",
            "file_md5": "md5",
            "file_sha1": "sha1",
            "file_sha256": "sha256",
            "file_sha512": "sha512",
            "file_size": "size",
            "malware_names": "malware_family",
            "threat_actor_names": "threat_actor_names",
        },
        "hash": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "cve": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
        "wallet": {"wallet_type": "service_type"},
    },
}
# The record attributes a reputation result takes its tags, malware families, threat actors and TLP from.
REPUTATION_CONTEXT_KEYS = {
    "malware_names": "malwareList.name",
    "threat_names": "threatList.name",
    "threat_actor_name": "threatActor.name",
    "tlp": "evaluation.tlp",
}
# The same names in a public post: the actors it names and the malware Group-IB extracted from it.
OPEN_THREAT_CONTEXT_KEYS = {
    "malware_names": "data.malware.name",
    "threat_actor_name": "threatActors.name",
    "tlp": "evaluation.tlp",
}

COLLECTIONS: dict[str, CollectionSpec] = {
    TICollections.COMPROMISED_ACCOUNT_GROUP: CollectionSpec(
        incident_prefix="Compromised Account Group",
        occurred_fields=("dateFirstSeen",),
        grid_tables=("events_table",),
        server_scoped=True,
        indicator_types={
            # Only the C&C URL, domain and IP become indicators: the client IP, ASN and geo next to them are the compromised
            # user's own network, never an IOC nor an attribute of one.
            "types": {
                "event_url": FeedIndicatorType.URL,
                "event_domain": FeedIndicatorType.Domain,
                "event_ipv4": FeedIndicatorType.IP,
            },
            # Each event names its own malware and actor: a C&C carries the attribution of the event it comes
            # from.
            "per_element_fields": ("malware_family", "threat_actor_names"),
            "add_fields_types": {
                "event_url": {
                    "malware_names": "malware_family",
                    "threat_actor_names": "threat_actor_names",
                },
                "event_domain": {
                    "malware_names": "malware_family",
                    "threat_actor_names": "threat_actor_names",
                },
                "event_ipv4": {
                    "malware_names": "malware_family",
                    "threat_actor_names": "threat_actor_names",
                },
            },
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "login",
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
            "portalLink": {
                "__concatenate": {"collection": TICollections.COMPROMISED_ACCOUNT_GROUP, "dynamic": "id"}
            },  # GIB Portal Link
            "events_table": {  # GIB Compromised Events Information Table
                "cnc": "events.cnc.cnc",
                "asn": "events.client.ipv4.asn",
                "city": "events.client.ipv4.city",
                "region": "events.client.ipv4.region",
                "provider": "events.client.ipv4.provider",
                "countryCode": "events.client.ipv4.countryCode",
                "countryName": "events.client.ipv4.countryName",
                "ip": "events.client.ipv4.ip",
                "malware": "events.malware.name",
                "threatActor": "events.threatActor.name",
                "sourceType": "events.source.type",
                "sourceLink": "events.source.id",
                # The compromised machine's host information (stealer logs).
                "userName": "events.additionalData.indexed.username",
                "pcName": "events.additionalData.indexed.pcname",
                "os": "events.additionalData.indexed.os_raw",
                "screen": "events.additionalData.indexed.screen",
                "locale": "events.additionalData.indexed.locale",
                "malwarePath": "events.additionalData.indexed.malware_path",
                "dateDetected": "events.dateDetected",
                "dateCompromised": "events.dateCompromised",
                "phone": "events.person.phone",
                "name": "events.person.name",
                "email": "events.person.email",
                "address": "events.person.address",
            },
            "dateFirstCompromised": "dateFirstCompromised",  # GIB Date First Compromised
            "dateLastCompromised": "dateLastCompromised",  # GIB Date Last Compromised
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "evaluation": EVALUATION_KEYS,
            "indicators": {  # observables and their attributes, read through indicator_types
                "event_url": "events.cnc.url",
                "event_domain": "events.cnc.domain",
                "event_ipv4": "events.cnc.ipv4.ip",
                "malware_names": "events.malware.name",
                "threat_actor_names": "events.threatActor.name",
            },
            # GIB Source: the source type of each event.
            "source_type": "events.source.type",
        },
    ),
    TICollections.COMPROMISED_BANK_CARD_GROUP: CollectionSpec(
        incident_prefix="Compromised Card Group",
        occurred_fields=("dateFirstCompromised", "dateFirstSeen"),
        grid_tables=("threatActor", "compromised_events", "malware"),
        server_scoped=True,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "cardInfo.number",
            "issuer": "cardInfo.issuer.issuer",  # GIB Card Issuer
            "issuer_country_code": "cardInfo.issuer.countryCode",  # GIB Card Issuer Country Code
            "number": "cardInfo.number",  # GIB Card Number
            "type": "cardInfo.type",  # GIB Card Type
            "card_category": "cardInfo.category",  # GIB Card Category
            "payment_system": "cardInfo.system",  # GIB Payment System
            "id": "id",  # GIB ID
            "sourceType": "sourceType",  # GIB Source
            # CVV and expiry live in the events; the record-level keys are filled from them when absent.
            "cvv": "cardInfo.cvv",  # no incident field: the events table keeps each event's CVV unless Mask card data clears it
            "validThru": "cardInfo.validThru",  # GIB Card Valid Thru
            "compromised_events": {  # GIB Compromised Events Table
                "cvv": "events.cardInfo.cvv",
                "valid_thru_date": "events.cardInfo.validThruDate",
                "valid_thru": "events.cardInfo.validThru",
                "client_ip": "events.client.ipv4.ip",
                "cnc": "events.cnc.cnc",
                "cnc_ip": "events.cnc.ipv4.ip",
                "threat_actor_name": "events.threatActor.name",
                "source_type": "events.source.type",
                "source_link": "events.source.id",
                "date_detected": "events.dateDetected",
                "date_compromised": "events.dateCompromised",
                "victim_phone": "events.owner.phone",
                "victim_name": "events.owner.name",
                "malware": "events.malware.name",
            },
            "malware": {  # GIB Malware Table
                "id": "malware.id",
                "name": "malware.name",
            },
            "portalLink": {
                "__concatenate": {"collection": TICollections.COMPROMISED_BANK_CARD_GROUP, "dynamic": "id"}
            },  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "dateFirstCompromised": "dateFirstCompromised",  # GIB Date First Compromised
            "dateLastCompromised": "dateLastCompromised",  # GIB Date Last Compromised
            "threatActor": {  # GIB Threat Actors Table
                "id": "threatActor.id",
                "name": "threatActor.name",
            },
        },
    ),
    TICollections.COMPROMISED_MASKED_CARD: CollectionSpec(
        incident_prefix="Compromised Masked Card",
        occurred_fields=("dateDetected", "dateCompromised"),
        server_scoped=True,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "cardInfo.number",
            "id": "id",  # GIB ID
            "baseName": "baseName",  # GIB Base Name
            "card_bin": "cardInfo.bin",  # GIB Card BIN
            "cvv": "cardInfo.cvv",  # GIB CVV
            "card_dump": "cardInfo.dump",  # GIB Card Dump
            "issuer_country_code": "cardInfo.issuer.countryCode",  # GIB Card Issuer Country Code
            "issuer_country_name": "cardInfo.issuer.countryName",  # GIB Card Issuer Country Name
            "issuer": "cardInfo.issuer.issuer",  # GIB Card Issuer
            "number": "cardInfo.number",  # GIB Card Number
            "card_pin": "cardInfo.pin",  # GIB Card PIN
            "payment_system": "cardInfo.system",  # GIB Payment System
            "card_category": "cardInfo.category",  # GIB Card Category
            "type": "cardInfo.type",  # GIB Card Type
            "validThru": "cardInfo.validThru",  # GIB Card Valid Thru
            "validThruDate": "cardInfo.validThruDate",  # GIB Card Valid Thru Date
            "client_asn": "client.ipv4.asn",  # GIB Client ASN
            "client_city": "client.ipv4.city",  # GIB Client City
            "client_region": "client.ipv4.region",  # GIB Client Region
            "client_provider": "client.ipv4.provider",  # GIB Client Provider
            "client_country_code": "client.ipv4.countryCode",  # GIB Client Country Code
            "client_country_name": "client.ipv4.countryName",  # GIB Client Country Name
            "client_ip": "client.ipv4.ip",  # GIB Client IP
            "cnc": "cnc.cnc",  # GIB CNC
            "cnc_domain": "cnc.domain",  # GIB CNC Domain
            "cnc_ip": "cnc.ipv4.ip",  # GIB CNC IP
            "cnc_asn": "cnc.ipv4.asn",  # GIB CNC ASN
            "cnc_city": "cnc.ipv4.city",  # GIB CNC City
            "cnc_region": "cnc.ipv4.region",  # GIB CNC Region
            "cnc_provider": "cnc.ipv4.provider",  # GIB CNC Provider
            "cnc_country_code": "cnc.ipv4.countryCode",  # GIB CNC Country Code
            "cnc_country_name": "cnc.ipv4.countryName",  # GIB CNC Country Name
            "cnc_url": "cnc.url",  # GIB CNC URL
            "dateDetected": "dateDetected",  # GIB Date of Detection
            "dateCompromised": "dateCompromised",  # GIB Date Compromised
            "evaluation": {**EVALUATION_KEYS, "ttl": "evaluation.ttl"},  # GIB TTL
            "isDump": "isDump",  # GIB Is Dump
            "isExpired": "isExpired",  # GIB Is Expired
            "isMasked": "isMasked",  # GIB Is Masked
            "malware_name": "malware.name",  # GIB Malware Name
            "malware_id": "malware.id",  # GIB Malware ID
            "malware_stix_guid": "malware.stixGuid",  # GIB Malware STIX GUID
            "address": "owner.address",  # GIB Address
            "owner_birthday": "owner.birthday",  # GIB Owner Birthday
            "owner_country_code": "owner.countryCode",  # GIB Owner Country Code
            "email": "owner.email",  # GIB Email
            "owner_name": "owner.name",  # GIB Person
            "owner_passport": "owner.passport",  # GIB Owner Passport
            "phone": "owner.phone",  # Phone Number
            "owner_state": "owner.state",  # GIB Owner State
            "owner_tax_number": "owner.taxNumber",  # GIB Owner Tax Number
            "owner_zip": "owner.zip",  # GIB Owner ZIP
            "owner_city": "owner.city",  # GIB Owner City
            "price_currency": "price.currency",  # GIB Price Currency
            "price_value": "price.value",  # GIB Price Value
            "sourceLink": "sourceLink",  # GIB Source Link
            "sourceType": "sourceType",  # GIB Source
            "threat_actor_name": "threatActor.name",  # GIB Threat Actor Name
            "threat_actor_id": "threatActor.id",  # GIB Threat Actor ID
            "threat_actor_stix_guid": "threatActor.stixGuid",  # GIB Threat Actor STIX GUID
            "threat_actor_is_apt": "threatActor.isAPT",  # GIB Threat Actor is APT
            "threat_actor_country": "threatActor.country",  # GIB Threat Actor Country
            "track": "track",  # GIB Track
            "portalLink": {
                "__concatenate": {"collection": TICollections.COMPROMISED_MASKED_CARD, "dynamic": "id"}
            },  # GIB Portal Link
        },
    ),
    TICollections.COMPROMISED_BREACHEDDB: CollectionSpec(
        incident_prefix="Data Breach",
        occurred_fields=("uploadTime",),
        grid_tables=("record_details",),
        server_scoped=True,
        forces_hunting_rules=True,
        dedup_fields=("id", "leakName", "uploadTime"),
        lookup_route="route",
        by_id_route="compromised/breached",
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "id",
            "id": "id",  # GIB ID
            "leakName": "leakName",  # GIB Leak Name
            # GIB Threat Actor Name holds the leak's publishers (``authors``), no attribution.
            "threat_actor_name": "authors",  # GIB Threat Actor Name
            "passwords": "password",  # GIB Passwords
            "description": "description",  # Description
            "emails": "email",  # GIB Emails
            "emailDomains": "addInfo.emailDomain",  # GIB Email Domains
            # The leaked attributes differ per leak, so the whole block becomes a key/value table.
            "record_details": "addInfo",  # GIB Breach Record Details
            "portalLink": "set_generated_portal_link",  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
            "leakPublished": "leakPublished",  # GIB Leak Published
            "updateTime": "updateTime",  # GIB Update Time
            "uploadTime": "uploadTime",  # GIB Upload Time
        },
    ),
    TICollections.COMPROMISED_SPD: CollectionSpec(
        incident_prefix="Compromised SPD",
        occurred_fields=("firstSeenAt", "lastSeenAt", "createdAt"),
        grid_tables=("events", "sources", "malware", "threatActor"),
        server_scoped=True,
        indicator_types={
            # Only a crypto wallet becomes an indicator here; the feed integration files every other type (bank account
            # numbers, mobile numbers, bank cards, IBANs, e-mail addresses, QR payment strings and payment details of type
            # Unknown) under the custom "GIB Suspicious Payment Detail" type.
            "types": {
                "value_value": {
                    "field": "type",
                    "map": {"Cryptocurrency Wallet": CRYPTOCURRENCY_TYPE},
                    "default": None,
                },
            },
            "add_fields_types": {
                "value_value": {
                    "type": "spd_type",
                    "service_type": "service_type",
                    "illegal_score": "illegal_score",
                    "tlp": "trafficlightprotocol",
                    "malware_names": "malware_family",
                    "threat_actor_names": "threat_actor_names",
                },
            },
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "type",
            "id": "id",  # GIB ID
            "type": "type",  # GIB SPD Type
            "serviceType": "serviceType",  # GIB SPD Service Type
            "country": "country",
            "ownerName": "ownerName",  # GIB SPD Owner Name
            "illegalScore": "illegalScore",  # GIB SPD Illegal Score
            "value": "value.value",  # GIB SPD Value
            "source_type": "sources.type",  # GIB Source
            "createdAt": "createdAt",  # GIB Date Created At
            "firstSeenAt": "firstSeenAt",  # GIB Date First Seen
            "lastSeenAt": "lastSeenAt",  # GIB Date Last Seen
            "portalLink": {"__concatenate": {"collection": TICollections.COMPROMISED_SPD, "dynamic": "id"}},  # GIB Portal Link
            "events": {  # GIB SPD Events Table
                "compromisedAt": "events.compromisedAt",
                "detectedAt": "events.detectedAt",
                "sourceName": "events.source.name",
                "sourceType": "events.source.type",
                "illegalScore": "events.illegalScore",
                "malwareId": "events.malware.id",
                "malwareName": "events.malware.name",
                "threatActorId": "events.threatActor.id",
                "threatActorName": "events.threatActor.name",
            },
            "sources": {  # GIB SPD Sources Table
                "name": "sources.name",
                "type": "sources.type",
            },
            "malware": {  # GIB SPD Malware Table
                "id": "malware.id",
                "name": "malware.name",
            },
            "threatActor": {  # GIB SPD Threat Actor Table
                "id": "threatActor.id",
                "name": "threatActor.name",
            },
            "evaluation": {**EVALUATION_KEYS, "ttl": "evaluation.ttl"},  # GIB TTL
            "indicators": {  # observables and their attributes, read through indicator_types
                "value_value": "value.value",
                "type": "type",
                "service_type": "serviceType",
                "illegal_score": "illegalScore",
                "tlp": "evaluation.tlp",
                "malware_names": "malware.name",
                "threat_actor_names": "threatActor.name",
            },
        },
    ),
    TICollections.COMPROMISED_ACCESS: CollectionSpec(
        # A marketplace listing of access to one of the customer's hosts. Nothing in it is an indicator: the target is
        # the customer's own host and the cnc block is the shop's storefront, kept as shop attribution.
        incident_prefix="Compromised Access",
        occurred_fields=("dateDetected", "dateCompromised"),
        html_fields=("archiveFiles",),
        server_scoped=True,
        lookup_route="id query",
        mapping={  # GIB Source:sourceType (the shop), severity:systemSeverity
            "name": "target.host",
            "id": "id",  # GIB ID
            "accessType": "type",  # GIB Access Type
            "dateCompromised": "dateCompromised",  # GIB Date Compromised
            "dateDetected": "dateDetected",  # GIB Date of Detection
            "priceValue": "price.value",  # GIB Price Value
            "priceCurrency": "price.currency",  # GIB Price Currency
            "malware_name": "malware.name",  # GIB Malware Name
            "malware_id": "malware.id",  # GIB Malware ID
            "sourceType": "sourceInfo.name",
            "seller": "sourceInfo.seller",  # GIB Seller
            "sourceExternalId": "sourceInfo.externalId",
            "sourceDbId": "sourceDbId",
            "sourceLink": "sourceLink",
            "shop": {  # GIB Shop Domain, GIB Shop URL, GIB Shop IP: the storefront the listing is sold on
                "domain": "cnc.domain",
                "url": "cnc.url",
                "ip": "cnc.ipv4.ip",
                "port": "cnc.port",
                "protocol": "cnc.proto",
                "asn": "cnc.ipv4.asn",
                "provider": "cnc.ipv4.provider",
                "countryCode": "cnc.ipv4.countryCode",
                "region": "cnc.ipv4.region",
                "city": "cnc.ipv4.city",
            },
            "target": {  # GIB Target Host, GIB Target Domain, GIB Device OS, GIB Device Browser, GIB Device Name
                "host": "target.host",
                "domain": "target.domain",
                "ip": "target.ipv4",
                "provider": "target.provider",
                "os": "target.device.os",
                "browser": "target.device.browser",
                "userAgent": "target.device.userAgent",
                "systemName": "target.device.systemName",
                "country": "target.geo.country",
                "region": "target.geo.region",
                "state": "target.geo.state",
                "city": "target.geo.city",
            },
            "archiveFiles": "rawData",  # GIB Archive File List: the file listing of the offered archive, as text
            "portalLink": {"__concatenate": {"collection": TICollections.COMPROMISED_ACCESS, "dynamic": "id"}},  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
        },
    ),
    TICollections.COMPROMISED_MESSENGER: CollectionSpec(
        # One Telegram post the customer's hunting rules matched. The post is free text that can hold anything, so it
        # is no source of indicators; the poster and the channel are research pivots, never infrastructure.
        incident_prefix="Darkweb Telegram",
        occurred_fields=("postDate",),
        grid_tables=("edits",),
        default_severity=IncidentSeverity.HIGH,
        server_scoped=True,
        darkweb_post=True,
        lookup_route="id query",
        mapping={  # GIB Source:sourceType (the collection), severity:systemSeverity
            "name": "chatStat.title",
            "id": "id",  # GIB ID
            "messageId": "messageId",
            "text": "message",  # GIB Post Text
            "translation": "translatedMessage",  # GIB Post Translation
            "postDate": "messageTs",  # GIB Post Date
            "editDate": "lastEditTs",  # GIB Post Edit Date
            "deletedDate": "deleted",  # GIB Post Deleted Date
            "isReply": "isReply",
            "highlight": "highlight",
            "author": {  # GIB Author ID, GIB Author Handle, GIB Author Name
                "id": "author.id",
                "handle": "author.userName",
                "firstName": "author.firstName",
                "lastName": "author.lastName",
                "type": "author.type",
            },
            "channel": {  # GIB Channel ID, Name, Title, Description, Subscribers, Messages
                "id": "chatStat.id",
                "name": "chatStat.name",
                "title": "chatStat.title",
                "description": "chatStat.about",
                "type": "chatStat.type",
                "messages": "chatStat.messageNum",
                "subscribers": "chatStat.userNum",
                "firstMessageDate": "chatStat.firstMessageDate",
                "lastMessageDate": "chatStat.lastMessageDate",
            },
            "attachment": {"name": "media.name", "type": "media.type", "size": "media.size"},  # GIB Attachment Name, Type, Size
            "edits": {  # GIB Post Edits Table
                "dateDetected": "edits.detected_date",
                "text": "edits.message",
                "translation": "edits.message_translated",
            },
            "reply": {  # GIB Reply Text
                "id": "repliedMessage.id",
                "messageId": "repliedMessage.messageId",
                "postDate": "repliedMessage.messageTs",
                "text": "repliedMessage.message",
                "translation": "repliedMessage.translatedMessage",
                "authorId": "repliedMessage.author.id",
            },
            # GIB Portal Link
            "portalLink": {"__concatenate": {"collection": TICollections.COMPROMISED_MESSENGER, "dynamic": "id"}},
        },
    ),
    TICollections.COMPROMISED_DISCORD: CollectionSpec(
        # One Discord post the customer's hunting rules matched, handled as a Telegram post is.
        incident_prefix="Darkweb Discord",
        occurred_fields=("postDate",),
        grid_tables=("edits",),
        default_severity=IncidentSeverity.HIGH,
        server_scoped=True,
        darkweb_post=True,
        lookup_route="id query",
        mapping={  # GIB Source:sourceType (the collection), severity:systemSeverity
            "name": "channel.name",
            "id": "id",  # GIB ID
            "text": "text",  # GIB Post Text
            "translation": "translation",  # GIB Post Translation
            "postDate": "ts",  # GIB Post Date
            "deletedDate": "deleted",  # GIB Post Deleted Date
            "highlight": "highlight",
            "ruleIds": "rules",
            # GIB Author ID, GIB Author Handle
            "author": {"id": "author.id", "name": "author.name", "discriminator": "author.discriminator"},
            "channel": {  # GIB Channel ID, GIB Channel Name, GIB Server Name, GIB Channel Subscribers, GIB Channel Messages
                "id": "channel.id",
                "name": "channel.name",
                "server": "channel.server",
                "messages": "channel.stat.messageNum",
                "subscribers": "channel.stat.userNum",
                "firstMessageDate": "channel.stat.firstMessageDate",
                "lastMessageDate": "channel.stat.lastMessageDate",
            },
            "attachment": {"name": "media.name", "type": "media.type", "size": "media.size"},  # GIB Attachment Name, Type, Size
            "edits": {  # GIB Post Edits Table
                "date": "edits.date",
                "dateDetected": "edits.detected_date",
                "text": "edits.content",
                "translation": "edits.content_translated",
            },
            "reply": {  # GIB Reply Text
                "id": "repliedMessage.id",
                "text": "repliedMessage.text",
                "translation": "repliedMessage.translation",
                "authorName": "repliedMessage.author.name",
            },
            # GIB Portal Link
            "portalLink": {"__concatenate": {"collection": TICollections.COMPROMISED_DISCORD, "dynamic": "id"}},
        },
    ),
    TICollections.DARKWEB_FORUMS: CollectionSpec(
        # One forum post the customer's hunting rules matched. The body arrives three times: the post, a cleaned copy
        # and the text of its images. A fetch reads the collection through BoundaryPages, one page per run.
        incident_prefix="Darkweb Forum",
        occurred_fields=("postDate", "uploadTime"),
        default_severity=IncidentSeverity.HIGH,
        server_scoped=True,
        darkweb_post=True,
        cursor_from_items=True,
        lookup_route="id query",
        mapping={  # GIB Source:sourceType (the collection), severity:systemSeverity
            "name": "topic",
            "id": "id",  # GIB ID
            "text": "message",  # GIB Post Text
            "clearText": "clear_message",
            "imageText": "ocr_analyser",  # GIB Image Text
            "messageHash": "message_hash",  # GIB Data Hash
            "messageLength": "message_len",
            "languages": "lang",  # GIB Languages
            "messageLanguages": "message_lang",
            "topic": "topic",  # GIB Title
            "topicHash": "topicHash",
            "threadId": "thread_id",  # GIB Thread ID
            "firstPost": "first_post",
            "forum": "forum",  # GIB Forum
            "forumSection": "forum_path_tree",  # GIB Forum Section
            "domain": "domain",
            "url": "url",  # GIB Post URL
            "author": {"handle": "nickname"},  # GIB Author Handle
            "categories": "categories",  # GIB Categories
            "postDate": "datetime",  # GIB Post Date
            "uploadTime": "uploadTime",  # GIB Upload Time
            "alertUpdateDate": "updateDatetimeAlert",
            "portalLink": {"__concatenate": {"collection": TICollections.DARKWEB_FORUMS, "dynamic": "id"}},  # GIB Portal Link
        },
    ),
    TICollections.OSI_GIT_REPOSITORY: CollectionSpec(
        incident_prefix="Git Leak",
        occurred_fields=("dateDetected",),
        grid_tables=("files",),
        file_severities={
            "green": IncidentSeverity.LOW,
            "orange": IncidentSeverity.MEDIUM,
            "red": IncidentSeverity.HIGH,
            "yellow": IncidentSeverity.LOW,
        },
        server_scoped=True,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
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
                "severity": "files.evaluation.severity",
            },
            "portalLink": {"__concatenate": {"collection": TICollections.OSI_GIT_REPOSITORY, "dynamic": "id"}},  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
        },
    ),
    TICollections.OSI_PUBLIC_LEAK: CollectionSpec(
        incident_prefix="Public Leak",
        occurred_fields=("created",),
        grid_tables=("linkList", "matches"),
        server_scoped=True,
        forces_hunting_rules=True,
        lookup_route="id query",
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "hash",
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
            "portalLink": {"__concatenate": {"collection": TICollections.OSI_PUBLIC_LEAK, "dynamic": "id"}},  # GIB Portal Link
            "matches": "matches",  # GIB Matches Table
            "evaluation": EVALUATION_KEYS,
        },
    ),
    TICollections.OSI_VULNERABILITY: CollectionSpec(
        incident_prefix="OSI Vulnerability",
        occurred_fields=("datePublished",),
        grid_tables=("cpeTable", "affectedSoftware"),
        html_when_marked_up=("description",),
        verdict=Common.DBotScore.BAD,
        indicator_types={
            "types": {
                "id": FeedIndicatorType.CVE,
            },
            "add_fields_types": {
                "id": {
                    "cvss_score": "cvss",
                    "cvss_vector": "cvss_vector",
                    "merged_cvss": "merged_cvss",
                    "merged_cvss_vector": "merged_cvss_vector",
                    "epss": "epss",
                    "epss_percentile": "epss_percentile",
                    "has_exploit": "has_exploit",
                    "exploit_count": "exploit_count",
                    "seen_in_the_wild": "seen_in_the_wild",
                    "description": "description",
                    "software_mixed": "gibsoftwaremixed",
                    "dateModified": "cvemodified",
                    "datePublished": "published",
                    "severity": "severity",
                    "tlp": "trafficlightprotocol",
                }
            },
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "id",
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "dateModified": "dateModified",  # GIB Date Modified
            "datePublished": "datePublished",  # GIB Date Published
            "id": "id",  # GIB ID
            "bulletinFamily": "bulletinFamily",  # GIB Bulletin Family
            "description": "description",  # Description
            "extDescription": "extDescription",  # GIB Extended Description
            "reporter": "reporter",  # GIB Reporter
            "hasExploit": "hasExploit",  # GIB Has Exploit
            "exploitCount": "exploitCount",  # GIB Exploit Count
            "seenInTheWild": "seenInTheWild",  # GIB Seen In The Wild
            "epssScore": "epss.epss",  # GIB EPSS
            "epssPercentile": "epss.percentile",  # GIB EPSS Percentile
            "provider": "provider",  # GIB Provider
            "href": "href",  # GIB Href
            "mergedCvss": "mergedCvss",  # GIB Merged Cvss
            "type": "type",  # GIB Vulnerability Type
            "portalLink": {"__concatenate": {"collection": TICollections.OSI_VULNERABILITY, "dynamic": "id"}},  # GIB Portal Link
            "cpeTable": {  # GIB CPE Table
                "product": "cpeTable.product",
                "string": "cpeTable.string",
                "string23": "cpeTable.string23",
                "type": "cpeTable.type",
                "vendor": "cpeTable.vendor",
                "version": "cpeTable.version",
                "update": "cpeTable.update",
            },
            "affectedSoftware": {  # GIB Affected Software Table
                "name": "affectedSoftware.name",
                "operator": "affectedSoftware.operator",
                "version": "affectedSoftware.version",
            },
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
            "evaluation": EVALUATION_KEYS,
            "indicators": {  # observables and their attributes, read through indicator_types
                "severity": "evaluation.severity",
                "tlp": "evaluation.tlp",
                "id": "id",
                "cvss_score": "cvss.score",
                "cvss_vector": "cvss.vector",
                "merged_cvss": "mergedCvss",
                "merged_cvss_vector": "mergedCvssVector",
                "epss": "epss.epss",
                "epss_percentile": "epss.percentile",
                "has_exploit": "hasExploit",
                "exploit_count": "exploitCount",
                "seen_in_the_wild": "seenInTheWild",
                "description": "description",
                "dateModified": "dateModified",
                "datePublished": "datePublished",
                "software_mixed": {
                    "names": "softwareMixed.softwareName",
                    "types": "softwareMixed.softwareType",
                    "versions": "softwareMixed.softwareVersion",
                },
            },
        },
    ),
    TICollections.ATTACKS_DDOS: CollectionSpec(
        incident_prefix="Attacks DDoS",
        occurred_fields=("dateBegin", "dateReg"),
        server_scoped=True,
        starts_from_date=True,
        indicator_types={
            "types": {
                "cnc_url": FeedIndicatorType.URL,
                "cnc_domain": FeedIndicatorType.Domain,
                "cnc_ipv4_ip": FeedIndicatorType.IP,
            },
            "add_fields_types": {
                "cnc_url": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
                "cnc_domain": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
                "cnc_ipv4_ip": {
                    "cnc_ipv4_asn": "asn",
                    "cnc_ipv4_country_name": "geocountry",
                    "cnc_ipv4_country_code": "geocountrycode",
                    "cnc_ipv4_region": "geolocation",
                    "cnc_ipv4_provider": "organization",
                    "malware_names": "malware_family",
                    "threat_actor_names": "threat_actor_names",
                },
            },
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "target.ipv4.ip",
            "id": "id",  # GIB ID
            "dateBegin": "dateBegin",  # GIB DDOS Date Begin
            "dateEnd": "dateEnd",  # GIB DDOS Date End
            "dateReg": "dateReg",  # GIB DDOS Date Registration
            "duration": "duration",  # GIB DDOS Duration
            "protocol": "protocol",  # GIB DDOS Protocol
            "source": "source",  # GIB DDOS Source
            "type": "type",  # GIB DDOS Type
            "malwareName": "malware.name",  # GIB Malware Name
            "portalLink": {"__concatenate": {"collection": TICollections.ATTACKS_DDOS, "dynamic": "id"}},  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
            "cnc": {
                "cnc": "cnc.cnc",  # GIB CNC
                "domain": "cnc.domain",  # GIB CNC Domain
                "port": "cnc.port",  # GIB CNC Port
                "url": "cnc.url",  # GIB CNC URL
            },
            "threatActor": {
                "id": "threatActor.id",  # GIB Threat Actor ID
                "name": "threatActor.name",  # GIB Threat Actor Name
                "isAPT": "threatActor.isAPT",  # GIB Threat Actor is APT
            },
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
            "requestData": {
                "link": "requestData.link",  # GIB DDOS Request Data Link
                "headersHash": "requestData.headersHash",  # GIB DDOS Request Headers Hash
                "body": "requestData.body",  # GIB DDOS Request Body
                "bodyHash": "requestData.bodyHash",  # GIB DDOS Request Body Hash
            },
            "indicators": {  # observables and their attributes, read through indicator_types
                "cnc_url": "cnc.url",
                "cnc_domain": "cnc.domain",
                "cnc_ipv4_ip": "cnc.ipv4.ip",
                "cnc_ipv4_asn": "cnc.ipv4.asn",
                "cnc_ipv4_country_name": "cnc.ipv4.countryName",
                "cnc_ipv4_country_code": "cnc.ipv4.countryCode",
                "cnc_ipv4_region": "cnc.ipv4.region",
                "cnc_ipv4_provider": "cnc.ipv4.provider",
                "malware_names": "malware.name",
                "threat_actor_names": "threatActor.name",
            },
        },
    ),
    TICollections.ATTACKS_DEFACE: CollectionSpec(
        incident_prefix="Attacks Deface",
        occurred_fields=("date",),
        victim_site=True,
        reputation_kinds=frozenset({"ip", "domain"}),
        reputation_reliability=DBotScoreReliability.B,
        domain_reputation_keys={
            "date": "date",
            "targetDomain": "targetDomain",
            "url": "url",
            "targetIp": "targetIp.ip",
            **REPUTATION_CONTEXT_KEYS,
        },
        indicator_types={
            # Only the defaced URL is an observable: targetDomain / targetIp are the victim and stay on the incident. The
            # defacer handle groups defacements and is no attribution, as in the feed and the reputation commands.
            "types": {"url": FeedIndicatorType.URL},
            "add_fields_types": {"url": {}},
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "url",
            "id": "id",  # GIB ID
            "mirrorLink": "mirrorLink",  # GIB Mirror Link
            "providerDomain": "providerDomain",  # GIB Provider Domain
            "siteUrl": "siteUrl",  # GIB Deface Site URL
            "source": "source",  # GIB Deface Source
            "targetDomain": "targetDomain",  # GIB Target Domain
            "targetDomainProvider": "targetDomainProvider",  # GIB Target Domain Provider
            "date": "date",  # GIB Deface Date
            "contacts": "contacts",  # GIB Deface Contacts
            "portalLink": "portalLink",  # GIB Portal Link, see IncidentBuilder.portal_link
            "evaluation": EVALUATION_KEYS,
            "targetIp": {
                "asn": "targetIp.asn",  # GIB Target ASN
                "city": "targetIp.city",  # GIB Target City
                "countryCode": "targetIp.countryCode",  # GIB Country Code
                "countryName": "targetIp.countryName",  # GIB Country Name
                "ip": "targetIp.ip",  # GIB Target IP
                "provider": "targetIp.provider",  # GIB Target Provider
                "region": "targetIp.region",  # GIB Target Region
            },
            "threatActor": {
                "id": "threatActor.id",  # GIB Threat Actor ID
                "name": "threatActor.name",  # GIB Threat Actor Name
                "isAPT": "threatActor.isAPT",  # GIB Threat Actor is APT
            },
            "indicators": {  # observables and their attributes, read through indicator_types
                "url": "url",
                "threat_actor_names": "threatActor.name",
            },
        },
    ),
    TICollections.ATTACKS_PHISHING_GROUP: CollectionSpec(
        incident_prefix="Phishing Group",
        occurred_fields=("detected", "updated"),
        grid_tables=("phishing_ip", "phishing_kit_table"),
        dropped_record_flags=("falsePositive", "whitelist"),
        brand_markers=frozenset({"index of", "not specified"}),
        lookup_route="id query",
        indicator_types={
            # Only the phishing URLs are observables: the domain and the hosting IP are often shared infrastructure (a
            # free blog host, a cloud provider's address) and stay on the incident.
            "types": {
                "url": FeedIndicatorType.URL,
            },
            "add_fields_types": {
                "url": {"brand": "brand", "objective": "category", "threat_actor_names": "threat_actor_names"},
            },
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "domain",  # the group key, never null; the incident name adds a real brand
            "id": "id",  # GIB ID
            # Group-IB's quality flags: a flagged record is dropped or handed to the pre-processing rule (dropped_record_flags).
            "falsePositive": "falsePositive",
            "whitelist": "whitelist",
            "brand": "brand",  # GIB Phishing Brand
            "phishing_urls": "phishing.url",  # GIB Phishing URLs
            "objective": "objective",  # GIB Phishing Objectives
            "source": "source",  # GIB Phishing Sources
            "portalLink": {
                "__concatenate": {"collection": TICollections.ATTACKS_PHISHING_GROUP, "dynamic": "id"}
            },  # GIB Portal Link
            "blocked": "date.blocked",  # GIB Phishing Date Blocked
            "added": "date.added",  # GIB Phishing Date Added
            "detected": "date.detected",  # GIB Phishing Date Detected
            "updated": "date.updated",  # GIB Phishing Date Updated
            "domainInfo": {
                "domain": "domainInfo.domain",  # GIB Phishing Domain
                "domainPuny": "domainInfo.domainPuny",  # GIB Phishing Domain Puny
                "expirationDate": "domainInfo.expirationDate",  # GIB Phishing Domain Expiration Date
                "registrar": "domainInfo.registrar",  # GIB Phishing Registrar
            },
            "evaluation": EVALUATION_KEYS,
            "phishing_ip": {  # GIB Phishing IP Table
                "ip": "ip.ip",
                "countryCode": "ip.countryCode",
                "countryName": "ip.countryName",
                "provider": "ip.provider",
            },
            "threatActor": {
                "id": "threatActor.id",  # GIB Threat Actor ID
                "name": "threatActor.name",  # GIB Threat Actor Name
            },
            "phishing_kit_table": {  # GIB Phishing Kit Table
                "name": "phishing.phishingKit.name",
                "email": "phishing.phishingKit.email",
            },
            "indicators": {  # observables and their attributes, read through indicator_types
                "url": "phishing.url",
                "brand": "brand",
                "objective": "objective",
                "threat_actor_names": "threatActor.name",
            },
        },
    ),
    TICollections.ATTACKS_PHISHING_KIT: CollectionSpec(
        incident_prefix="Phishing Kit",
        occurred_fields=("dateFirstSeen",),
        grid_tables=("downloadedFrom",),
        starts_from_date=True,
        indicator_types={
            # The kit's hash, the SHA-256 of its archive, is its primary indicator.
            "types": {"emails": FeedIndicatorType.Email, "hash": FeedIndicatorType.File},
            "add_fields_types": {"emails": {}, "hash": {}},
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "hash",
            "id": "id",  # GIB ID
            "hash": "hash",  # GIB Data Hash
            "dateDetected": "dateDetected",  # GIB Date of Detection
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "source": "source",  # GIB Phishing Kit Source
            "emails": "emails",  # GIB Phishing Kit Email
            "targetBrand": "targetBrand",  # the brand the kit targets, read by the brands filter
            "portalLink": {
                "__concatenate": {"collection": TICollections.ATTACKS_PHISHING_KIT, "dynamic": "id"}
            },  # GIB Portal Link
            "downloadedFrom": {  # GIB Downloaded From Table
                "date": "downloadedFrom.date",
                "url": "downloadedFrom.url",
                "phishingUrl": "downloadedFrom.phishingUrl",
                "domain": "downloadedFrom.domain",
                "fileName": "downloadedFrom.fileName",
            },
            "evaluation": EVALUATION_KEYS,
            "indicators": {"emails": "emails", "hash": "hash"},  # observables, read through indicator_types
        },
    ),
    TICollections.SUSPICIOUS_IP_TOR_NODE: CollectionSpec(
        incident_prefix="Suspicious IP Tor Node",
        occurred_fields=("dateLastSeen", "dateFirstSeen"),
        lookup_route="text query",
        floor_by_default=True,
        indicator_types=SUSPICIOUS_IPV4_INDICATOR_TYPES,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "ipv4.ip",
            "id": "id",  # GIB ID
            "source": "source",  # GIB IP Source
            "countryName": "ipv4.countryName",  # GIB Country Name
            "countryCode": "ipv4.countryCode",  # GIB Country Code
            "asn": "ipv4.asn",  # GIB ASN
            "provider": "ipv4.provider",  # GIB Provider
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            # Consensus snapshots of the relay; IncidentBuilder.shape reads the newest one's flags, AS and country
            # and drops the snapshots.
            "nodes": "nodes",
            "portalLink": {
                "__concatenate": {"collection": TICollections.SUSPICIOUS_IP_TOR_NODE, "dynamic": "id"}
            },  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
            "indicators": SUSPICIOUS_IPV4_INDICATOR_KEYS,  # observables and their attributes, read through indicator_types
        },
    ),
    TICollections.SUSPICIOUS_IP_OPEN_PROXY: CollectionSpec(
        incident_prefix="Suspicious IP Open Proxy",
        occurred_fields=("dateLastSeen", "dateFirstSeen"),
        dedup_fields=("id", "port"),
        lookup_route="listings",
        listing_keys=("id", "port"),
        floor_by_default=True,
        indicator_types=SUSPICIOUS_IPV4_INDICATOR_TYPES,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "ipv4.ip",
            "id": "id",  # GIB ID
            "countryName": "ipv4.countryName",  # GIB Country Name
            "countryCode": "ipv4.countryCode",  # GIB Country Code
            "asn": "ipv4.asn",  # GIB ASN
            "provider": "ipv4.provider",  # GIB Provider
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "dateDetected": "dateDetected",  # GIB Date of Detection
            "port": "port",  # GIB Proxy Port
            "source": "source",  # GIB Proxy Source
            "sources": "sources",  # GIB Proxy Sources
            "type": "type",  # GIB Proxy Type
            "portalLink": {
                "__concatenate": {"collection": TICollections.SUSPICIOUS_IP_OPEN_PROXY, "dynamic": "id"}
            },  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
            "indicators": SUSPICIOUS_IPV4_INDICATOR_KEYS,  # observables and their attributes, read through indicator_types
        },
    ),
    TICollections.SUSPICIOUS_IP_SOCKS_PROXY: CollectionSpec(
        incident_prefix="Suspicious IP Socks Proxy",
        occurred_fields=("dateFirstSeen",),
        lookup_route="text query",
        floor_by_default=True,
        indicator_types=SUSPICIOUS_IPV4_INDICATOR_TYPES,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "ipv4.ip",
            "id": "id",  # GIB ID
            "countryName": "ipv4.countryName",  # GIB Country Name
            "countryCode": "ipv4.countryCode",  # GIB Country Code
            "asn": "ipv4.asn",  # GIB ASN
            "provider": "ipv4.provider",  # GIB Provider
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "dateDetected": "dateDetected",  # GIB Date of Detection
            "source": "source",  # GIB Socks Proxy Source
            "portalLink": {
                "__concatenate": {"collection": TICollections.SUSPICIOUS_IP_SOCKS_PROXY, "dynamic": "id"}
            },  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
            "indicators": SUSPICIOUS_IPV4_INDICATOR_KEYS,  # observables and their attributes, read through indicator_types
        },
    ),
    TICollections.SUSPICIOUS_IP_VPN: CollectionSpec(
        incident_prefix="Suspicious IP VPN",
        occurred_fields=("dateFirstSeen",),
        floor_by_default=True,
        indicator_types=SUSPICIOUS_IPV4_INDICATOR_TYPES,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "ipv4.ip",
            "id": "id",  # GIB ID
            "countryName": "ipv4.countryName",  # GIB Country Name
            "countryCode": "ipv4.countryCode",  # GIB Country Code
            "asn": "ipv4.asn",  # GIB ASN
            "provider": "ipv4.provider",  # GIB Provider
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "sources": "sources",  # GIB VPN Sources
            "names": "names",  # GIB VPN Names
            "types": "types",  # GIB VPN Types
            "portalLink": {"__concatenate": {"collection": TICollections.SUSPICIOUS_IP_VPN, "dynamic": "id"}},  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
            "indicators": SUSPICIOUS_IPV4_INDICATOR_KEYS,  # observables and their attributes, read through indicator_types
        },
    ),
    TICollections.SUSPICIOUS_IP_SCANNER: CollectionSpec(
        incident_prefix="Suspicious IP Scanner",
        occurred_fields=("dateFirstSeen",),
        floor_by_default=True,
        indicator_types={
            # A scanner record carries ipv4 or ipv6, never both.
            "types": {
                "ipv4_ip": FeedIndicatorType.IP,
                "ipv6_ip": FeedIndicatorType.IP,
            },
            "add_fields_types": {
                "ipv4_ip": {
                    "ipv4_asn": "asn",
                    "ipv4_country_name": "geocountry",
                    "ipv4_country_code": "geocountrycode",
                    "ipv4_region": "geolocation",
                    "ipv4_provider": "organization",
                },
                "ipv6_ip": {
                    "ipv6_asn": "asn",
                    "ipv6_country_name": "geocountry",
                    "ipv6_country_code": "geocountrycode",
                    "ipv6_region": "geolocation",
                    "ipv6_provider": "organization",
                },
            },
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "ipv4.ip",
            "id": "id",  # GIB ID
            "countryName": "ipv4.countryName",  # GIB Country Name
            "countryCode": "ipv4.countryCode",  # GIB Country Code
            "asn": "ipv4.asn",  # GIB ASN
            "provider": "ipv4.provider",  # GIB Provider
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "portalLink": {
                "__concatenate": {"collection": TICollections.SUSPICIOUS_IP_SCANNER, "dynamic": "id"}
            },  # GIB Portal Link
            "categories": "categories",  # GIB Scanner Categories
            "sources": "sources",  # GIB Scanner Sources
            "evaluation": EVALUATION_KEYS,
            "indicators": {  # observables and their attributes, read through indicator_types
                "ipv4_ip": "ipv4.ip",
                "ipv4_asn": "ipv4.asn",
                "ipv4_country_name": "ipv4.countryName",
                "ipv4_country_code": "ipv4.countryCode",
                "ipv4_region": "ipv4.region",
                "ipv4_provider": "ipv4.provider",
                "ipv6_ip": "ipv6.ip",
                "ipv6_asn": "ipv6.asn",
                "ipv6_country_name": "ipv6.countryName",
                "ipv6_country_code": "ipv6.countryCode",
                "ipv6_region": "ipv6.region",
                "ipv6_provider": "ipv6.provider",
            },
        },
    ),
    TICollections.MALWARE_CNC: CollectionSpec(
        incident_prefix="Malware CNC",
        occurred_fields=("dateFirstSeen", "dateDetected", "dateLastSeen"),
        grid_tables=("threatActor", "malwareList"),
        default_severity=IncidentSeverity.HIGH,
        verdict=Common.DBotScore.BAD,
        indicator_types={
            # The IP attributes (ASN, geo) belong to the IP entries only; a URL or domain entry carries the attribution alone.
            "types": {
                "url": FeedIndicatorType.URL,
                "domain": FeedIndicatorType.Domain,
                "ipv4_ip": FeedIndicatorType.IP,
                "ipv6_ip": FeedIndicatorType.IP,
            },
            "add_fields_types": {
                "url": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
                "domain": {"malware_names": "malware_family", "threat_actor_names": "threat_actor_names"},
                "ipv4_ip": {
                    "ipv4_asn": "asn",
                    "country_name": "geocountry",
                    "ipv4_country_code": "geocountrycode",
                    "ipv4_region": "geolocation",
                    "ipv4_provider": "organization",
                    "malware_names": "malware_family",
                    "threat_actor_names": "threat_actor_names",
                },
                "ipv6_ip": {
                    "ipv6_asn": "asn",
                    "ipv6_country_name": "geocountry",
                    "ipv6_country_code": "geocountrycode",
                    "ipv6_region": "geolocation",
                    "ipv6_provider": "organization",
                    "malware_names": "malware_family",
                    "threat_actor_names": "threat_actor_names",
                },
            },
        },
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "cnc",
            "id": "id",  # GIB ID
            "cnc": "cnc",  # GIB CNC URL
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "dateDetected": "dateDetected",  # GIB Date of Detection
            "domain": "domain",  # GIB Malware CNC Domain
            "platform": "platform",  # the platform the malware runs on, read by the platforms filter
            "malwareList": {  # GIB Malware Table
                "id": "malwareList.id",
                "name": "malwareList.name",
            },
            "threatActor": {  # GIB Threat Actors Table
                "id": "threatActor.id",
                "name": "threatActor.name",
            },
            "indicators": {  # observables and their attributes, read through indicator_types
                "url": "url",
                "domain": "domain",
                "ipv4_ip": "ipv4.ip",
                "ipv4_asn": "ipv4.asn",
                "country_name": "ipv4.countryName",
                "ipv4_country_code": "ipv4.countryCode",
                "ipv4_region": "ipv4.region",
                "ipv4_provider": "ipv4.provider",
                "ipv6_ip": "ipv6.ip",
                "ipv6_asn": "ipv6.asn",
                "ipv6_country_name": "ipv6.countryName",
                "ipv6_country_code": "ipv6.countryCode",
                "ipv6_region": "ipv6.region",
                "ipv6_provider": "ipv6.provider",
                "malware_names": "malwareList.name",
                "threat_actor_names": "threatActor.name",
            },
        },
    ),
    TICollections.MALWARE_MALWARE: CollectionSpec(
        incident_prefix="Malware",
        occurred_fields=("updatedAt",),
        grid_tables=("taList",),
        html_fields=("description", "shortDescription"),
        threat_level_severities={"low": IncidentSeverity.LOW, "medium": IncidentSeverity.MEDIUM, "high": IncidentSeverity.HIGH},
        verdict=Common.DBotScore.BAD,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
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
            "portalLink": {"__concatenate": {"collection": TICollections.MALWARE_MALWARE, "dynamic": "id"}},  # GIB Portal Link
            "sourceCountry": "sourceCountry",  # GIB Malware Source Countries
            "platform": "platform",  # GIB Malware Platforms
            "threatLevel": "threatLevel",  # GIB Threat Level
            "taList": {  # GIB Threat Actors Table
                "id": "taList.id",
                "name": "taList.name",
            },
        },
    ),
    TICollections.HI_THREAT: CollectionSpec(
        incident_prefix="GIB Cybercriminal Threat Report",
        occurred_fields=("createdAt",),
        grid_tables=("forumsAccounts", "files"),
        html_fields=("description",),
        checks_update_feed_on_refusal=True,
        verdict=Common.DBotScore.BAD,
        indicator_types=THREAT_REPORT_INDICATOR_TYPES,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "threatActor.name",
            "threatActor": {
                "country": "threatActor.country",  # GIB Threat Actor Country
                "id": "threatActor.id",  # GIB Threat Actor ID
                "isAPT": "threatActor.isAPT",  # GIB Threat Actor is APT
                "name": "threatActor.name",  # GIB Threat Actor Name
            },
            "evaluation": EVALUATION_KEYS,
            "forumsAccounts": {  # GIB Cybercriminal Forums Table
                "nickname": "forumsAccounts.nickname",
                "url": "forumsAccounts.url",
            },
            "id": "id",  # GIB ID
            "title": "title",  # GIB Cybercriminal Threat Title
            "description": "description",  # GIB Cybercriminal Threat Description
            "expertise": "expertise",  # GIB Cybercriminal Expertises
            "regions": "regions",  # GIB Cybercriminal Regions
            "labels": "labels",  # GIB Cybercriminal Threat Labels
            "countries": "countries",  # GIB Cybercriminal Threat Countries
            "sectors": "sectors",  # GIB Cybercriminal Sectors
            "reportNumber": "reportNumber",  # GIB Report Number
            "report_type": "type",  # GIB Report Type
            "sources": "sources",  # GIB Threat Sources
            "targeted_companies": "targetedCompany",  # GIB Targeted Companies
            "targeted_partners_and_clients": "targetedPartnersAndClients",  # GIB Targeted Partners And Clients
            "target_domains": "targetDomain",  # GIB Target Domains
            "files": {  # GIB Threat Files Table (files attached to the report)
                "name": "files.name",
                "mime": "files.mime",
                "size": "files.size",
                "hash": "files.hash",
            },
            "createdAt": "createdAt",  # GIB Date Created At
            "datePublished": "datePublished",  # the publication date, read by the max_age_days filter
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "portalLink": {"__concatenate": {"collection": TICollections.HI_THREAT, "dynamic": "id"}},  # GIB Portal Link
            "indicators": {  # observables and their attributes, read through indicator_types
                "ipv4": "indicators.params.ipv4",
                "ipv6": "indicators.params.ipv6",
                "domain": "indicators.params.domain",
                "url": "indicators.params.url",
                "hashes_md5": "indicators.params.hashes.md5",
                "name": "indicators.params.name",
                "hashes_sha1": "indicators.params.hashes.sha1",
                "hashes_sha256": "indicators.params.hashes.sha256",
                "hashes_sha512": "indicators.params.hashes.sha512",
                "size": "indicators.params.size",
                "element_type": "indicators.type",
                "email_address": "indicators.params.address",
                "email_sender_ip": "indicators.params.senderIp",
                "malware_names": "malwareList.name",
                "threat_actor_names": "threatActor.name",
            },
        },
    ),
    TICollections.HI_THREAT_ACTOR: CollectionSpec(
        incident_prefix="GIB Cybercriminal Threat Actor Profile",
        occurred_fields=("createdAt",),
        grid_tables=("reports",),
        html_fields=("description",),
        checks_update_feed_on_refusal=True,
        verdict=Common.DBotScore.BAD,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "name",
            "id": "id",  # GIB ID
            "aliases": "aliases",  # GIB Cybercriminal Threat Actor Aliases
            "description": "description",  # GIB Cybercriminal Threat Actor Description
            "isAPT": "isAPT",  # GIB Threat Actor is APT
            "hasIocs": "hasIocs",  # whether the actor has linked indicators, read by the with_iocs_only filter
            "threat_actor_name": "name",  # GIB Threat Actor Name
            "threat_actor_id": "id",  # GIB Threat Actor ID, which the postprocessing playbook looks the actor up by
            "expertise": "stat.expertise",  # GIB Cybercriminal Expertises
            "regions": "stat.regions",  # GIB Cybercriminal Regions
            "sectors": "stat.sectors",  # GIB Cybercriminal Sectors
            "malware": "stat.malware",  # GIB Cybercriminal Malware
            "portalLink": {"__concatenate": {"collection": TICollections.HI_THREAT_ACTOR, "dynamic": "id"}},  # GIB Portal Link
            "reports": "stat.reports",  # GIB Cybercriminal Threat Actor Reports Table, see IncidentBuilder.shape
            "createdAt": "createdAt",  # GIB Date Created At
            "updatedAt": "updatedAt",  # GIB Date Updated At
            "dateFirstSeen": "stat.dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "stat.dateLastSeen",  # GIB Date Last Seen
        },
    ),
    TICollections.APT_THREAT_ACTOR: CollectionSpec(
        incident_prefix="Nation-State Cybercriminals Threat Actor Profile",
        occurred_fields=("createdAt",),
        grid_tables=("reports",),
        html_fields=("description",),
        checks_update_feed_on_refusal=True,
        verdict=Common.DBotScore.BAD,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "name",
            "id": "id",  # GIB ID
            "aliases": "aliases",  # GIB Nation-State Cybercriminals Threat Actor Aliases
            "country": "country",  # GIB Nation-State Cybercriminals Threat Actor Country
            "description": "description",  # GIB Nation-State Cybercriminals Threat Actor Description
            "goals": "goals",  # GIB Nation-State Cybercriminals Threat Actor Goals
            "isAPT": "isAPT",  # GIB Threat Actor is APT
            "hasIocs": "hasIocs",  # whether the actor has linked indicators, read by the with_iocs_only filter
            "labels": "labels",  # GIB Nation-State Cybercriminals Threat Actor Labels
            "threat_actor_name": "name",  # GIB Threat Actor Name
            "threat_actor_id": "id",  # GIB Threat Actor ID, which the postprocessing playbook looks the actor up by
            "roles": "roles",  # GIB Nation-State Cybercriminals Threat Actor Roles
            "cve": "stat.cve",  # GIB Nation-State Cybercriminals Threat Actor CVE
            "expertise": "stat.expertise",  # GIB Nation-State Cybercriminals Expertises
            "malware": "stat.malware",  # GIB Nation-State Cybercriminals Malware
            "regions": "stat.regions",  # GIB Nation-State Cybercriminals Regions
            "sectors": "stat.sectors",  # GIB Nation-State Cybercriminals Sectors
            "portalLink": {"__concatenate": {"collection": TICollections.APT_THREAT_ACTOR, "dynamic": "id"}},  # GIB Portal Link
            "reports": "stat.reports",  # GIB Nation-State Cybercriminals Threat Actor Reports Table, see IncidentBuilder.shape
            "createdAt": "createdAt",  # GIB Date Created At
            "dateFirstSeen": "stat.dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "stat.dateLastSeen",  # GIB Date Last Seen
            "updatedAt": "updatedAt",  # GIB Date Updated At
        },
    ),
    TICollections.APT_THREAT: CollectionSpec(
        incident_prefix="Nation-State Cybercriminals Threat Report",
        occurred_fields=("createdAt",),
        grid_tables=("forumsAccounts", "files"),
        html_fields=("description",),
        checks_update_feed_on_refusal=True,
        verdict=Common.DBotScore.BAD,
        reputation_kinds=frozenset({"ip", "domain"}),
        reputation_reliability=DBotScoreReliability.A,
        indicator_types=THREAT_REPORT_INDICATOR_TYPES,
        mapping={  # GIB Source:sourceType, severity:systemSeverity
            "name": "threatActor.name",
            "id": "id",  # GIB ID
            "title": "title",  # GIB Nation-State Cybercriminals Threat Title
            "countries": "countries",  # GIB Nation-State Cybercriminals Threat Countries
            "description": "description",  # GIB Nation-State Cybercriminals Threat Description
            "expertise": "expertise",  # GIB Nation-State Cybercriminals Threat Expertises
            "labels": "labels",  # GIB Nation-State Cybercriminals Threat Actor Labels
            "langs": "langs",  # GIB Nation-State Cybercriminals Threat Langs
            "regions": "regions",  # GIB Nation-State Cybercriminals Threat Regions
            "reportNumber": "reportNumber",  # GIB Nation-State Cybercriminals Threat Report Number
            "sectors": "sectors",  # GIB Nation-State Cybercriminals Threat Sectors
            "report_type": "type",  # GIB Report Type
            "sources": "sources",  # GIB Threat Sources
            "targeted_companies": "targetedCompany",  # GIB Targeted Companies
            "targeted_partners_and_clients": "targetedPartnersAndClients",  # GIB Targeted Partners And Clients
            "target_domains": "targetDomain",  # GIB Target Domains
            "files": {  # GIB Threat Files Table (files attached to the report)
                "name": "files.name",
                "mime": "files.mime",
                "size": "files.size",
                "hash": "files.hash",
            },
            "portalLink": {"__concatenate": {"collection": TICollections.APT_THREAT, "dynamic": "id"}},  # GIB Portal Link
            "createdAt": "createdAt",  # GIB Date Created At
            "dateFirstSeen": "dateFirstSeen",  # GIB Date First Seen
            "dateLastSeen": "dateLastSeen",  # GIB Date Last Seen
            "datePublished": "datePublished",  # GIB Date Published
            "threatActor": {
                "country": "threatActor.country",  # GIB Threat Actor Country
                "id": "threatActor.id",  # GIB Threat Actor ID
                "isAPT": "threatActor.isAPT",  # GIB Threat Actor is APT
                "name": "threatActor.name",  # GIB Threat Actor Name
            },
            "evaluation": EVALUATION_KEYS,
            "forumsAccounts": {  # GIB Nation-State Cybercriminal Forums Table
                "nickname": "forumsAccounts.nickname",
                "url": "forumsAccounts.url",
            },
            "indicators": {  # observables and their attributes, read through indicator_types
                "ipv4": "indicators.params.ipv4",
                "ipv6": "indicators.params.ipv6",
                "domain": "indicators.params.domain",
                "url": "indicators.params.url",
                "hashes_md5": "indicators.params.hashes.md5",
                "name": "indicators.params.name",
                "hashes_sha1": "indicators.params.hashes.sha1",
                "hashes_sha256": "indicators.params.hashes.sha256",
                "hashes_sha512": "indicators.params.hashes.sha512",
                "size": "indicators.params.size",
                "element_type": "indicators.type",
                "email_address": "indicators.params.address",
                "email_sender_ip": "indicators.params.senderIp",
                "malware_names": "malwareList.name",
                "threat_actor_names": "threatActor.name",
            },
        },
    ),
    # The reputation commands read the collection directly; the fetch does not read it (the feed does).
    TICollections.IOC_PRIMARY: CollectionSpec(
        verdict=Common.DBotScore.BAD,
        reputation_kinds=frozenset({"ip", "domain", "url", "file"}),
        reputation_reliability=DBotScoreReliability.A,
        reputation_context_keys={
            "malware_names": "malwareList.name",
            "threat_names": "threatList.name",
            "threat_actor_name": "threatActorList.name",
            "tlp": "evaluation.tlp",
        },
    ),
    TICollections.IOC_COMMON: CollectionSpec(
        verdict=Common.DBotScore.BAD,
        reputation_kinds=frozenset({"file"}),
        reputation_reliability=DBotScoreReliability.A,
    ),
    TICollections.HI_OPEN_THREATS: CollectionSpec(
        # A public post about a threat, from a security blog or a social network, with the IOCs Group-IB extracted
        # from it. Public-tier OSINT: its observables are worth watching, not proven malicious.
        incident_prefix="Open Threat",
        occurred_fields=("dateDetected", "createdAt"),
        html_when_marked_up=("text",),
        lookup_route="id query",
        reputation_kinds=frozenset({"ip", "domain"}),
        reputation_reliability=DBotScoreReliability.B,
        domain_reputation_keys={
            "detected": "detected",
            "title": "title",
            "link": "link",
            "source": "source",
            "createdAt": "createdAt",
            **OPEN_THREAT_CONTEXT_KEYS,
        },
        reputation_context_keys=OPEN_THREAT_CONTEXT_KEYS,
        indicator_types=OPEN_THREAT_INDICATOR_TYPES,
        mapping={  # GIB Source:sourceType (Blog or Social Network), severity:systemSeverity
            "name": "title",
            "id": "id",  # GIB ID
            "title": "title",  # GIB Title
            "text": "text",  # GIB Post Text
            "url": "link",  # GIB Post URL
            "sourceName": "source",  # GIB Source Name
            "sourceType": "sourceType",
            "author": {  # GIB Author ID, GIB Author Handle, GIB Author Name, GIB Author Profile URL
                "id": "author.userId",
                "handle": "author.screenName",
                "name": "author.name",
                "profileUrl": "author.profileUrl",
                "reposted": "author.reposted",
            },
            "createdAt": "createdAt",  # GIB Date Created At
            "dateDetected": "dateDetected",  # GIB Date of Detection
            "updatedAt": "updatedAt",  # GIB Date Updated At
            "threat_actor_name": "threatActors.name",  # GIB Threat Actor Name
            "threat_actor_id": "threatActors.id",  # GIB Threat Actor ID
            "malware_name": "data.malware.name",  # GIB Malware Name
            "countryName": "data.countries.country",  # GIB Country Name
            "tags": "data.tags",  # GIB Tags
            "cveIds": "data.cve.id",  # GIB CVE IDs
            "huntingRuleIds": "data.rules",  # GIB Hunting Rule IDs
            "companyTags": "data.companyTags",  # GIB Company Tags
            "portalLink": {"__concatenate": {"collection": TICollections.HI_OPEN_THREATS, "dynamic": "id"}},  # GIB Portal Link
            "evaluation": EVALUATION_KEYS,
            "indicators": {  # observables and their attributes, read through indicator_types
                "ip": "data.ip.ip",
                "domain": "data.domains.value",
                "file_sha256": "data.files.hashes.sha256",
                "file_sha1": "data.files.hashes.sha1",
                "file_md5": "data.files.hashes.md5",
                "file_sha512": "data.files.hashes.sha512",
                "file_name": "data.files.name",
                "file_size": "data.files.size",
                "hash": "data.hashes.value",
                "cve": "data.cve.id",
                "email": "data.emails",
                "wallet": "data.cryptoWallets.wallets",
                "wallet_type": "data.cryptoWallets.walletType",
                "malware_names": "data.malware.name",
                "threat_actor_names": "threatActors.name",
            },
        },
    ),
}

# Collection names the pack refuses, with the collection to use instead (None: there is none).
RETIRED_COLLECTIONS: dict[str, str | None] = {
    "compromised/breached": TICollections.COMPROMISED_BREACHEDDB,
    TICollections.COMPROMISED_MULE: TICollections.COMPROMISED_SPD,
    "malware/targeted_malware": TICollections.MALWARE_MALWARE,
    "compromised/masked_cards": TICollections.COMPROMISED_MASKED_CARD,
    "compromised/bank_card": TICollections.COMPROMISED_BANK_CARD_GROUP,
    "compromised/card": TICollections.COMPROMISED_BANK_CARD_GROUP,
    "compromised/account": TICollections.COMPROMISED_ACCOUNT_GROUP,
    "attacks/phishing": TICollections.ATTACKS_PHISHING_GROUP,
    "bp/phishing": None,
    "bp/phishing_kit": None,
    "compromised/imei": None,
}


""" FILTERS """


SEVERITY_RANKS = {"green": 1, "orange": 2, "red": 3, "low": 1, "medium": 2, "high": 3}
SEVERITY_OPTIONS = ("Low", "Medium", "High")
# The file grades of osi/git_repository: gray and yellow rank with green, as Low.
FILE_SEVERITY_RANKS = {"gray": 1, "yellow": 1, "green": 1, "orange": 2, "red": 3}


def record_value(record: dict, path: str) -> Any:
    """The value under a dotted ``path`` of a parsed record; a key of a list of rows is read across the rows."""
    value: Any = record
    for key in path.split("."):
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list):
            value = [row.get(key) for row in value if isinstance(row, dict)]
        else:
            return None
    return value


def values_at(*paths: str) -> Callable[[dict], list[str]]:
    """A reader of the texts under the first of ``paths`` that holds any."""

    def read(record: dict) -> list[str]:
        for path in paths:
            found = texts(record_value(record, path))
            if found:
                return found
        return []

    return read


def all_values_at(*paths: str) -> Callable[[dict], list[str]]:
    """A reader of the texts under every one of ``paths``."""

    def read(record: dict) -> list[str]:
        return texts([record_value(record, path) for path in paths])

    return read


def http_status(exc: Exception) -> str | None:
    """The HTTP status of a failed request: from ciaops' "HTTP <code>" text, or from the code that exhausted its retries."""
    found = re.match(r"HTTP (\d{3})", str(exc)) or re.search(r"too many (\d{3}) error responses", str(exc))
    return found.group(1) if found else None


def seq_update_number(value: Any) -> int | None:
    """A stored or served seqUpdate as a number: an int, a float or a string of digits; None otherwise."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def known_date(value: Any) -> Any:
    """``value``, or None when it is the placeholder the API writes for "no date"."""
    placeholder = re.match(r"\s*(\d{4})-\d{1,2}-\d{1,2}(?!\d)", value) if isinstance(value, str) else None
    return None if placeholder and int(placeholder.group(1)) < FIRST_RECORD_YEAR else value


def number_at(*paths: str, scale: float = 1.0) -> Callable[[dict], float | None]:
    """A reader of the number under the first of ``paths`` that holds one, times ``scale``."""

    def read(record: dict) -> float | None:
        for path in paths:
            number = as_number(record_value(record, path))
            if number is not None:
                return number * scale
        return None

    return read


def cvss_at(*pairs: tuple[str, str]) -> Callable[[dict], float | None]:
    """A reader of the first known score of ``(score, vector)`` paths; 0 with no vector (or "NONE") is unknown."""

    def read(record: dict) -> float | None:
        for score_path, vector_path in pairs:
            number = as_number(record_value(record, score_path))
            vector = first_value(record_value(record, vector_path))
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
            labels = name.strip().strip(".").split(".")
            found.extend(".".join(labels[i:]) for i in range(len(labels)))
        return found

    return read


def rank_at(*paths: str, ranks: dict[str, int] | None = None) -> Callable[[dict], int]:
    """A reader of the highest severity rank among a record's values by ``ranks`` (SEVERITY_RANKS by default); unrated is 1."""

    def read(record: dict) -> int:
        table = ranks or SEVERITY_RANKS
        found = [table.get(value.lower(), 1) for value in all_values_at(*paths)(record)]
        return max(found, default=1)

    return read


def present_at(*paths: str) -> Callable[[dict], bool]:
    """A reader of whether ``paths`` hold any text."""

    def read(record: dict) -> bool:
        return bool(all_values_at(*paths)(record))

    return read


def flag_at(path: str, expected: bool = True) -> Callable[[dict], bool]:
    """A reader of whether the boolean under ``path`` is ``expected``; a missing one counts as False."""

    def read(record: dict) -> bool:
        return bool(first_value(record_value(record, path))) is expected

    return read


def split_values(*paths: str, separator: str = ",") -> Callable[[dict], list[str]]:
    """A reader of the texts under ``paths``, each split on ``separator`` (a proxy listed as "SOCKS4, SOCKS5")."""

    def read(record: dict) -> list[str]:
        return texts([part for value in all_values_at(*paths)(record) for part in value.split(separator)])

    return read


def tor_state(record: dict) -> dict:
    """The newest consensus state of a Tor relay record, as the fetch sees it before the incident is shaped."""
    return IncidentBuilder._newest_tor_state(record.get("nodes"))


def tor_flags(record: dict) -> list[str]:
    return texts(tor_state(record).get("flags"))


def tor_exit(record: dict) -> bool:
    """Whether the relay's newest consensus flags make it a usable exit: Exit among them, BadExit not."""
    flags = {flag.casefold() for flag in tor_flags(record)}
    return "exit" in flags and "badexit" not in flags


def tor_country(record: dict) -> list[str]:
    return values_at("countryCode")(record) or texts(tor_state(record).get("country"))


def tor_asn(record: dict) -> list[str]:
    return values_at("asn")(record) or texts(tor_state(record).get("as"))


def normalize_asn(value: str) -> str:
    """An autonomous system number without its AS prefix and case: "AS64501" and "64501" are one."""
    return value.casefold().removeprefix("as").strip()


def normalize_name(value: str) -> str:
    """A name without its separators and case: "Brute-Force" and "brute force" are one."""
    return " ".join(re.sub(r"[^0-9a-z]+", " ", value.casefold()).split())


def platform_names(record: dict) -> list[str]:
    """The platform of a C&C record, with the value "Winsows" read as Windows."""
    return ["windows" if value.casefold() == "winsows" else value for value in values_at("platform")(record)]


def leak_match_types(record: dict) -> list[str]:
    """The buckets and bucket.category names of a public leak's matches."""
    matches = record.get("matches")
    found: list[str] = []
    for bucket, categories in matches.items() if isinstance(matches, dict) else []:
        found.append(str(bucket))
        if isinstance(categories, dict):
            found.extend(f"{bucket}.{category}" for category in categories)
    return found


def vendor_products(record: dict) -> list[str]:
    """The vendors of a vulnerability's CPE table and each vendor:product pair."""
    table = record.get("cpeTable")
    if not isinstance(table, dict):
        return []
    vendors, products = record_value(table, "vendor"), record_value(table, "product")
    vendors = vendors if isinstance(vendors, list) else [vendors]
    products = products if isinstance(products, list) else [products]
    found = texts(vendors)
    for vendor, product in zip(vendors, products, strict=False):
        if vendor not in (None, "") and product not in (None, ""):
            found.append(f"{vendor}:{product}")
    return found


REPORT_INDICATOR_PATHS = (
    "indicators.ipv4",
    "indicators.ipv6",
    "indicators.domain",
    "indicators.url",
    "indicators.hashes_md5",
    "indicators.hashes_sha1",
    "indicators.hashes_sha256",
    "indicators.hashes_sha512",
    "indicators.email_address",
    "indicators.email_sender_ip",
)
# The observables of a public post: the types of OPEN_THREAT_INDICATOR_TYPES and their file hash fallbacks.
OPEN_THREAT_INDICATOR_PATHS = tuple(
    f"indicators.{key}"
    for key in ("ip", "domain", "file_sha256", "file_sha1", "file_md5", "file_sha512", "hash", "cve", "wallet")
)
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
BREACH_RECORD_OPTIONS = ("all", "password", "credentials")


@dataclass(frozen=True)
class FilterSpec:
    """One filter of a collection: its name in "Collection filters", how it decides and what it reads."""

    name: str
    # include: a record needs one of the values; exclude: a record with one of them is skipped; contains: a record
    # needs a value holding one of the texts; min, max: a number, a record without one passes; age: days back from
    # the fetch by the record's date, a record without one passes; severity: Low, Medium or High, an unrated record
    # counts as Low; flag: true keeps the records the condition holds for; choice: one of the options; networks:
    # addresses and CIDR networks a record's address must not be in; query: sent to the API with every request.
    kind: str
    help: str
    read: Callable[[dict], Any] = field(default=lambda record: None, repr=False, compare=False)
    # The values the filter takes, when the set is closed; for a query, the field prefixes the API takes.
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


def _max(name: str, help: str, read: Callable[[dict], Any]) -> FilterSpec:
    return FilterSpec(name, "max", help, read)


def _flag(name: str, help: str, read: Callable[[dict], Any]) -> FilterSpec:
    return FilterSpec(name, "flag", help, read)


def _severity(
    help: str = "The lowest Group-IB severity a record needs.", read: Callable[[dict], Any] | None = None
) -> FilterSpec:
    return FilterSpec("min_severity", "severity", help, read or rank_at("evaluation.severity"), SEVERITY_OPTIONS)


def _age(help: str, *paths: str) -> FilterSpec:
    return FilterSpec("max_age_days", "age", help, values_at(*paths))


def _networks(read: Callable[[dict], Any]) -> FilterSpec:
    return FilterSpec(
        "excluded_networks", "networks", "Addresses and CIDR networks; a record whose address lies in one is skipped.", read
    )


def _query(help: str, fields: tuple[str, ...] = ()) -> FilterSpec:
    return FilterSpec("query", "query", help, options=fields)


def _actors(path: str = "threatActor.name") -> FilterSpec:
    return _include("actors", "Threat actor names a record needs one of.", values_at(path))


def _malware(path: str, what: str = "a record") -> tuple[FilterSpec, FilterSpec]:
    return (
        _include("malware", f"Malware family names {what} needs one of.", values_at(path)),
        _exclude("excluded_malware", f"Malware family names that skip {what}.", values_at(path)),
    )


def _listing_filters(
    country: Callable[[dict], Any], asn: Callable[[dict], Any], address: Callable[[dict], Any], *extra: FilterSpec
) -> tuple[FilterSpec, ...]:
    """The filters every suspicious_ip/* collection takes."""
    sources = all_values_at("source", "sources")
    return (
        _severity(),
        _age("Days back from the fetch by the date the address was last seen listed.", "dateLastSeen"),
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


def _report_filters(*date_paths: str) -> tuple[FilterSpec, ...]:
    """The filters of the threat report collections."""
    return (
        _severity(),
        _age("Days back from the fetch by the report's publication date, else the date it was created.", *date_paths),
        _include(
            "report_types", "Report types a report needs one of: threat (analyst-authored) or event.", values_at("report_type")
        ),
        _include("sectors", "Sectors a report needs one of.", values_at("sectors")),
        _include("regions", "Regions or country names a report needs one of.", all_values_at("regions", "countries")),
        _actors(),
        _exclude("excluded_actors", "Threat actor names that skip a report.", values_at("threatActor.name")),
        *_malware("indicators.malware_names", "a report"),
        _contains("targeted_companies", "Text one of the targeted company names must contain.", values_at("targeted_companies")),
        _include(
            "target_domains", "Domains among the report's target domains, subdomains included.", domains_at("target_domains")
        ),
        _flag("with_iocs_only", "true keeps only the reports that carry indicators.", present_at(*REPORT_INDICATOR_PATHS)),
    )


def _actor_filters(query_help: str) -> tuple[FilterSpec, ...]:
    """The filters of the threat actor profile collections."""
    return (
        _age("Days back from the fetch by the date the actor was last seen active.", "dateLastSeen"),
        _flag("with_iocs_only", "true keeps only the profiles with linked indicators.", flag_at("hasIocs")),
        _include("sectors", "Sectors a profile needs one of.", values_at("sectors")),
        _include("regions", "Regions a profile needs one of.", values_at("regions")),
        *_malware("malware", "a profile"),
        _query(query_help),
    )


def _post_filters(
    channel: tuple[str, ...], author: tuple[str, ...], channel_names: str, author_names: str
) -> tuple[FilterSpec, ...]:
    """The filters of the Telegram and Discord post collections."""
    return (
        _age("Days back from the fetch by the post date.", "postDate"),
        _include("channels", f"{channel_names} a post needs one of.", all_values_at(*channel)),
        _exclude("excluded_channels", f"{channel_names} that skip a post.", all_values_at(*channel)),
        _include("authors", f"{author_names} a post needs one of.", all_values_at(*author)),
        _exclude("excluded_authors", f"{author_names} that skip a post.", all_values_at(*author)),
        _flag(
            "with_attachment", "true keeps only the posts with an attachment.", present_at("attachment.name", "attachment.type")
        ),
    )


# The filters of each collection, in the order the README lists them.
FILTERS: dict[str, dict[str, FilterSpec]] = {
    name: {spec.name: spec for spec in specs}
    for name, specs in {
        TICollections.COMPROMISED_ACCOUNT_GROUP: (
            _severity(),
            _age(
                "Days back from the fetch by the date the account was last compromised, else the date it was first seen.",
                "dateLastCompromised",
                "dateFirstSeen",
            ),
            *_malware("events_table.malware", "an account"),
            _include("source_types", "Source types an account's events need one of.", values_at("events_table.sourceType")),
            _include(
                "service_domains",
                "Domains of the service the account belongs to, subdomains included.",
                domains_at("service.domain"),
            ),
            _include(
                "login_domains", "Domains of the login's e-mail address, subdomains included.", domains_at("parsedLogin.domain")
            ),
            _include(
                "victim_countries",
                "Country codes of the compromised device, from the account's events.",
                values_at("events_table.countryCode"),
            ),
        ),
        TICollections.COMPROMISED_BANK_CARD_GROUP: (
            _severity(),
            _age(
                "Days back from the fetch by the date the card was last compromised, else the date it was first compromised.",
                "dateLastCompromised",
                "dateFirstCompromised",
            ),
            _include("payment_systems", "Payment systems a card needs one of.", values_at("payment_system")),
            _include("issuer_countries", "Issuer country codes a card needs one of.", values_at("issuer_country_code")),
            _contains("issuers", "Text the issuer's name must contain.", values_at("issuer")),
            _include("card_types", "Card types a card needs one of.", values_at("type")),
            *_malware("compromised_events.malware", "a card"),
        ),
        TICollections.COMPROMISED_MASKED_CARD: (
            _severity(),
            _age(
                "Days back from the fetch by the date the card was compromised, else the date it was detected.",
                "dateCompromised",
                "dateDetected",
            ),
            _include("payment_systems", "Payment systems a card needs one of.", values_at("payment_system")),
            _include("issuer_countries", "Issuer country codes a card needs one of.", values_at("issuer_country_code")),
            _contains("issuers", "Text the issuer's name must contain.", values_at("issuer")),
            *_malware("malware_name", "a card"),
            _flag("skip_expired", "true skips the cards past their expiry date.", flag_at("isExpired", expected=False)),
            _flag("skip_dumps", "true skips the records that are card dumps.", flag_at("isDump", expected=False)),
        ),
        TICollections.COMPROMISED_BREACHEDDB: (
            _severity(),
            _age(
                "Days back from the fetch by the date the leak was published, else the date it was uploaded.",
                "leakPublished",
                "uploadTime",
            ),
            FilterSpec(
                "records",
                "choice",
                "all (every record), password (the records with a password, asked of the API) or credentials (the "
                "records with a password, a credential column or a secret a column quotes).",
                lambda record: ["all", "password", "credentials"] if record.get("hasPassword") else ["all"],
                BREACH_RECORD_OPTIONS,
            ),
            _contains("leaks", "Text the leak's name must contain.", values_at("leakName")),
            _include(
                "email_domains",
                "Domains of the leaked e-mail addresses, subdomains included.",
                domains_at("emailDomains"),
            ),
        ),
        TICollections.COMPROMISED_SPD: (
            _severity(),
            _age("Days back from the fetch by the date the payment detail was last seen.", "lastSeenAt"),
            _include("types", "Payment detail types a record needs one of.", values_at("type"), SPD_TYPES),
            _include("service_types", "Service types a record needs one of.", values_at("serviceType")),
            _min("min_illegal_score", "The lowest illegal score a record needs.", number_at("illegalScore")),
            _include("countries", "Country codes a record needs one of.", values_at("country")),
            _include("malware", "Malware family names a record needs one of.", values_at("malware.name")),
            _actors(),
        ),
        TICollections.COMPROMISED_ACCESS: (
            _severity(),
            _age(
                "Days back from the fetch by the date the access was compromised, else the date it was detected.",
                "dateCompromised",
                "dateDetected",
            ),
            _include("access_types", "Access types a listing needs one of.", values_at("accessType")),
            *_malware("malware_name", "a listing"),
            _include(
                "target_domains", "Domains of the target host, subdomains included.", domains_at("target.domain", "target.host")
            ),
            _include("shops", "Marketplace domains a listing needs one of.", values_at("shop.domain")),
            _exclude("excluded_shops", "Marketplace domains that skip a listing.", values_at("shop.domain")),
            _max("max_price", "The highest price a listing may ask.", number_at("priceValue")),
        ),
        TICollections.COMPROMISED_MESSENGER: _post_filters(
            ("channel.name", "channel.title"),
            ("author.handle", "author.firstName"),
            "Channel names",
            "Author handles or first names",
        ),
        TICollections.COMPROMISED_DISCORD: _post_filters(
            ("channel.name", "channel.server"),
            ("author.name",),
            "Channel or server names",
            "Author names, without the #discriminator,",
        ),
        TICollections.DARKWEB_FORUMS: (
            _age("Days back from the fetch by the post date.", "postDate"),
            _include(
                "categories",
                "Group-IB categories a post needs one of; a post without categories is skipped.",
                values_at("categories"),
            ),
            _exclude("excluded_categories", "Group-IB categories that skip a post.", values_at("categories")),
            _include("forums", "Forum hosts a post needs one of.", values_at("forum")),
            _exclude("excluded_forums", "Forum hosts that skip a post.", values_at("forum")),
            _include("authors", "Author handles a post needs one of.", values_at("author.handle")),
            _exclude("excluded_authors", "Author handles that skip a post.", values_at("author.handle")),
            _include(
                "languages",
                "Language names (English, Russian, ...) a post needs one of.",
                all_values_at("languages", "messageLanguages"),
            ),
            _query(
                'Sent to the API as `q` with every request of the collection: bare words, or `id:<id>`, `forum:"<host>"`, '
                '`nickname:"<handle>"`, `message:"<term>"` or `ocr_analyser:<term>`; the API rejects other field prefixes.',
                ("id", "forum", "nickname", "message", "ocr_analyser"),
            ),
        ),
        TICollections.OSI_GIT_REPOSITORY: (
            _severity("The lowest Group-IB severity of the repository record; the files carry their own grades."),
            _age("Days back from the fetch by the date the leak was detected.", "dateDetected"),
            FilterSpec(
                "min_file_severity",
                "severity",
                "The lowest grade one of the repository's files needs (gray and yellow count as Low).",
                rank_at("files.severity", ranks=FILE_SEVERITY_RANKS),
                SEVERITY_OPTIONS,
            ),
            _flag(
                "secrets_only",
                "true keeps only the repositories where a file holds a detected secret.",
                present_at("files.dataFound"),
            ),
            _include(
                "secret_types",
                "Secret types (password, api_key, ...) a repository's files need one of.",
                values_at("files.dataFound"),
            ),
        ),
        TICollections.OSI_PUBLIC_LEAK: (
            _severity(),
            _age("Days back from the fetch by the date the leak was created.", "created"),
            _include("sources", "Sites a leak needs a link from.", values_at("linkList.source")),
            _exclude("excluded_sources", "Sites whose leaks are skipped.", values_at("linkList.source")),
            _include(
                "match_types",
                "Match buckets (card, email, commonKeywords, ...) or bucket.category names a leak needs one of.",
                leak_match_types,
            ),
            _exclude("excluded_match_types", "Match buckets or bucket.category names that skip a leak.", leak_match_types),
        ),
        TICollections.OSI_VULNERABILITY: (
            _severity(),
            _age(
                "Days back from the fetch by the publication date; an older record updated in the window is skipped.",
                "datePublished",
            ),
            _include(
                "types", "Record types to fetch (cve, mscve, nessus, redhat, ...); asked of the API as well.", values_at("type")
            ),
            _exclude(
                "excluded_types",
                "Record types to skip; a single type is asked of the API as well when types is empty.",
                values_at("type"),
            ),
            _flag(
                "has_exploit",
                "true keeps only the records with a known exploit, asked of the API as well.",
                flag_at("hasExploit"),
            ),
            _flag(
                "seen_in_the_wild", "true keeps only the vulnerabilities seen exploited in the wild.", flag_at("seenInTheWild")
            ),
            _min(
                "min_cvss",
                "The lowest CVSS score a record needs: the merged cross-version score, else the legacy CVSS score.",
                cvss_at(("mergedCvss", "mergedCvssVector"), ("cvss.score", "cvss.vector")),
            ),
            _min(
                "min_epss_percentile",
                "The lowest EPSS percentile (0-100) a record needs.",
                number_at("epssPercentile", scale=100),
            ),
            _include("vendors", "CPE vendors, or vendor:product pairs, a record's CPE table needs one of.", vendor_products),
            _include("products", "CPE products a record's CPE table needs one of.", values_at("cpeTable.product")),
        ),
        TICollections.ATTACKS_DDOS: (
            _severity(),
            _age(
                "Days back from the fetch by the date the attack began, else the date it was registered.", "dateBegin", "dateReg"
            ),
            _include("types", "Attack types a record needs one of.", values_at("type")),
            _include("protocols", "Protocols a record needs one of.", values_at("protocol")),
            _include("target_countries", "Country codes of the attack's target.", values_at("target.countryCode")),
            _include("target_ports", "Target ports a record needs one of.", values_at("target.port")),
            _include("malware", "Malware family names a record needs one of.", values_at("malwareName")),
            _actors(),
        ),
        TICollections.ATTACKS_DEFACE: (
            _severity(),
            _age("Days back from the fetch by the date of the defacement.", "date"),
            _include("target_domains", "Domains of the defaced site, subdomains included.", domains_at("targetDomain")),
            _include(
                "countries",
                "Country codes of the defaced site's address.",
                values_at("targetIp.countryCode"),
            ),
            _actors(),
            _include("sources", "Source names a record needs one of.", values_at("source")),
        ),
        TICollections.ATTACKS_PHISHING_GROUP: (
            _severity(),
            _age(
                "Days back from the fetch by the date the group was detected, else the date it was updated.",
                "detected",
                "updated",
            ),
            _include("brands", "Brands a group needs to impersonate one of.", values_at("brand")),
            _exclude("excluded_brands", "Brands whose groups are skipped.", values_at("brand")),
            _include("objectives", "Phishing objectives a group needs one of.", values_at("objective")),
            _actors(),
            _include("sources", "Source names a group needs one of.", values_at("source")),
        ),
        TICollections.ATTACKS_PHISHING_KIT: (
            _severity(),
            _age(
                "Days back from the fetch by the date the kit was last seen, else the date it was first seen.",
                "dateLastSeen",
                "dateFirstSeen",
            ),
            _include("brands", "Brands a kit needs to target one of.", values_at("targetBrand")),
            _include("sources", "Source names a kit needs one of.", values_at("source")),
        ),
        TICollections.SUSPICIOUS_IP_TOR_NODE: _listing_filters(
            tor_country,
            tor_asn,
            values_at("name"),
            _flag(
                "exit_only",
                "true keeps only the relays whose newest consensus flags make them a usable exit (Exit without BadExit).",
                tor_exit,
            ),
            _include("flags", "Consensus flags (Exit, Guard, ...) a relay's newest state needs one of.", tor_flags),
        ),
        TICollections.SUSPICIOUS_IP_OPEN_PROXY: _listing_filters(
            values_at("countryCode"),
            values_at("asn"),
            values_at("name"),
            _include("types", "Proxy protocols (HTTP, HTTPS, SOCKS4, SOCKS5) a listing needs one of.", split_values("type")),
            _include("ports", "Ports a listing needs one of.", values_at("port")),
            _min("min_sources", "The lowest number of public lists the address must appear on.", count_at("sources")),
        ),
        TICollections.SUSPICIOUS_IP_SOCKS_PROXY: _listing_filters(values_at("countryCode"), values_at("asn"), values_at("name")),
        TICollections.SUSPICIOUS_IP_VPN: _listing_filters(
            values_at("countryCode"),
            values_at("asn"),
            values_at("name"),
            _include(
                "types", "Deployment types (commercial, self-hosted, public, ...) a gateway needs one of.", values_at("types")
            ),
            _include("names", "VPN product names a gateway needs one of.", values_at("names")),
            _exclude("excluded_names", "VPN product names that skip a gateway.", values_at("names")),
        ),
        TICollections.SUSPICIOUS_IP_SCANNER: _listing_filters(
            all_values_at("countryCode", "indicators.ipv6_country_code"),
            all_values_at("asn", "indicators.ipv6_asn"),
            all_values_at("name", "indicators.ipv6_ip"),
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
        ),
        TICollections.MALWARE_CNC: (
            _age(
                "Days back from the fetch by the date the C&C was last seen, else the date it was detected.",
                "dateLastSeen",
                "dateDetected",
            ),
            _actors(),
            *_malware("malwareList.name", "a C&C"),
            _include(
                "countries",
                "Country codes of the C&C's resolved addresses.",
                all_values_at("indicators.ipv4_country_code", "indicators.ipv6_country_code"),
            ),
            _exclude(
                "excluded_countries",
                "Country codes that skip a C&C.",
                all_values_at("indicators.ipv4_country_code", "indicators.ipv6_country_code"),
            ),
            _include("platforms", "Platforms (Windows, Android, Web) a C&C needs one of.", platform_names),
            _networks(all_values_at("indicators.ipv4_ip", "indicators.ipv6_ip")),
        ),
        TICollections.MALWARE_MALWARE: (
            _severity("The lowest threat level a malware profile needs.", rank_at("threatLevel")),
            _include("platforms", "Platforms a malware profile needs one of.", values_at("platform")),
            _include(
                "categories", "Categories (Infostealer, RAT, Ransomware, ...) a profile needs one of.", values_at("category")
            ),
            _exclude("excluded_categories", "Categories that skip a profile.", values_at("category")),
            _include("source_countries", "Source country codes a profile needs one of.", values_at("sourceCountry")),
        ),
        TICollections.HI_THREAT: _report_filters("datePublished", "createdAt"),
        TICollections.APT_THREAT: _report_filters("datePublished", "createdAt"),
        TICollections.HI_THREAT_ACTOR: _actor_filters(
            "A name, alias or forum username sent to the API as `q` with every request of the collection, without a field prefix."
        ),
        TICollections.APT_THREAT_ACTOR: _actor_filters(
            "A name, alias or country sent to the API as `q` with every request of the collection, without a field prefix."
        ),
        TICollections.HI_OPEN_THREATS: (
            _severity(),
            _age(
                "Days back from the fetch by the date the post was created, else the date it was detected.",
                "createdAt",
                "dateDetected",
            ),
            _include("source_types", "Blog, Social Network or both.", values_at("sourceType"), OPEN_THREAT_SOURCE_TYPES),
            _include("sources", "Site or network names a post needs one of.", values_at("sourceName")),
            _exclude("excluded_sources", "Site or network names that skip a post.", values_at("sourceName")),
            _include("actors", "Threat actor names a post needs one of.", values_at("threat_actor_name")),
            _include("malware", "Malware family names a post needs one of.", values_at("malware_name")),
            _include("tags", "Tags a post needs one of.", values_at("tags")),
            _flag(
                "with_iocs_only",
                "true keeps only the posts Group-IB extracted indicators from.",
                present_at(*OPEN_THREAT_INDICATOR_PATHS),
            ),
            _flag(
                "matched_rules_only", "true keeps only the posts one of your hunting rules matched.", present_at("huntingRuleIds")
            ),
        ),
    }.items()
}


@dataclass(frozen=True)
class RecordFilter:
    """The instance's fetch filters: which records become incidents, and the request parameters that narrow a collection."""

    # A record a filter drops is not fetched later: the cursor moves past it.

    SETTING: ClassVar[str] = "Collection filters"
    # Setting key, its label, the filter it sets and the collections it applies to: None for every collection with
    # the filter.
    SETTINGS: ClassVar[tuple[tuple[str, str, str, tuple[str, ...] | None], ...]] = (
        ("min_severity", "Minimum severity", "min_severity", None),
        ("max_record_age_days", "Skip records older than (days)", "max_age_days", None),
        ("vulnerability_types", "Vulnerability types to fetch", "types", (TICollections.OSI_VULNERABILITY,)),
        ("vulnerability_excluded_types", "Vulnerability types to skip", "excluded_types", (TICollections.OSI_VULNERABILITY,)),
        ("vulnerability_has_exploit", "Vulnerabilities with an exploit only", "has_exploit", (TICollections.OSI_VULNERABILITY,)),
        ("breacheddb_records", "Breached records to fetch", "records", (TICollections.COMPROMISED_BREACHEDDB,)),
        ("spd_types", "Payment detail types to fetch", "types", (TICollections.COMPROMISED_SPD,)),
        ("darkweb_forum_categories", "Dark web forum categories to fetch", "categories", (TICollections.DARKWEB_FORUMS,)),
        (
            "darkweb_forum_excluded_categories",
            "Dark web forum categories to skip",
            "excluded_categories",
            (TICollections.DARKWEB_FORUMS,),
        ),
        ("open_threats_source_types", "Open threat source types", "source_types", (TICollections.HI_OPEN_THREATS,)),
    )
    # "Breached records to fetch" as the setting words it.
    BREACH_RECORD_LABELS: ClassVar[dict[str, str]] = {
        "all": "all",
        "with a password": "password",
        "with a password or a credential column": "credentials",
    }
    # The payment detail types as the API's type parameter spells them, by their lowercase name.
    SPD_SERVER_TYPES: ClassVar[dict[str, str]] = {name.casefold(): name for name in SPD_TYPES}
    TRUE_WORDS: ClassVar[frozenset[str]] = frozenset({"true", "yes", "on", "1"})
    FALSE_WORDS: ClassVar[frozenset[str]] = frozenset({"false", "no", "off", "0"})

    # Collection -> filter name -> its normalized value.
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_params(cls, params: dict) -> "RecordFilter":
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
        """Stores the normalized ``raw``, or clears the filter when it sets none (empty, an age of 0, Low, false, all)."""
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
        if spec.kind in ("include", "exclude", "contains"):
            values = frozenset(spec.normalize(item.strip()) for item in text.split(",") if item.strip())
            allowed = {spec.normalize(option) for option in spec.options}
            unknown = sorted(values - allowed) if allowed else []
            if unknown:
                raise DemistoException(f"{where}: {spec.name} takes {', '.join(spec.options)}, got {', '.join(unknown)}.")
            return values or None
        if spec.kind in ("min", "max", "age"):
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
        if spec.kind == "choice":
            word = text.casefold()
            option = cls.BREACH_RECORD_LABELS.get(word, word) if spec.name == "records" else word
            if not option or option == spec.options[0]:
                return None
            if option not in spec.options:
                raise DemistoException(f"{where}: {spec.name} takes {', '.join(spec.options)}, got {text!r}.")
            return option
        if spec.kind == "networks":
            networks = []
            for item in (part.strip() for part in text.split(",") if part.strip()):
                try:
                    networks.append(ipaddress.ip_network(item, strict=False))
                except ValueError:
                    raise DemistoException(f"{where}: {spec.name} takes addresses and CIDR networks, got {item!r}.") from None
            return tuple(networks) or None
        return cls._query_text(spec, text, where)

    @staticmethod
    def _query_text(spec: FilterSpec, text: str, where: str) -> str | None:
        """A query the API takes, with a field prefix only among the ones the collection's API accepts."""
        if not text:
            return None
        prefix = text.split(":", 1)[0].strip().casefold() if ":" in text else ""
        if prefix and " " not in prefix and prefix not in spec.options:
            accepted = f"use {', '.join(spec.options)} or bare words" if spec.options else "it takes a bare value"
            raise DemistoException(f"{where}: {spec.name} does not take the query field {prefix!r} here; {accepted}.")
        return text

    def accepts(self, collection_name: str, record: dict, now: datetime) -> bool:
        """Whether the record passes every filter of its collection."""
        specs = FILTERS.get(collection_name, {})
        return all(self._passes(specs[name], value, record, now) for name, value in self.rules.get(collection_name, {}).items())

    @classmethod
    def _passes(cls, spec: FilterSpec, value: Any, record: dict, now: datetime) -> bool:
        if spec.kind == "query":
            return True
        found = spec.read(record)
        if spec.kind == "include":
            return bool(value & {spec.normalize(str(item)) for item in found})
        if spec.kind == "exclude":
            return not value & {spec.normalize(str(item)) for item in found}
        if spec.kind == "contains":
            return any(text in spec.normalize(str(item)) for item in found for text in value)
        if spec.kind == "min":
            return found is None or found >= value
        if spec.kind == "max":
            return found is None or found <= value
        if spec.kind == "severity":
            return found >= value
        if spec.kind == "age":
            moment = cls._moment(found)
            return moment is None or moment >= now - timedelta(days=value)
        if spec.kind == "flag":
            return bool(found)
        if spec.kind == "choice":
            return value in found
        return not cls._listed(found, value)

    @staticmethod
    def _query_value(value: str) -> str:
        """A filter value as the quoted form of a ``q`` query reads it."""
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _moment(found: Any) -> datetime | None:
        text = first_value(found)
        moment = dateparser_parse(str(text)) if text not in (None, "") else None
        # A placeholder of an unknown date: a record carrying it has no date.
        if moment is None or moment.year < FIRST_RECORD_YEAR:
            return None
        return moment if moment.tzinfo else moment.replace(tzinfo=UTC)

    @staticmethod
    def _listed(addresses: Any, networks: tuple) -> bool:
        """Whether one of the addresses lies in one of the networks; a text that is no address does not."""
        for text in texts(addresses):
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            if any(address in network for network in networks):
                return True
        return False

    def request_params(self, collection_name: str) -> dict[str, Any]:
        """The request parameters that narrow the collection on the server; every filter but query is checked again on arrival."""
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
        elif collection_name == TICollections.COMPROMISED_BREACHEDDB and rules.get("records") == "password":
            extra["has_password"] = 1
        elif collection_name == TICollections.COMPROMISED_SPD and len(rules.get("types") or ()) == 1:
            extra["type"] = self.SPD_SERVER_TYPES[next(iter(rules["types"]))]
            # The type goes out as the API spells it; ciaops validates against its own spellings.
            extra["ignore_validation"] = True
        elif rules.get("query"):
            extra["query"] = rules["query"]
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


""" SETTINGS """


@dataclass(frozen=True)
class Settings:
    """The instance settings."""

    # Just above the API's limit of one request per second per route.
    DEFAULT_RATE_LIMIT_DELAY = 1.2
    DEFAULT_SEARCH_TIMEOUT = 20.0
    DEFAULT_PARALLEL_REQUESTS = 4
    DEFAULT_DEDUP_LOOKBACK_DAYS = 365
    # A DBotScore never goes out without a reliability.
    DEFAULT_SOURCE_RELIABILITY = DBotScoreReliability.C
    REPUTATION_COMMANDS = frozenset({"ip", "domain", "file", "url"})

    base_url: str
    username: Any = field(repr=False)
    password: Any = field(repr=False)
    proxy: bool
    verify: bool
    incident_collections: Any
    # "Incidents first fetch", parsed only when a collection without a cursor needs it (first_fetch_date), so an
    # invalid value fails no fetch whose collections all have a cursor.
    first_fetch: str
    # Pages requested per collection and run.
    max_requests: int
    hunting_rules: bool
    combolist: bool
    unique: bool
    enable_probable_corporate_access: bool
    skip_updated_incidents: bool
    dedup_lookback_days: int
    # A phishing group Group-IB flags goes to the pre-processing rule instead of being dropped; while the duplicate cache is
    # on, only a group the cache holds is passed on.
    pass_flagged_phishing_groups: bool
    # Records per page of the update feed, cut to the page size ciaops documents for the collection. On a BoundaryPages
    # collection, a page that one cursor position fills is read again larger, up to BoundaryPages.LARGEST_PAGES.
    limit: int
    # Minimum seconds between two requests to the same collection within one paged read: a fetch or gibti-local-search.
    rate_limit_delay: float
    # The reliability of the DBotScores the integration writes; with use_computed_reliability on, a reputation result
    # takes the highest reliability among the matched collections that give one instead.
    source_reliability: str
    # "Ignore Source Reliability override".
    use_computed_reliability: bool
    # Only these reputation commands enrich; the others answer with a note. Empty when the setting is missing or empty.
    enabled_reputation_commands: frozenset[str]
    # Relate observables to the Malware and Threat Actor objects the records name.
    create_relationships: bool
    # The collections selected in 'Collections that keep an IP at least Suspicious' (only the suspicious_ip/* ones count),
    # and the days a listing keeps it there: None or 0 for any age.
    floor_collections: frozenset[str]
    floor_max_age_days: int | None
    # The longest wait for the requests of one value of a reputation command, and for a list's batched risk scores;
    # 0 for no limit.
    search_timeout: float
    # ip, gibti-ip-whois and gibti-ip-scoring also ask Group-IB about an address that is not global (private, loopback,
    # link-local, shared or reserved).
    lookup_internal_addresses: bool
    # The requests of one reputation lookup that run at once, and whether ip, domain and file also ask the global search.
    parallel_requests: int
    use_global_search: bool
    # ip and domain read the WHOIS record too; gibti-domain-whois and domain keep or drop a registrant's name and e-mail
    # address.
    reputation_whois: bool
    whois_personal_data: bool
    # A reputation result below Suspicious still tags the indicator with the collections that list or mention it, apart from
    # the floor collections of an ip result.
    collection_tags_always: bool
    masking: "Masking"
    record_filter: RecordFilter

    @classmethod
    def from_params(cls, params: dict) -> "Settings":
        """The settings of ``params``, read in the order that decides which invalid setting a failure names."""
        credentials: dict = params.get("credentials") or {}
        username = credentials.get("identifier")
        password = credentials.get("password")
        base_url = str(params.get("url"))
        proxy = argToBoolean(params.get("proxy") or False)
        hunting_rules = argToBoolean(params.get("hunting_rules") or False)
        verify = not argToBoolean(params.get("insecure") or False)
        incident_collections = params.get("incident_collections") or []
        first_fetch = (params.get("first_fetch") or "").strip() or "3 days"
        max_requests = cls._number(params, "max_fetch", "Number of requests per collection", int, "a whole number", 3)
        skip_updated_incidents = cls._flag(params, "skip_updated_incidents", False)
        dedup_lookback_days = cls._dedup_lookback_days(params)
        pass_flagged_phishing_groups = argToBoolean(params.get("pass_flagged_phishing_groups") or False)
        combolist = argToBoolean(params.get("combolist") or False)
        unique = argToBoolean(params.get("unique") or False)
        enable_probable_corporate_access = argToBoolean(params.get("enable_probable_corporate_access") or False)
        limit = cls._number(params, "limit", "Limit (items per request)", int, "a whole number", 100)
        rate_limit_delay = cls._number(
            params,
            "rate_limit_delay",
            "Delay between API requests (seconds)",
            float,
            "a number of seconds",
            cls.DEFAULT_RATE_LIMIT_DELAY,
        )
        source_reliability = cls._source_reliability(params.get("integration_reliability")) or cls.DEFAULT_SOURCE_RELIABILITY
        use_computed_reliability = cls._flag(params, "disable_integration_reliability_override", False)
        enabled_reputation_commands = cls._enabled_reputation_commands(params)
        create_relationships = cls._flag(params, "create_relationships", True)
        floor_collections = cls._floor_collections(params)
        floor_max_age_days = cls._number(
            params, "reputation_floor_max_age_days", "Suspicious IP listing recency (days)", int, "a whole number of days", None
        )
        search_timeout = cls._number(
            params, "search_timeout", "Lookup timeout (seconds)", float, "a number of seconds", cls.DEFAULT_SEARCH_TIMEOUT
        )
        lookup_internal_addresses = cls._flag(params, "lookup_internal_addresses", False)
        parallel_requests = cls._number(
            params, "parallel_requests", "Parallel requests per lookup", int, "a whole number", cls.DEFAULT_PARALLEL_REQUESTS
        )
        if parallel_requests < 1:
            raise DemistoException("Parallel requests per lookup must be 1 or more.")
        use_global_search = cls._flag(params, "use_global_search", False)
        reputation_whois = cls._flag(params, "reputation_whois", True)
        collection_tags_always = cls._flag(params, "collection_tags_always", True)
        whois_personal_data = str(params.get("whois_personal_data") or "Show").strip().lower() != "drop"
        masking = Masking(PasswordMask.from_params(params), CardDataMask.from_params(params), PostTextMask.from_params(params))
        record_filter = RecordFilter.from_params(params)
        return cls(
            base_url=base_url,
            username=username,
            password=password,
            proxy=proxy,
            verify=verify,
            incident_collections=incident_collections,
            first_fetch=first_fetch,
            max_requests=max_requests,
            hunting_rules=hunting_rules,
            combolist=combolist,
            unique=unique,
            enable_probable_corporate_access=enable_probable_corporate_access,
            skip_updated_incidents=skip_updated_incidents,
            dedup_lookback_days=dedup_lookback_days,
            pass_flagged_phishing_groups=pass_flagged_phishing_groups,
            limit=limit,
            rate_limit_delay=rate_limit_delay,
            source_reliability=source_reliability,
            use_computed_reliability=use_computed_reliability,
            enabled_reputation_commands=enabled_reputation_commands,
            create_relationships=create_relationships,
            floor_collections=floor_collections,
            floor_max_age_days=floor_max_age_days,
            search_timeout=search_timeout,
            lookup_internal_addresses=lookup_internal_addresses,
            parallel_requests=parallel_requests,
            use_global_search=use_global_search,
            reputation_whois=reputation_whois,
            collection_tags_always=collection_tags_always,
            whois_personal_data=whois_personal_data,
            masking=masking,
            record_filter=record_filter,
        )

    @cached_property
    def first_fetch_date(self) -> str:
        parsed = dateparser_parse(date_string=self.first_fetch)  # type: ignore
        if parsed is None:
            raise DemistoException(
                f"Invalid 'Incidents first fetch' value {self.first_fetch!r}: use a date such as 2020-01-01, "
                "January 1 2020 or 3 days."
            )
        return parsed.strftime("%Y-%m-%d")

    def dedup_enabled(self) -> bool:
        """Whether the built-in deduplication runs; a negative lookback fails the fetch, and the fetch only."""
        if self.dedup_lookback_days < 0:
            raise DemistoException("'Deduplication lookback (days)' must be zero or positive.")
        return self.skip_updated_incidents and self.dedup_lookback_days > 0

    @property
    def retention_seconds(self) -> int:
        """An id added now leaves the duplicate cache exactly ``dedup_lookback_days`` days later."""
        return self.dedup_lookback_days * 86_400

    @property
    def reputation_reliability(self) -> str | None:
        """The reliability of a reputation result: the instance's, or None when it is computed per indicator."""
        return None if self.use_computed_reliability else self.source_reliability

    @staticmethod
    def _flag(params: dict, key: str, default: bool) -> bool:
        """A checkbox setting: absent or null is ``default``."""
        raw = params.get(key)
        return default if raw is None else argToBoolean(raw)

    @staticmethod
    def _number(params: dict, key: str, label: str, kind: Callable[[str], Any], expected: str, default: Any) -> Any:
        """A number setting: empty is ``default``, anything else a number of ``kind`` that is zero or positive."""
        raw = params.get(key)
        if raw in (None, ""):
            return default
        try:
            value = kind(str(raw).strip())
        except (TypeError, ValueError):
            raise DemistoException(f"Invalid '{label}' value: expected {expected}, got {raw!r}.") from None
        if value < 0:
            raise DemistoException(f"'{label}' must be zero or positive.")
        return value

    @classmethod
    def _dedup_lookback_days(cls, params: dict) -> int:
        raw = params.get("dedup_lookback_days")
        if raw in (None, ""):
            return cls.DEFAULT_DEDUP_LOOKBACK_DAYS
        if isinstance(raw, int) and not isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            try:
                return int(raw.strip())
            except ValueError:
                pass
        raise DemistoException(f"Invalid 'Deduplication lookback (days)' value: expected a whole number of days, got {raw!r}.")

    @classmethod
    def _enabled_reputation_commands(cls, params: dict) -> frozenset[str]:
        raw = params.get("enabled_reputation_commands") or []
        enabled = {str(x).strip().lower() for x in argToList(raw) if str(x).strip()}
        return frozenset(enabled & cls.REPUTATION_COMMANDS)

    @staticmethod
    def _source_reliability(value: str | None) -> str | None:
        """The Source Reliability parameter when it names a reliability, else None."""
        return value if isinstance(value, str) and DBotScoreReliability.is_valid_type(value) else None

    @staticmethod
    def _floor_collections(params: dict) -> frozenset[str]:
        """The floor collections of the setting: the default when it is absent or empty, none when it selects only "none"."""
        selected = frozenset(
            str(item).strip() for item in argToList(params.get("reputation_floor_collections")) if str(item).strip()
        )
        if not selected:
            return frozenset(name for name, spec in COLLECTIONS.items() if spec.floor_by_default)
        return selected - {"none"}


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
    """Group-IB TI API access through the ciaops TIPoller (``poller``), with the collections granted to the API user."""

    POLLER_PRODUCT_TYPE = "SOAR"
    POLLER_PRODUCT_NAME = "CortexSOAR"
    POLLER_INTEGRATION_NAME = "Group-IB Threat Intelligence"
    POLLER_INTEGRATION_VERSION = "4.0.0"
    # Data kept between command runs goes in the integration context, so the granted collections are cached there:
    # within the TTL a fetch (the hunting-rules grants) or gibti-get-available-collections spends no request on them.
    GRANTED_CACHE_KEY = "granted_collections_cache"
    GRANTED_CACHE_TTL_SECONDS = 300

    def __init__(
        self,
        base_url,
        verify=True,
        proxy=False,
        headers=None,
        auth=None,
        limit: int = 100,
        rate_limit_delay: float = Settings.DEFAULT_RATE_LIMIT_DELAY,
        clock: Callable[[], float] | None = None,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, auth=auth)
        self._auth: tuple[str, str]
        self.poller = TIPoller(
            username=self._auth[0],
            api_key=self._auth[1],
            api_url=base_url,
        )
        # The poller's session takes the proxy from the environment BaseClient sets up but checks certificates on its
        # own (verify=True by default), so "Trust any certificate (not secure)" is passed to it here.
        self.poller.set_verify(verify)
        self.limit = limit
        self.rate_limit_delay = rate_limit_delay
        self._clock = clock or time.time
        self._granted: list[dict[str, Any]] | None = None
        self._grants_failure: ConnectionException | None = None
        self._available: frozenset[str] | None = None
        self.poller.set_product(
            product_type=self.POLLER_PRODUCT_TYPE,
            product_name=self.POLLER_PRODUCT_NAME,
            product_version=demisto.demistoVersion().get("version", "unknown"),
            integration_name=self.POLLER_INTEGRATION_NAME,
            integration_version=self.POLLER_INTEGRATION_VERSION,
        )

    def fork(self) -> "Client":
        """A client of the same instance with a poller of its own, for requests on another thread."""
        twin = copy(self)
        twin.poller = TIPoller(username=self._auth[0], api_key=self._auth[1], api_url=self._base_url)
        twin.poller.set_verify(self._verify)
        twin.poller.set_product(
            product_type=self.POLLER_PRODUCT_TYPE,
            product_name=self.POLLER_PRODUCT_NAME,
            product_version=demisto.demistoVersion().get("version", "unknown"),
            integration_name=self.POLLER_INTEGRATION_NAME,
            integration_version=self.POLLER_INTEGRATION_VERSION,
        )
        return twin

    def granted_collections(self, refresh: bool = False) -> list[dict[str, Any]]:
        """``GET /user/granted_collections``, answered from this client's copy or the context cache unless ``refresh``."""
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
        self._available = None
        self._cache_grants(items)
        return items

    def available_collections(self) -> frozenset[str]:
        """The collections granted to the API user that ciaops knows."""
        if self._available is None:
            self._available = self._granted_names(lambda item: True)
        return self._available

    def hunting_rules_collections(self) -> frozenset[str]:
        """The granted collections whose grant has hunting rules enabled."""
        return self._granted_names(lambda item: bool(item.get("huntingRulesUsed")))

    def sequence_cursor(self, collection_name: str, date: str, hunting_rules: int | None) -> Any:
        """sequence_list's update position of ``collection_name`` at ``date``, None when it gives none."""
        seq_map = self.poller.get_seq_update_dict(date=date, collection_name=collection_name, apply_hunting_rules=hunting_rules)
        return seq_map.get(collection_name)

    def update_feed(
        self, collection_name: str, request_params: TIRequestParams, sequpdate: int | str | None, seen_keys: Iterable[str] = ()
    ) -> Any:
        """The pages a fetch reads from ``sequpdate`` on, with ``seen_keys`` the records already read at that cursor."""
        if collection_name in BoundaryPages.UNITS:
            return BoundaryPages(self.poller, collection_name, request_params, sequpdate, seen_keys, self.rate_limit_delay)
        return self._generator_pages(collection_name, request_params, sequpdate)

    def _generator_pages(self, collection_name: str, request_params: TIRequestParams, sequpdate: int | str | None) -> Any:
        """The pages of the collection's update feed from ``sequpdate`` on, paced by ciaops' generator."""
        return self._pages(
            self.poller.create_update_generator(
                collection_name=collection_name,
                request_params=request_params,
                sequpdate=sequpdate,
                rate_limit_delay=self.rate_limit_delay,
            )
        )

    @staticmethod
    def _pages(pages: Any) -> Iterator[Any]:
        """The pages of an update feed; a body that is no page, or a page without a cursor, raises a ConnectionException."""
        try:
            for page in pages or []:
                # ciaops asks for the next page from the cursor a page answers: without one it reads from the oldest record.
                if seq_update_number(page.sequpdate) is None:
                    raise ConnectionException(Client.NO_CURSOR)
                yield page
        except (AttributeError, TypeError):
            # ciaops raises AttributeError on a null or list body, and TypeError on a page whose items are null or a number.
            raise ConnectionException(Client.NOT_A_PAGE) from None

    def search_collection(
        self,
        collection_name: str,
        query: str | None,
        limit: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        sequpdate: int | str | None = None,
    ):
        """The update feed filtered by ``q``: from ``sequpdate``, from the oldest record, or within a ``df``/``dt`` window."""
        pages = self._generator_pages(
            collection_name,
            TIRequestParams(query=query, limit=self.page_size(collection_name, limit), date_from=date_from, date_to=date_to),
            sequpdate,
        )
        # A page of a feed paged by its items answers its lowest record cursor, which says nothing of the records above it.
        return pages if CollectionSpec.of(collection_name).cursor_from_items else self._advancing(pages, sequpdate)

    @staticmethod
    def _advancing(pages: Iterable[Any], sequpdate: int | str | None) -> Iterator[Any]:
        """The pages up to the first whose seqUpdate does not pass the one before, which ciaops would ask for again.

        ``ioc/primary`` answers a search without a cursor with seqUpdate 0 on every page."""
        previous = seq_update_number(sequpdate)
        for page in pages:
            cursor = seq_update_number(page.sequpdate)
            if previous is not None and cursor is not None and cursor <= previous:
                return
            previous = cursor
            yield page

    @staticmethod
    def page_size(collection_name: str, limit: int | str | None) -> int | None:
        """``limit`` up to the page size ciaops documents for the collection, that size when no limit is given."""
        cap = TICollections.get_page_limit(collection_name)
        if limit is None or limit == "":
            return cap
        size = int(limit)
        return min(size, cap) if cap is not None else size

    NOT_A_PAGE = "HTTP 200 with a body that is not a page of records"
    NO_CURSOR = "HTTP 200 with a page that carries no seqUpdate"

    @staticmethod
    def refusals_as_messages(pages: Any, message: Callable[[ConnectionException], str]) -> Iterator[Any]:
        """The pages of an update feed, a refusal while paging raised as a DemistoException of ``message``."""
        try:
            yield from pages or []
        except ConnectionException as exc:
            raise DemistoException(message(exc)) from None
        except (AttributeError, TypeError):
            # ciaops raises AttributeError on a null or list body, and TypeError on a page whose items are null or a number.
            raise DemistoException(message(ConnectionException(Client.NOT_A_PAGE))) from None

    def record_by_id(self, collection_name: str, record_id: str) -> Any:
        """``GET /{collection}/{id}``; NotFoundException when the collection has no such record."""
        try:
            return self.poller.search_feed_by_id(collection_name, record_id)
        except (AttributeError, TypeError):
            # ciaops raises AttributeError on a by-id body that is null or a list.
            raise ConnectionException(Client.NOT_A_PAGE) from None

    def record_by_route(self, route: str, record_id: str) -> Any:
        """``GET /{route}/{id}``, a route outside ciaops' collection list, sent through the poller."""
        Validator.validate_path_segment(record_id)
        return self.poller.send_request(endpoint=f"{route}/{urllib.parse.quote(record_id, safe='')}", params={})

    def global_search(self, query: str) -> Any:
        """``GET /search``: the collections with records that mention ``query``; null or a list."""
        return self.poller.global_search(query)

    def risk_score(self, kind: str, value: str) -> Any:
        """Group-IB's risk score of an IP (``kind`` "ip") or a domain, None when the answer has none."""
        scoring = (self.poller.get_ip_scoring if kind == "ip" else self.poller.get_domain_scoring)(value) or {}
        return dict_safe_get(scoring, ["items", value, "riskScore"])

    # The most values one scoring request asks about.
    SCORING_BATCH = 100

    def risk_scores(self, kind: str, values: list[str]) -> dict[str, Any]:
        """The risk scores of IPs or domains, SCORING_BATCH values a request; None for a value the answer has none for."""
        score = self.poller.get_ip_scoring if kind == "ip" else self.poller.get_domain_scoring
        scores: dict[str, Any] = {}
        for start in range(0, len(values), self.SCORING_BATCH):
            chunk = values[start : start + self.SCORING_BATCH]
            answer = score(chunk) or {}
            scores.update({value: dict_safe_get(answer, ["items", value, "riskScore"]) for value in chunk})
        return scores

    def ip_graph(self, value: str) -> Any:
        """The Graph WHOIS answer of an IP, None when the API has none."""
        try:
            return self.poller.graph_ip_search(value) or None
        except NotFoundException:
            return None

    def domain_graph(self, value: str) -> Any:
        """The Graph WHOIS answer of a domain, None when the API has none."""
        try:
            return self.poller.graph_domain_search(value) or None
        except NotFoundException:
            return None

    def _granted_names(self, wanted: Callable[[dict], bool]) -> frozenset[str]:
        known = TICollections.INFO.keys()
        return frozenset(
            str(item.get("collection")) for item in self.granted_collections() if wanted(item) and item.get("collection") in known
        )

    def _cached_grants(self) -> list[dict[str, Any]] | None:
        """The cached grants, None when they are absent or older than the TTL."""
        try:
            context = demisto.getIntegrationContext() or {}
        except Exception as exc:  # pragma: no cover - an unreadable context means no cache
            demisto.debug(f"[granted_collections] integration context unavailable: {exc}")
            return None
        entry = context.get(self.GRANTED_CACHE_KEY)
        if not isinstance(entry, dict):
            return None
        fetched_at = entry.get("fetched_at")
        items = entry.get("items")
        if not isinstance(fetched_at, int | float) or not isinstance(items, list):
            return None
        if self._clock() - fetched_at > self.GRANTED_CACHE_TTL_SECONDS:
            return None
        return [item for item in items if isinstance(item, dict)]

    def _cache_grants(self, items: list[dict[str, Any]]) -> None:
        try:
            context = demisto.getIntegrationContext() or {}
            context[self.GRANTED_CACHE_KEY] = {"fetched_at": self._clock(), "items": items}
            demisto.setIntegrationContext(context)
        except Exception as exc:  # pragma: no cover - a cache write failure must not break a command
            demisto.debug(f"[granted_collections] failed to persist the cache: {exc}")


""" MASKING """


class PasswordMask:
    """ "Mask passwords and leaked secrets": Off, Partial (first half and ****) or Full (dropped or withheld)."""

    OFF, PARTIAL, FULL = "Off", "Partial", "Full"
    MODES = (OFF, PARTIAL, FULL)
    WITHHELD = "[withheld]"
    # The parsed record's key of the password, per collection; a breached record carries a list.
    FIELDS = {
        TICollections.COMPROMISED_ACCOUNT_GROUP: "password",
        TICollections.COMPROMISED_BREACHEDDB: "passwords",
    }
    # The parsed record's key of the leak's own columns (addInfo); their names are open per leak (salt,
    # passwordFromAuthorizations0, token, passportNumber, ...).
    DETAILS_FIELDS = {TICollections.COMPROMISED_BREACHEDDB: "record_details"}
    # The collections whose texts can quote a password, besides the dark web posts.
    TEXT_COLLECTIONS = frozenset(
        {TICollections.COMPROMISED_ACCOUNT_GROUP, TICollections.COMPROMISED_BREACHEDDB, TICollections.OSI_PUBLIC_LEAK}
    )
    # A column holds a credential when its name has a word containing pass, pwd, psw, salt or token ("userpassword",
    # "accessToken", not "passport"), a session id ("sessionId", "PHPSESSID"), or password in another language or a common
    # misspelling ("senha", "pasword"); a word ending in pw ("userPw", "pw1"); a last word naming a secret
    # ("userSecret", "plaintext", not "secretQuestion"); a secret key as its last two words ("apiKey", "secret_key",
    # "sshKey", not "publicKey"); or only hash words, with or without pw, nt or lm ("md5_hash", "nt_hash", not
    # "emailHash"). A last word that dates, types or describes the credential ("passwordChangedAt", "hashType",
    # "pwdLastSet") rules it out.
    CREDENTIAL_RE = re.compile(
        r"pass|pwd|psw|pasw|pword|p4ss|salt|token|sessionid|sessid|senha|contrasena|parol|haslo|sifre|kennwort|wachtwoord"
        r"|losenord|heslo|jelszo|salasana|kodeord|lozinka|adgangskode"
    )
    # Password in Russian and Ukrainian, Chinese, Japanese and Korean, read before the name is folded to ASCII.
    NON_ASCII_CREDENTIAL_RE = re.compile(
        "\u043f\u0430\u0440\u043e\u043b|\u5bc6\u7801|\u53e3\u4ee4|\u30d1\u30b9\u30ef\u30fc\u30c9|\ube44\ubc00\ubc88\ud638"
    )
    NOT_CREDENTIAL_RE = re.compile(
        r"passport|passenger|compass|bypass|passive|passage|passion|passed|passing|passover|passthr|trespass|parole|tokeniz"
        r"|oldpwd"
    )
    PW_RE = re.compile(r"pw\d*$")
    SECRET_WORDS = frozenset(
        {"secret", "secrets", "credential", "credentials", "plain", "plaintext", "cleartext", "cracked", "mdp", "clave"}
        | {"apikey", "secretkey", "privatekey", "accesskey", "authkey"}
    )
    KEY_OWNERS = frozenset(
        {"api", "secret", "private", "priv", "access", "auth", "client", "encryption", "decryption", "master", "session"}
        | {"signing", "ssh", "recovery"}
    )
    HASH_RE = re.compile(
        r"(?:nt|lm)?hash(?:es|ed)?|md5|sha(?:1|224|256|384|512)?|ssha|bcrypt|scrypt|crypt|argon2|pbkdf2|ntlm|digest"
    )
    HASH_PARTNERS = frozenset({"pw", "nt", "lm"})
    DESCRIPTOR_WORDS = frozenset(
        {"at", "on", "date", "time", "timestamp", "created", "changed", "change", "updated", "modified", "reset"}
        | {"expiry", "expires", "expiration", "expired"}
        | {"type", "kind", "algorithm", "algo", "format", "scheme", "id", "file", "path", "ttl"}
        | {"length", "strength", "policy", "count", "required", "rounds", "size", "bits"}
        | {"visible", "visibility", "enabled", "disabled", "hidden", "field", "box", "label", "input", "prompt", "button"}
    )
    KEY_WORD_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z0-9]+(?![a-z])")
    # A flag, a placeholder or nothing: a credential column holding only these holds no credential.
    BLANK_VALUES = frozenset({"0", "1", "true", "false", "yes", "no", "null", "none", "nil", "-", "n/a"})
    # A key a text writes a secret after on one line: "password: S", "accessToken=S", '"clientSecret": "S"', "pwd => S".
    # The key decides, as a column name does; the value is read only after a credential key.
    KEY_RE = re.compile(
        r"(?<![\w.])(?P<key>[^\W\d][\w.-]{0,127})\\?[\"']?[^\S\n]*(?P<sep>:=|::?|=>|->|=|\uff1a)(?P<gap>[^\S\n]*)"
    )
    # A value unquoted runs to a space, a quote, a comma, a semicolon, an angle bracket or a backslash; an & only when the next
    # URL parameter follows it ("&page=2") and a closing bracket only when it closes what holds the value ("token=S)&next=").
    VALUE_RE = re.compile(
        r"\\?\"(?P<dq>[^\"\\\n]+)\\?\"|\\?'(?P<sq>[^'\\\n]+)\\?'"
        r"|(?P<bare>(?:[^\s\"'<>,;&)\]}\\]|&(?![\w.-]{1,64}=)|[)\]}](?=[^\s\"'<>,;&)\]}]))+)"
    )
    # Other places a text writes a secret by its key: "<dbPassword>S</dbPassword>", '<add key="DbPassword" value="S"/>',
    # "define('DB_PASSWORD', 'S')", 'ds.setPassword("S")' and "--password S".
    KEYED_SECRET_RES = (
        re.compile(
            r"<(?P<key>[^\W\d][\w:.-]{0,63})(?:[ \t][^<>\n]{0,200})?>[ \t]*(?:<!\[CDATA\[)?"
            r"(?P<secret>[^<\]\n]{0,255}[^<\]\s])[ \t]*(?:\]\]>)?</"
        ),
        re.compile(
            r"(?<![\w-])(?:key|name)[ \t]*=[ \t]*[\"'](?P<key>[^\"'<>\n]{1,64})[\"'][ \t]+value[ \t]*=[ \t]*"
            r"[\"'](?P<secret>[^\"'\n]+)[\"']"
        ),
        re.compile(r"(?<![\w-])key[ \t]*=[ \t]*[\"'](?P<key>[^\"'<>\n]{1,64})[\"'][^<>\n]{0,200}>(?P<secret>[^<\n]{1,256})</"),
        re.compile(r"\bdefine\([ \t]*[\"'](?P<key>[^\"'\n]{1,64})[\"'][ \t]*,[ \t]*[\"'](?P<secret>[^\"'\n]+)[\"']"),
        re.compile(r"\.set(?P<key>[A-Z]\w{0,63})\([ \t]*[\"'](?P<secret>[^\"'\n]+)[\"']"),
    )
    # A command-line flag and its value; a value in capitals alone ("--password PASSWORD") is a usage placeholder.
    FLAG_SECRET_RE = re.compile(r"(?<!\S)--(?P<key>[a-z][\w-]{1,40})[ \t]+(?P<secret>[^\s\"'<>-][^\s\"'<>]*)")
    # Nouns a sentence uses as a heading ("Credentials: ask the admin"): after one of them, a colon and a space, a word
    # without a digit, a symbol or a capital after its first letter is prose, not a secret.
    PROSE_KEYS = frozenset({"credential", "credentials", "secrets"})
    SECRET_SHAPE_RE = re.compile(r"[^A-Za-z]|.[A-Z]")
    # A plural key before a number counts things ("Passwords: 12000", "Passwords: 2.5k"); it does not quote one.
    COUNT_KEYS = frozenset({"passwords", "credentials", "secrets", "tokens", "creds", "logins", "cookies"})
    COUNT_RE = re.compile(r"\d+(?:[.,]\d+)?[kKmM]?\+?")
    PORT_RE = re.compile(r"\d{1,5}(?:/|$)")
    # The password of a user:password@host URL, an empty user included.
    URL_SECRET_RE = re.compile(r"(?i)(?<![\w+.-])[a-z][a-z0-9+.-]{1,20}://[^/\s:@]{0,128}:(?P<secret>[^/\s@]{1,256})@")
    # The password of an e-mail:password pair, up to a space, a separator, the next pair (",b@example.com:...") or the
    # quote that opened the pair; after ; or | only when it ends its line.
    PAIR_SECRET_RE = re.compile(
        r"(?<![\w.+-])(?P<quote>[\"']?)[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}[\"']?(?P<sep>[:;|])[\"']?"
        r"(?P<secret>[^\s:;|]{1,256})"
    )
    NEXT_PAIR_RE = re.compile(r",(?=[\w.+-]+@)")
    # After an e-mail address and a colon: a port, a path, a date or a repository rather than a password.
    NOT_PAIR_SECRET_RE = re.compile(r"\d{1,5}(?:/|$)|[/~]|\d{4}-\d{2}-\d{2}|.*\.git$")
    # An Authorization header's credential: after its scheme, or a value with a digit, a symbol or an inner capital.
    HEADER_SECRET_RE = re.compile(
        r"(?i)\bauthorization[\"']?[ \t]*[:=][ \t]*[\"']?(?:(?P<scheme>bearer|basic|token|digest)[ \t]+)?"
        r"(?P<secret>[^\s\"',;{\[][^\s\"',;]*)"
    )
    # A credential has a digit, a symbol or an inner capital, or is longer than a word: that tells it from the words
    # "basic" and "bearer" in prose. A Basic credential is base64, without the hyphen of "Basic Life-Support".
    BEARER_SECRET_RE = re.compile(r"(?i)\b(?P<scheme>bearer|basic)[ \t]+(?P<secret>[A-Za-z0-9._~+/-]{8,}=*)")
    CREDENTIAL_SYMBOL_RE = re.compile(r"[\d+/=._~-]|.[A-Z]")
    BASIC_CREDENTIAL_RE = re.compile(r"(?=.*(?:[\d+/=]|[a-z][A-Z]))[A-Za-z0-9+/]+=*")
    # A secret recognizable by its own shape: a crypt hash ($2y$..., $6$...), the hashes of an NTLM dump line and the
    # tokens of GitHub, GitLab, Slack and Stripe.
    SHAPED_SECRET_RES = (
        re.compile(r"(?P<secret>\$(?:2[abxy]?|1|5|6|y|gy|7|argon2(?:id|i|d))\$[^\s:\"'<>]{8,})"),
        re.compile(r"\b(?P<secret>(?:gh[pousr]_|github_pat_|glpat-|xox[abprs]-|[sr]k_live_)[A-Za-z0-9_-]{10,})"),
    )
    NTLM_LINE_RE = re.compile(r"(?m)^[^\s:]{1,64}:\d{1,10}:(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32})(?=:)")
    PEM_HEADER_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
    # The time at the end of a URL's query ("?ts=2026-11-03T10:30:45Z"), whose colons a login line would misread.
    TIME_END_RE = re.compile(r"\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$")
    LINE_RE = re.compile(r"[^\n]+")
    LINE_END_RE = re.compile(r"[^\S\n]*(?:\n|\Z)")
    SPACE_RE = re.compile(r"\s")
    EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
    WORD_RE = re.compile(r"[^\W_]+")
    # A secret is looked for in the record's other texts from six characters; one the record names (its password, a
    # credential column, a detector's value), from four in a text with spaces. Shorter ones, or short ones in a date, a
    # host or an id, would hide years, words and numbers.
    MIN_SECRET = 6
    MIN_NAMED_SECRET = 4
    # The fields that name a record's account: a login, an address or a domain there is not searched for copies of a
    # password, or the incident, its playbook and the login filters would read the wrong account. A login:password
    # or a URL in them is masked.
    IDENTITY_KEYS = {
        TICollections.COMPROMISED_ACCOUNT_GROUP: frozenset({"id", "name", "login", "parsedLogin", "service"}),
        TICollections.COMPROMISED_BREACHEDDB: frozenset({"id", "name", "emails", "emailDomains"}),
    }
    IDENTITY_VALUE_RE = re.compile(r"(?:[\w.-]+\\)?[\w.+-]+(?:@[\w.-]+)?")
    # An account's C&C, which also becomes its indicators, is the attacker's: its credentials are no victim's secret.
    ATTACKER_KEYS = frozenset({"indicators", "cnc"})

    def __init__(self, mode: str = OFF) -> None:
        if mode not in self.MODES:
            raise DemistoException(f"'Mask passwords and leaked secrets' must be one of {', '.join(self.MODES)}, got {mode!r}.")
        self.mode = mode

    @classmethod
    def from_params(cls, params: dict) -> "PasswordMask":
        raw = str(params.get("mask_passwords") or cls.OFF).strip()
        mode = next((mode for mode in cls.MODES if mode.lower() == raw.lower()), raw)
        return cls(mode)

    def apply(self, collection_name: str, record: Any) -> Any:
        """``record`` with its passwords and leaked secrets masked when the setting and the collection call for it."""
        if self.mode == self.OFF or not isinstance(record, dict):
            return record
        has_texts = collection_name in self.TEXT_COLLECTIONS or CollectionSpec.of(collection_name).darkweb_post
        exempt = self.ATTACKER_KEYS if collection_name == TICollections.COMPROMISED_ACCOUNT_GROUP else frozenset()
        if collection_name == TICollections.OSI_PUBLIC_LEAK:
            exempt = frozenset({"matches"})
        # The secrets each text quotes, found once: they are also looked for in the record's other texts.
        quoted = {text: self._secret_spans(text) for text in self._texts(record, exempt)} if has_texts else {}
        index = self._secret_index(self._known_secrets(collection_name, record, quoted)) if has_texts else {}
        field = self.FIELDS.get(collection_name)
        if field is not None and field in record:
            if self.mode == self.FULL:
                record.pop(field)
            else:
                record[field] = self._partial(record[field])
        details_field = self.DETAILS_FIELDS.get(collection_name)
        if details_field is not None and isinstance(record.get(details_field), dict):
            record[details_field] = self._masked_columns(record[details_field])
        if collection_name == TICollections.OSI_PUBLIC_LEAK:
            if record.get("matches") is not None:
                # Every value a detector extracted is a secret or the victim's own data; the categories and counts stay.
                record["matches"] = self._masked_values(record["matches"])
            if self.mode == self.FULL and record.get("data"):
                record["data"] = self.WITHHELD
        if has_texts:
            identity = self.IDENTITY_KEYS.get(collection_name, frozenset())
            record = {
                key: item if key in exempt else self._masked_texts(item, index, exempt, quoted, key in identity)
                for key, item in record.items()
            }
        return record

    @classmethod
    def _known_secrets(cls, collection_name: str, record: dict, quoted: dict[str, list[tuple[int, int]]]) -> list[str]:
        """The passwords and secrets the record names or its texts quote, to mask wherever its texts repeat them."""
        named = cls._column_values(record.get(cls.FIELDS.get(collection_name, ""))) + cls._credentials(
            cls._details(collection_name, record), quoted=False
        )
        if collection_name == TICollections.OSI_PUBLIC_LEAK:
            named += cls._column_values(record.get("matches"))
        return [secret for secret in named if len(secret) >= cls.MIN_NAMED_SECRET] + [
            text[start:end] for text, spans in quoted.items() for start, end in spans if end - start >= cls.MIN_SECRET
        ]

    def mask_inline(self, text: str) -> str:
        """The text with each secret it quotes masked: see ``inline_secrets``."""
        return self._masked_spans(text, self._secret_spans(text))

    @classmethod
    def inline_secrets(cls, text: str) -> list[str]:
        """The secrets a text quotes: after a credential key, in a pair, URL, login line or header, or known by their shape."""
        return [text[start:end] for start, end in cls._merged(cls._secret_spans(text))]

    @classmethod
    def _secret_spans(cls, text: str) -> list[tuple[int, int]]:
        spans = []
        position = 0
        while (match := cls.KEY_RE.search(text, position)) is not None:
            position = match.end()
            key = match.group("key")
            value = cls.VALUE_RE.match(text, position) if cls._names_credential(key, True) else None
            if value is None:
                continue
            group = next(name for name in ("dq", "sq", "bare") if value.group(name) is not None)
            secret = value.group(group)
            bare = group == "bare"
            words = cls.KEY_WORD_RE.findall(key)
            # A dotted name and a short number after a colon are a host and its port.
            is_port = bare and "." in key and match.group("sep") in (":", "\uff1a") and cls.PORT_RE.match(secret) is not None
            is_word = (
                bare
                and match.group("sep") in (":", "\uff1a")
                and bool(match.group("gap"))
                and key.lower() in cls.PROSE_KEYS
                and not cls.SECRET_SHAPE_RE.search(secret)
            )
            is_count = bare and bool(words) and words[-1].lower() in cls.COUNT_KEYS and cls.COUNT_RE.fullmatch(secret)
            # A path ("PWD=/home/sample") names a place, not a secret.
            is_path = bare and secret.startswith("/") and secret.count("/") > 1
            if not (is_port or is_word or is_count or is_path) and cls._is_secret_value(secret):
                spans.append(value.span(group))
                position = value.end()
        for pattern in cls.KEYED_SECRET_RES:
            spans += [
                match.span("secret")
                for match in pattern.finditer(text)
                if cls._is_secret_value(match.group("secret")) and cls._names_credential(match.group("key"), True)
            ]
        spans += [
            match.span("secret")
            for match in cls.FLAG_SECRET_RE.finditer(text)
            if not (match.group("secret").isalpha() and match.group("secret").isupper())
            and cls._is_secret_value(match.group("secret"))
            and cls._names_credential(match.group("key"), True)
        ]
        position = 0
        while (match := cls.PAIR_SECRET_RE.search(text, position)) is not None:
            start = match.start("secret")
            secret = match.group("secret")
            cut = cls.NEXT_PAIR_RE.search(secret)
            secret = secret[: cut.start()] if cut else secret
            if match.group("quote"):
                secret = secret.split(match.group("quote"))[0]
            end = start + len(secret)
            position = max(end, match.start() + 1)
            if match.group("sep") == ":":
                holds = cls.NOT_PAIR_SECRET_RE.match(secret) is None
            else:
                holds = cls.LINE_END_RE.match(text, end) is not None
            if holds and cls._is_secret(secret):
                spans.append((start, end))
        for pattern in (cls.URL_SECRET_RE, *cls.SHAPED_SECRET_RES):
            spans += [match.span("secret") for match in pattern.finditer(text) if cls._is_secret(match.group("secret"))]
        spans += [
            match.span("secret")
            for match in cls.HEADER_SECRET_RE.finditer(text)
            if (match.group("scheme") or cls.SECRET_SHAPE_RE.search(match.group("secret")))
            and match.group("secret").lower() not in cls.BLANK_VALUES
            and cls._is_secret(match.group("secret"))
        ]
        for match in cls.NTLM_LINE_RE.finditer(text):
            spans += [match.span("lm"), match.span("nt")]
        for match in cls.PEM_HEADER_RE.finditer(text):
            end = text.find("-----END", match.end(), match.end() + 16384)
            if end > match.end():
                spans.append((match.end(), end))
        spans += [
            match.span("secret")
            for match in cls.BEARER_SECRET_RE.finditer(text)
            if (
                (
                    cls.BASIC_CREDENTIAL_RE.fullmatch(match.group("secret"))
                    if match.group("scheme").lower() == "basic"
                    else cls.CREDENTIAL_SYMBOL_RE.search(match.group("secret"))
                )
                or len(match.group("secret")) >= 20
            )
            and cls._is_secret(match.group("secret"))
        ]
        return spans + cls._login_line_spans(text)

    @classmethod
    def _login_line_spans(cls, text: str) -> list[tuple[int, int]]:
        """The password of each url:login:password or url|login|password line, the line format of stealer logs."""
        spans = []
        for line in cls.LINE_RE.finditer(text):
            value = line.group(0).strip()
            if len(value) > 2048 or "://" not in value or cls.SPACE_RE.search(value):
                continue
            secret_at = max(value.rfind(":"), value.rfind("|")) + 1
            login_at = max(value.rfind(":", 0, secret_at - 1), value.rfind("|", 0, secret_at - 1)) + 1
            secret, login = value[secret_at:], value[login_at : secret_at - 1]
            if login_at <= 0 or "://" not in value[:login_at] or not login or "/" in login or "/" in secret:
                continue
            # An IPv6 address, a port, a time, a URN or a text fragment after the URL rather than a login and a password.
            if (
                "[" in value
                or "urn:" in value
                or "#:~:" in value
                or cls.PORT_RE.fullmatch(secret)
                or cls.TIME_END_RE.search(value)
            ):
                continue
            if cls._is_secret(secret):
                start = line.start() + line.group(0).index(value) + secret_at
                spans.append((start, start + len(secret)))
        return spans

    @classmethod
    def _is_secret_value(cls, value: str) -> bool:
        """Whether a value after a credential key is a secret rather than a flag, a placeholder or a masked value."""
        return value.strip().lower() not in cls.BLANK_VALUES and cls._is_secret(value)

    @classmethod
    def _is_secret(cls, value: str) -> bool:
        """Whether a value is a secret rather than a masked one or an e-mail address."""
        return bool(value) and not value.endswith("****") and cls.WITHHELD not in value and not cls.EMAIL_RE.fullmatch(value)

    @staticmethod
    def _merged(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(spans):
            if merged and start < merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    def _masked_spans(self, text: str, spans: list[tuple[int, int]], known: list[tuple[int, int]] | None = None) -> str:
        """The text with each span masked; a span that covers a known secret is masked whole, or only in the secrets it quotes."""
        marked = sorted([(start, end, False) for start, end in spans] + [(start, end, True) for start, end in known or ()])
        merged: list[tuple[int, int, bool]] = []
        for start, end, is_known in marked:
            if merged and start < merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end), merged[-1][2] or is_known)
            else:
                merged.append((start, end, is_known))
        pieces: list[str] = []
        position = 0
        for start, end, is_known in merged:
            part = text[start:end]
            pieces += [text[position:start], self._masked_snippet(part) if is_known else self._secret(part)]
            position = end
        return "".join(pieces) + text[position:]

    def _masked_snippet(self, snippet: str) -> str:
        """A secret masked whole, or only the secrets it holds, such as the password of a detector's login:password value."""
        inner = self._merged(self._secret_spans(snippet))
        if not inner:
            return self._secret(snippet)
        pieces: list[str] = []
        position = 0
        for start, end in inner:
            pieces += [snippet[position:start], self._secret(snippet[start:end])]
            position = end
        return "".join(pieces) + snippet[position:]

    @classmethod
    def _secret_index(cls, secrets: list[str]) -> dict[str, list[tuple[int, int, frozenset[str]]]]:
        """The secrets by first word, then by that word's offset and by length, longest first, for a one-pass lookup."""
        groups: dict[tuple[str, int, int], set[str]] = {}
        for secret in set(secrets):
            word = cls.WORD_RE.search(secret)
            # A secret of symbols alone ("!@#$%^&*") is filed under no word and looked for as it is.
            key = (word.group(0), word.start(), len(secret)) if word else ("", 0, len(secret))
            groups.setdefault(key, set()).add(secret)
        index: dict[str, list[tuple[int, int, frozenset[str]]]] = {}
        for (first, offset, length), group in sorted(groups.items(), key=lambda item: -item[0][2]):
            index.setdefault(first, []).append((offset, length, frozenset(group)))
        return index

    @classmethod
    def _known_spans(cls, text: str, index: dict[str, list[tuple[int, int, frozenset[str]]]]) -> list[tuple[int, int]]:
        """Where the text repeats a known secret as a whole: not inside a longer word or number."""
        spans = []
        short = cls.SPACE_RE.search(text) is not None
        for word in cls.WORD_RE.finditer(text) if index else ():
            for offset, length, group in index.get(word.group(0), ()):
                start = word.start() - offset
                end = start + length
                if (
                    (length >= cls.MIN_SECRET or short)
                    and start >= 0
                    and text[start:end] in group
                    and not cls._alnum_at(text, start - 1)
                    and not cls._alnum_at(text, end)
                ):
                    spans.append((start, end))
                    break
        for _, length, group in index.get("", ()):
            for secret in group if length >= cls.MIN_SECRET or short else ():
                start = text.find(secret)
                while start >= 0:
                    if not cls._alnum_at(text, start - 1) and not cls._alnum_at(text, start + length):
                        spans.append((start, start + length))
                    start = text.find(secret, start + 1)
        return spans

    @staticmethod
    def _alnum_at(text: str, position: int) -> bool:
        return 0 <= position < len(text) and text[position].isalnum()

    @classmethod
    def is_credential_key(cls, key: Any) -> bool:
        return cls._names_credential(str(key), False)

    @classmethod
    @lru_cache(maxsize=4096)
    def _names_credential(cls, key: str, in_text: bool) -> bool:
        if cls.NON_ASCII_CREDENTIAL_RE.search(key.lower()):
            return True
        ascii_key = unicodedata.normalize("NFKD", key.replace("\u0142", "l").replace("\u0141", "L"))
        words = [word.lower() for word in cls.KEY_WORD_RE.findall(ascii_key.encode("ascii", "ignore").decode())]
        if words[-2:] == ["session", "id"]:
            return True
        if not words or (len(words) > 1 and words[-1] in cls.DESCRIPTOR_WORDS) or words[-2:] == ["last", "set"]:
            return False
        rests = [cls.HASH_RE.sub("", word) for word in words]
        if all(rest in ("", *cls.HASH_PARTNERS) for rest in rests) and (rests != words or "pw" in words):
            # In a text, a hash name alone ("MD5: ...") names a file's hash far more often than a password's.
            return not in_text or "pw" in rests
        if words[-1] in cls.SECRET_WORDS or any(cls.PW_RE.search(word) for word in words):
            return True
        if len(words) > 1 and words[-1] == "key" and words[-2] in cls.KEY_OWNERS:
            return True
        return any(
            cls.CREDENTIAL_RE.search(cls.NOT_CREDENTIAL_RE.sub(" ", word))
            and not (word == "pass" and words[index + 1 : index + 2] == ["port"])
            for index, word in enumerate(words)
        )

    @classmethod
    def credentials_in_details(cls, collection_name: str, record: Any) -> list[str]:
        """The values of a breached record's credential columns, at any depth, and the secrets its other columns quote."""
        return cls._credentials(cls._details(collection_name, record), quoted=True)

    @classmethod
    def _credentials(cls, value: Any, quoted: bool) -> list[str]:
        if isinstance(value, dict):
            return [
                text
                for key, item in value.items()
                for text in (cls._column_values(item) if cls.is_credential_key(key) else cls._credentials(item, quoted))
            ]
        if isinstance(value, list):
            return [text for item in value for text in cls._credentials(item, quoted)]
        return cls.inline_secrets(value) if quoted and isinstance(value, str) else []

    @classmethod
    def _texts(cls, value: Any, exempt: frozenset[str]) -> Iterator[str]:
        if isinstance(value, dict):
            for key, item in value.items():
                if key not in exempt:
                    yield from cls._texts(item, exempt)
        elif isinstance(value, list):
            for item in value:
                yield from cls._texts(item, exempt)
        elif isinstance(value, str) and value:
            yield value

    def _masked_columns(self, value: Any) -> Any:
        """A leak's columns at any depth, each credential column holding a value cut to its first half or dropped under Full."""
        if isinstance(value, dict):
            masked: dict = {}
            for key, item in value.items():
                if not (self.is_credential_key(key) and self._column_values(item)):
                    masked[key] = self._masked_columns(item)
                elif self.mode != self.FULL:
                    masked[key] = self._partial(item)
            return masked
        if isinstance(value, list):
            return [self._masked_columns(item) for item in value]
        return value

    def _masked_values(self, value: Any) -> Any:
        """Every text of ``value`` masked, its structure and counts kept."""
        if isinstance(value, dict):
            return {key: self._masked_values(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._masked_values(item) for item in value]
        return self._masked_snippet(value) if isinstance(value, str) and value else value

    def _masked_texts(
        self,
        value: Any,
        index: dict[str, list[tuple[int, int, frozenset[str]]]],
        exempt: frozenset[str],
        quoted: dict[str, list[tuple[int, int]]],
        identity: bool = False,
    ) -> Any:
        """Every text of ``value`` outside the exempt keys with the known secrets and the secrets it quotes masked."""
        if isinstance(value, dict):
            return {
                key: item if key in exempt else self._masked_texts(item, index, exempt, quoted, identity)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._masked_texts(item, index, exempt, quoted, identity) for item in value]
        if not isinstance(value, str) or not value:
            return value
        spans = quoted[value] if value in quoted else self._secret_spans(value)
        known = self._known_spans(value, index)
        if identity:
            if self.IDENTITY_VALUE_RE.fullmatch(value):
                # A login, an address or a domain stays whole; in DOMAIN\user a copy of the password in the domain is masked.
                known = [span for span in known if span[1] <= value.find("\\")]
            else:
                # Any other shape stays only when the whole of it is the password: anything more can hold it.
                known = [span for span in known if span != (0, len(value))]
        return self._masked_spans(value, spans, known)

    def _secret(self, value: str) -> str:
        return self.WITHHELD if self.mode == self.FULL else self._partial(value)

    @classmethod
    def _column_values(cls, value: Any) -> list[str]:
        if isinstance(value, dict):
            value = list(value.values())
        if isinstance(value, list):
            return [text for item in value for text in cls._column_values(item)]
        return [] if isinstance(value, bool) else [text for text in texts(value) if text.lower() not in cls.BLANK_VALUES]

    @classmethod
    def _details(cls, collection_name: str, record: Any) -> dict:
        details = record.get(cls.DETAILS_FIELDS.get(collection_name, "")) if isinstance(record, dict) else None
        return details if isinstance(details, dict) else {}

    @staticmethod
    def _partial(value: Any) -> Any:
        """The first half of each part of a secret followed by ****; a cell can hold several, split by spaces or ,;|."""
        if isinstance(value, list):
            return [PasswordMask._partial(item) for item in value]
        if isinstance(value, dict):
            return {key: PasswordMask._partial(item) for key, item in value.items()}
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str) or not value:
            return value
        parts = re.split(r"([\s,;|]+)", value)
        if not any(parts[::2]):
            return value[: len(value) // 2] + "****"
        return "".join(part if index % 2 or not part else part[: len(part) // 2] + "****" for index, part in enumerate(parts))


class CardDataMask:
    """ "Mask card data": the first six and last four digits of a card number kept, the CVV dropped, the cardholder redacted."""

    COLLECTIONS = frozenset({TICollections.COMPROMISED_BANK_CARD_GROUP, TICollections.COMPROMISED_MASKED_CARD})
    # The record-level keys that hold the card number.
    NUMBER_KEYS = ("name", "number")
    REDACTED = "[redacted]"
    # The cardholder columns of the events table.
    EVENT_REDACTED_KEYS = ("victim_name", "victim_phone")
    # The record-level keys of a masked card's owner.
    MASKED_CARD_OWNER_KEYS = (
        "owner_name",
        "address",
        "owner_birthday",
        "email",
        "phone",
        "owner_city",
        "owner_zip",
        "owner_passport",
        "owner_tax_number",
    )

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    @classmethod
    def from_params(cls, params: dict) -> "CardDataMask":
        return cls(argToBoolean(params.get("mask_card_data") or False))

    @staticmethod
    def mask_number(value: Any) -> Any:
        """Every digit but the first six and the last four as X; a number too short for a card keeps its last four only."""
        if isinstance(value, list):
            return [CardDataMask.mask_number(item) for item in value]
        if not isinstance(value, str) or not value:
            return value
        if len(value) >= 13:
            return value[:6] + "X" * (len(value) - 10) + value[-4:]
        return "X" * max(len(value) - 4, 0) + value[-4:]

    def apply(self, collection_name: str, record: Any) -> Any:
        """``record`` with its card data masked when the setting and the collection call for it."""
        if not self.enabled or collection_name not in self.COLLECTIONS or not isinstance(record, dict):
            return record
        if collection_name == TICollections.COMPROMISED_MASKED_CARD:
            for key in self.MASKED_CARD_OWNER_KEYS:
                if record.get(key) not in (None, "", []):
                    record[key] = self.REDACTED
            return record
        for key in self.NUMBER_KEYS:
            if key in record:
                record[key] = self.mask_number(record[key])
        if "cvv" in record:
            record["cvv"] = None
        events = record.get("compromised_events")
        if isinstance(events, dict):
            if "cvv" in events:
                events["cvv"] = [None for _ in self._per_event(events["cvv"])]
            for key in self.EVENT_REDACTED_KEYS:
                if key in events:
                    events[key] = [self.REDACTED if value else value for value in self._per_event(events[key])]
        return record

    @staticmethod
    def _per_event(values: Any) -> list:
        """The column of the events table as a list; a record with one event may carry a scalar."""
        return values if isinstance(values, list) else [values]


class PostTextMask:
    """ "Mask dark web post text": Off, Partial (card numbers cut to the last four, CVV codes cleared) or Full (text withheld)."""

    OFF, PARTIAL, FULL = "Off", "Partial", "Full"
    MODES = (OFF, PARTIAL, FULL)
    # The keys that carry the post's text at any depth: the post, its translation, a cleaned copy, the text of its
    # images and the portal's highlighted copy, in the post itself, its edits and the post it replies to.
    TEXT_KEYS = frozenset({"text", "translation", "clearText", "imageText", "highlight"})
    # A markup tag, as a highlighted copy wraps around the matched text: its digits are never card digits.
    TAG = r"</?[A-Za-z][^<>\n\r]{0,39}>"
    # A run of digits, or groups of three to ten digits split by one to three tags or characters that are neither
    # letters, digits nor line breaks: the text a card number can hide in on one line. _cut_cards decides which part
    # is one.
    CARD_CANDIDATE_RE = re.compile(
        r"(?<!\d)\d{3,19}(?:(?:" + TAG + r"|[^\w\n\r\v\f\x1c-\x1e\x85\u2028\u2029]|_){1,3}\d{3,10})*(?!\d)"
    )
    GROUP_RE = re.compile(TAG + r"|\d+")
    # An IPv4 address of four parts: its octets are never card digits, even when they pass the check digit. A port is
    # read like any other number, as a card may follow the colon.
    IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)")
    CVV_RE = re.compile(r"\b(CVV2?|CVC2?|CV2|CID)\s*(?:[:=]\s*)?\d{3,4}\b", re.IGNORECASE)
    CARD_CUT = r"(?<![\d*])\d{0,6}\*{6,}\d{4}"
    # A CVV written before the expiry: MM|YY, MM|YYYY, YYYY|MM or YY|MM, with SEP for the line's separator, or MMYY or MMYYYY
    # after three digits only, as 1229|1234 is an expiry and a four-digit CVV.
    CVV_BEFORE_EXPIRY = (
        r"(?:\d{3,4}(?=SEP(?:(?:0?[1-9]|1[0-2])SEP(?:20\d{2}|\d{2})|20\d{2}SEP(?:0?[1-9]|1[0-2])|\d{2}SEP(?:0?[1-9]|1[0-2]))(?!\d))"
        r"|\d{3}(?=SEP(?:0[1-9]|1[0-2])(?:20)?\d{2}(?!\d)))"
    )
    # A CVV is no year: a date after a card number stays.
    NO_YEAR = r"(?!(?:19|20)\d\d(?!\d))"
    LINE_SEP = r"(?:[ \t]*[|:;,/=.\-][ \t]*|[ \t]+)"
    # The cardholder's name, which a dump line can hold between the card number, the expiry and the CVV.
    LINE_NAME = r"(?:[A-Za-z][A-Za-z .'\-]{0,40}" + LINE_SEP + r")?"
    # An amount there stays: "12/25 500$", "12/25 500 USD".
    NO_AMOUNT = (
        r"(?![\w$\u20ac\u00a3]|[.,]\d|[ \t]*(?:[$\u20ac\u00a3]|(?i:USD|EUR|RUB|GBP|BTC|ETH|USDT|dollars?|rub(?:les?)?)\b))"
    )
    # A dump line's CVV, without a label, after the card number and its expiry (PAN|MM|YY|CVV, PAN|MM/YY|CVV, PAN|MMYY|CVV,
    # PAN|YYYY|MM|CVV).
    CARD_LINE_CVV_RE = re.compile(
        "("
        + CARD_CUT
        + LINE_SEP
        + LINE_NAME
        + r"(?:\d{1,4}[|:;,/\-. \t]{1,3}\d{2,4}|\d{4}|\d{6})"
        + LINE_SEP
        + LINE_NAME
        + ")"
        + NO_YEAR
        + r"\d{3,4}"
        + NO_AMOUNT
    )
    # A dump line that writes the CVV before the expiry (PAN|CVV|MM|YY).
    CVV_FIRST_RE = re.compile("(" + CARD_CUT + LINE_SEP + LINE_NAME + ")" + NO_YEAR + CVV_BEFORE_EXPIRY.replace("SEP", LINE_SEP))
    # What magnetic stripe data holds after the card number: the expiry, service code and discretionary data.
    TRACK_RE = re.compile("(" + CARD_CUT + r"(?:=|\^[^^\r\n]{0,26}\^))[\d*]{7,}\d*")
    # A URL's percent-encoded character, read whole: its digits belong to no number.
    URL_ESCAPE = r"%[0-9A-Fa-f]{2}"
    URL_SEP = r"(?:[ |:;,/=_.+~\-]|" + URL_ESCAPE + ")"
    # Runs of digit groups in a URL: a number there is a card only by its check digit, the others are ids.
    URL_CARD_RE = re.compile(URL_ESCAPE + r"|(?:(?<!\d)|(?<=%[0-9A-Fa-f]{2}))\d{3,19}(?:" + URL_SEP + r"{1,3}\d{3,10})*(?!\d)")
    URL_GROUP_RE = re.compile(URL_ESCAPE + r"|\d+")
    URL_NAME = r"(?:[A-Za-z]{1,40}" + URL_SEP + r")?"
    URL_LINE_CVV_RE = re.compile(
        "("
        + CARD_CUT
        + URL_SEP
        + URL_NAME
        + r"(?:\d{1,4}"
        + URL_SEP
        + r"\d{2,4}|\d{4}|\d{6})"
        + URL_SEP
        + URL_NAME
        + ")"
        + NO_YEAR
        + r"\d{3,4}(?!\d)"
    )
    URL_CVV_FIRST_RE = re.compile("(" + CARD_CUT + URL_SEP + ")" + NO_YEAR + CVV_BEFORE_EXPIRY.replace("SEP", URL_SEP))
    URL_TRACK_RE = re.compile("(" + CARD_CUT + r"(?:=|%3[Dd]|(?:\^|%5[Ee]).{0,60}?(?:\^|%5[Ee])))[\d*]{7,}\d*")
    # A label takes a query's separators only: "free-cc-cvv.1234" is a thread's address.
    URL_CVV_RE = re.compile(
        r"((?:cvv2?|cvc2?|cv2)(?:_?code)?(?:\]|%5[Dd])?(?:[ +=:]|%20|%3[Dd]|%3[Aa]){1,3})\d{3,4}(?!\d)", re.IGNORECASE
    )
    # A forum post's subject, which can quote the post: Partial masks it, Full withholds it;
    # its URL keeps its address and is masked as a text is.
    SUBJECT_KEYS = ("name", "topic")
    WITHHELD = "[withheld]"

    def __init__(self, mode: str = OFF) -> None:
        if mode not in self.MODES:
            raise DemistoException(f"'Mask dark web post text' must be one of {', '.join(self.MODES)}, got {mode!r}.")
        self.mode = mode

    @classmethod
    def from_params(cls, params: dict) -> "PostTextMask":
        raw = str(params.get("mask_post_text") or cls.OFF).strip()
        return cls(next((mode for mode in cls.MODES if mode.lower() == raw.lower()), raw))

    def apply(self, collection_name: str, record: Any) -> Any:
        """The record with every text key masked; a record of another collection as it is."""
        if self.mode == self.OFF or not CollectionSpec.of(collection_name).darkweb_post:
            return record
        masked = self._masked(record)
        if collection_name == TICollections.DARKWEB_FORUMS and isinstance(masked, dict):
            for key in self.SUBJECT_KEYS:
                if isinstance(masked.get(key), str) and masked[key]:
                    masked[key] = self.WITHHELD if self.mode == self.FULL else self.mask_text(masked[key])
            # Under Full the incident takes its name from the forum.
            if self.mode == self.FULL:
                masked.pop("name", None)
            if isinstance(masked.get("url"), str):
                masked["url"] = self.masked_url(masked["url"])
        return masked

    @classmethod
    def masked_url(cls, url: str) -> str:
        """The URL with card numbers cut to the last four digits; labeled and dump-line CVV codes and stripe data cleared."""
        cards = cls._outside_addresses(url, lambda part: cls.URL_CARD_RE.sub(cls._cut_url_cards, part))
        cards = cls.URL_TRACK_RE.sub(r"\1***", cards)
        cards = cls.URL_CVV_FIRST_RE.sub(r"\1***", cards)
        cards = cls.URL_LINE_CVV_RE.sub(r"\1***", cards)
        return cls.URL_CVV_RE.sub(r"\1***", cards)

    @classmethod
    def _cut_url_cards(cls, match: re.Match) -> str:
        return cls._cut_cards(match.group(0), url=True)

    @classmethod
    def _outside_addresses(cls, text: str, change: Callable[[str], str]) -> str:
        """The text with ``change`` applied around its IPv4 addresses."""
        pieces: list[str] = []
        position = 0
        for address in cls.IPV4_RE.finditer(text):
            pieces += [change(text[position : address.start()]), address.group(0)]
            position = address.end()
        return "".join(pieces) + change(text[position:])

    @classmethod
    def mask_text(cls, text: str) -> str:
        """The text with card numbers cut to the last four digits; labeled and dump-line CVV codes and stripe data cleared."""
        cards = cls._outside_addresses(text, cls._cut_card_numbers)
        cards = cls.CVV_RE.sub(lambda match: f"{match.group(1)}: ***", cards)
        cards = cls.TRACK_RE.sub(r"\1***", cards)
        cards = cls.CVV_FIRST_RE.sub(r"\1***", cards)
        return cls.CARD_LINE_CVV_RE.sub(r"\1***", cards)

    @classmethod
    def _cut_card_numbers(cls, text: str) -> str:
        """The text with the card numbers of each run of digit groups cut."""
        return cls.CARD_CANDIDATE_RE.sub(lambda match: cls._cut_cards(match.group(0)), text)

    @classmethod
    def _cut_cards(cls, chunk: str, url: bool = False) -> str:
        """The chunk with each card number cut to its last four digits: one run of 13 to 19 digits, or Luhn-valid groups.

        A run in a URL needs the Luhn check too; numbers that share a group are cut as one."""
        found = (cls.URL_GROUP_RE if url else cls.GROUP_RE).finditer(chunk)
        groups = [match for match in found if not match.group(0).startswith(("<", "%"))]
        runs: list[list[int]] = []
        for start in range(len(groups)):
            end = None
            digits = ""
            # A span stops growing past 19 digits, which keeps a long line of digit groups linear.
            for stop in range(start, len(groups)):
                digits += groups[stop].group(0)
                if len(digits) > 19:
                    break
                if len(digits) >= 13 and ((stop == start and not url) or cls._luhn(digits)):
                    end = stop
            if end is None:
                continue
            if runs and start <= runs[-1][1]:
                runs[-1][1] = max(runs[-1][1], end)
            else:
                runs.append([start, end])
        pieces: list[str] = []
        position = 0
        for first, last in runs:
            digits = "".join(group.group(0) for group in groups[first : last + 1])
            pieces += [chunk[position : groups[first].start()], "*" * (len(digits) - 4) + digits[-4:]]
            position = groups[last].end()
        return "".join(pieces) + chunk[position:]

    @staticmethod
    def _luhn(digits: str) -> bool:
        """Whether the digits end in a valid Luhn check digit, as every payment card number does."""
        total = 0
        for index, char in enumerate(reversed(digits)):
            number = int(char) * (2 if index % 2 else 1)
            total += number - 9 if number > 9 else number
        return total % 10 == 0

    def _masked(self, value: Any, is_text: bool = False) -> Any:
        if isinstance(value, dict):
            # Every string under a text key is text, a highlighted copy split by field included.
            return {key: self._masked(item, is_text or key in self.TEXT_KEYS) for key, item in value.items()}
        if isinstance(value, list):
            return [self._masked(item, is_text) for item in value]
        if is_text and isinstance(value, str) and value:
            return self.WITHHELD if self.mode == self.FULL else self.mask_text(value)
        return value


class Masking:
    """The three mask settings, applied to fetched records, the lookup commands and gibti-local-search."""

    def __init__(self, password_mask: PasswordMask, card_mask: CardDataMask, post_mask: PostTextMask | None = None) -> None:
        self.password_mask = password_mask
        self.card_mask = card_mask
        self.post_mask = post_mask or PostTextMask()

    def apply(self, collection_name: str, record: Any) -> Any:
        if collection_name == TICollections.COMPROMISED_BREACHEDDB and isinstance(record, dict):
            # The mask can drop the passwords, never the fact that the record carries a credential: it decides the severity
            # of the incident. A record with an empty passwords field can still hold one in its leak's columns (record_details).
            record["hasPassword"] = bool(
                texts(record.get("passwords")) or PasswordMask.credentials_in_details(collection_name, record)
            )
        # The post mask reads a card number whole before the password mask can cut it.
        record = self.post_mask.apply(collection_name, record)
        return self.card_mask.apply(collection_name, self.password_mask.apply(collection_name, record))


""" BUILDERS """


class IncidentBuilder:
    """The incident of a fetched record, with the record shaped for its incident fields as rawJSON."""

    SEVERITIES = {
        "green": IncidentSeverity.LOW,
        "orange": IncidentSeverity.MEDIUM,
        "red": IncidentSeverity.HIGH,
    }
    # GIB Severity in words, in place of Group-IB's color.
    SEVERITY_NAMES = {
        "green": "Low",
        "orange": "Medium",
        "red": "High",
    }
    DATE_FIELDS = frozenset(
        {
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
            "dateBegin",
            "dateLastSeen",
            "blocked",
            "detected",
            "dateFirstCompromised",
            "dateDetected",
            "datePublished",
            "dateReg",
            "date",
            "validThruDate",
            "postDate",
            "editDate",
            "deletedDate",
            "uploadTime",
        }
    )
    # The grid columns of type date (IncidentFields), as the grid rows name them: lowercase, no underscores.
    GRID_DATE_COLUMNS = frozenset(
        {
            "date",
            "datecreated",
            "datedetected",
            "datepublished",
            "datecompromised",
            "validthrudate",
            "compromisedat",
            "detectedat",
        }
    )
    # A bare calendar date inside a grid row ("2026-08-28"); date columns need a full timestamp.
    DATE_ONLY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
    # The collections whose records are posts or listings shaped by _shape_post.
    POST_COLLECTIONS = frozenset(
        {
            TICollections.COMPROMISED_ACCESS,
            TICollections.COMPROMISED_MESSENGER,
            TICollections.COMPROMISED_DISCORD,
            TICollections.DARKWEB_FORUMS,
            TICollections.HI_OPEN_THREATS,
        }
    )
    # How much of an untitled open-threat post's text names its incident.
    TITLE_LENGTH = 80
    # A figure holds portal image links. An element name is letters and digits with an optional prefix ("o:p"); "<!"
    # and "<?" open a comment, a doctype or a processing instruction.
    HTML_FIGURE_OPEN_RE = re.compile(r"<figure\b[^<>]*>", re.IGNORECASE)
    HTML_FIGURE_CLOSE_RE = re.compile(r"</figure\s*>", re.IGNORECASE)
    HTML_BLOCK_RE = re.compile(r"</(?:h[1-6]|p|li|div|blockquote|tr|td|th)\s*>|<br\s*/?>", re.IGNORECASE)
    HTML_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9]*(?::[A-Za-z][A-Za-z0-9]*)?(?:[\s/][^<>]*)?>|<[!?][^<>]*>")
    # What marks a text of html_when_marked_up as HTML: a block end, a line break or the end of a formatting element. A
    # script payload quoted in plain text holds none of them.
    HTML_MARKUP_RE = re.compile(rf"{HTML_BLOCK_RE.pattern}|</(?:b|i|u|em|strong|code|span|sub|sup)\s*>", re.IGNORECASE)

    def build(self, collection_name: str, record: dict, hunting_rules_applied: bool | None = None) -> dict:
        """The incident of ``record``, shaped in place; ``hunting_rules_applied`` fills GIB Fetched With Hunting Rules."""
        record = self.shape(collection_name, record)
        record = self.portal_link(collection_name, record)
        incident_name = self._name(collection_name, record)
        system_severity = self._severity(collection_name, record)
        record.update(
            {
                "name": incident_name,
                "gibType": collection_name,
                "systemSeverity": system_severity,
                # "GIB Source" maps from sourceType on the incident types whose mapper fills it: the record's own source type
                # where the mapping reads one (sourceType or source_type), else the collection name.
                "sourceType": self._source_type(collection_name, record),
                "huntingRulesApplied": hunting_rules_applied,
            }
        )
        if collection_name == TICollections.MALWARE_MALWARE:
            # GIB Threat Actor Name / ID of a malware profile, which names several actors.
            actors = record.get("taList") or {}
            record["threat_actor_name"] = actors.get("name")
            record["threat_actor_id"] = actors.get("id")
        if collection_name == TICollections.ATTACKS_PHISHING_GROUP:
            # GIB Country Name: the countries of the hosting IPs as one string; the table keeps one row per IP.
            hosting = record.get("phishing_ip")
            names = hosting.get("countryName") if isinstance(hosting, dict) else None
            record["countryName"] = self._joined(names if isinstance(names, list) else [names], unique=True)
        if collection_name == TICollections.COMPROMISED_MASKED_CARD:
            self.scalar_fields(record, ("track", "card_bin"))
        if collection_name == TICollections.APT_THREAT:
            # GIB Nation-State Cybercriminals Threat Countries is a short text field.
            self.scalar_fields(record, ("countries",))
        # GIB Related Indicators Data and GIB Related Emails: the fields the platform extracts the incident's indicators from.
        record["relatedIndicators"] = self._related_indicators(collection_name, record)
        record["relatedEmails"] = self._related_emails(collection_name, record)
        self._name_severity(record)
        self.blank_placeholder_dates(record)
        self._expand_bare_dates(record)
        self._fill_card_summary(collection_name, record)
        self._grid_tables(collection_name, record)
        record = self.plain_text(collection_name, record)
        self.scalar_fields(record, ("id", "threat_actor_name", "threat_actor_id"))
        data = {
            "name": record["name"],
            "occurred": self._occurred(collection_name, record),
            "rawJSON": json.dumps(record),
            "dbotMirrorId": record.get("id"),
        }
        if data["occurred"] is None:
            data.pop("occurred")
        return data

    @classmethod
    def shape(cls, collection_name: str, record: dict) -> dict:
        """The record as its incident, its lookup and the local search show it."""
        if collection_name in (TICollections.HI_THREAT_ACTOR, TICollections.APT_THREAT_ACTOR):
            record["reports"] = cls._report_columns(record.get("reports"))
        if collection_name == TICollections.SUSPICIOUS_IP_TOR_NODE:
            # GIB Tor Flags and GIB Tor Exit: the newest consensus state, before the states are dropped.
            record["torFlags"] = tor_flags(record) or None
            record["torExit"] = tor_exit(record)
        if collection_name.startswith("suspicious_ip/"):
            cls._fill_ip_geography(record)
        if collection_name in cls.POST_COLLECTIONS:
            cls._shape_post(collection_name, record)
        return record

    @classmethod
    def _shape_post(cls, collection_name: str, record: dict) -> None:
        """The name and scalar fields of a post or listing; an empty attachment or deletion date is dropped."""
        author = cls._block(record, "author")
        if collection_name == TICollections.COMPROMISED_ACCESS:
            host = record.get("name") or cls._block(record, "target").get("domain") or record.get("id")
            malware = first_value(record.get("malware_name"))
            record["name"] = f"{host} ({malware})" if malware else host
        elif collection_name == TICollections.COMPROMISED_MESSENGER:
            author["name"] = " ".join(texts([author.get("firstName"), author.get("lastName")])) or None
            record["name"] = record.get("name") or cls._block(record, "channel").get("name") or record.get("id")
        elif collection_name == TICollections.COMPROMISED_DISCORD:
            name, tag = author.get("name"), author.get("discriminator")
            author["handle"] = f"{name}#{tag}" if name and tag not in (None, "", "0") else name
            channel = cls._block(record, "channel")
            record["name"] = " / ".join(texts([channel.get("server"), channel.get("name")])) or record.get("id")
        elif collection_name == TICollections.DARKWEB_FORUMS:
            record["forumSection"] = " / ".join(texts(record.get("forumSection"))) or None
            record["languages"] = cls._joined(texts(record.get("languages")), unique=True) or None
            record["name"] = record.get("name") or record.get("forum") or record.get("id")
        elif collection_name == TICollections.HI_OPEN_THREATS:
            for key in ("malware_name", "countryName", "tags", "cveIds", "huntingRuleIds", "companyTags"):
                record[key] = cls._joined(texts(record.get(key)), unique=True) or None
            record["name"] = cls._open_threat_title(record, author)
        if CollectionSpec.of(collection_name).darkweb_post:
            if "deletedDate" in CollectionSpec.of(collection_name).mapping:
                record["deletedDate"] = record.get("deletedDate") or None
            attachment = record.get("attachment")
            if isinstance(attachment, dict) and not any(texts([attachment.get("name"), attachment.get("type")])):
                # A post without an attachment parses to a block with no name or type: Telegram sends an empty media
                # block, Discord no media.
                record["attachment"] = None

    @staticmethod
    def _block(record: dict, key: str) -> dict:
        """The nested object under ``key``, {} when the record has none."""
        value = record.get(key)
        return value if isinstance(value, dict) else {}

    @classmethod
    def _open_threat_title(cls, record: dict, author: dict) -> str:
        """The author's handle and the post's title, else the start of its text: a title of digits is a social post's id."""
        title = str(record.get("title") or "").strip()
        if not title or title.isdigit():
            text = " ".join(cls._html_text(str(record.get("text") or "")).split())
            title = (text[: cls.TITLE_LENGTH].rstrip() + "..." if len(text) > cls.TITLE_LENGTH else text) or title
        title = title or str(record.get("id") or "")
        handle = author.get("handle") or record.get("sourceName")
        return f"{handle}: {title}" if handle else title

    @staticmethod
    def portal_link(collection_name: str, record: dict) -> dict:
        """The portal link the ciaops template cannot build: a breached record's first id, a defacement's, a vulnerability's."""
        template = TICollections.PORTAL_LINKS.get(collection_name, "")
        if collection_name == TICollections.ATTACKS_DEFACE:
            if not record.get("portalLink") and record.get("id"):
                record["portalLink"] = f"{template}{urllib.parse.quote(str(record['id']), safe='')}"
            return record
        if collection_name == TICollections.OSI_VULNERABILITY:
            id_ = str(record.get("id") or "")
            if id_:
                query = f'id:"{id_}"' if ":" in id_ else id_
                record["portalLink"] = f"{template}{urllib.parse.quote(query, safe='')}"
            return record
        if collection_name != TICollections.COMPROMISED_BREACHEDDB:
            return record
        ids = record.get("id")
        candidates = ids if isinstance(ids, list) else str(ids or "").split(",")
        first = next((str(value).strip() for value in candidates if str(value).strip()), "")
        if first:
            record["portalLink"] = f"{template}{urllib.parse.quote(first, safe='')}"
        return record

    @classmethod
    def plain_text(cls, collection_name: str, record: dict) -> dict:
        """The record with the narratives Group-IB writes in HTML as plain text."""
        spec = CollectionSpec.of(collection_name)
        for name in spec.html_fields:
            if isinstance(record.get(name), str):
                record[name] = cls._html_text(record[name])
        for name in spec.html_when_marked_up:
            if isinstance(record.get(name), str) and cls.HTML_MARKUP_RE.search(record[name]):
                record[name] = cls._html_text(record[name])
        return record

    @classmethod
    def scalar_fields(cls, record: dict, keys: Iterable[str]) -> dict:
        """The record with each of ``keys`` that holds a list joined into one text, for the fields that take one string."""
        for key in keys:
            if isinstance(record.get(key), list):
                record[key] = cls._joined(record[key])
        return record

    @staticmethod
    def rows(columns: dict[str, Any]) -> list[dict[str, Any]]:
        """Columns (one list per field) as one row per element of the longest; a shorter column repeats its first value."""
        if not columns:
            return [{}]
        normalized = {key: value if isinstance(value, list) else [value] for key, value in columns.items()}
        length = max((len(value) for value in normalized.values()), default=1)
        return [
            {key: (value[index] if index < len(value) else (value[0] if value else None)) for key, value in normalized.items()}
            for index in range(length)
        ]

    @classmethod
    def _name(cls, collection_name: str, record: dict) -> str:
        prefix = CollectionSpec.of(collection_name).incident_prefix
        if collection_name == TICollections.COMPROMISED_BREACHEDDB:
            names = record["name"]
            if not isinstance(names, list):
                names = [names]
            name = f"{prefix}: " + ", ".join(names)
        elif collection_name == TICollections.COMPROMISED_SPD:
            ptype = record.get("type") or "Payment data"
            name = f"{prefix}: {ptype} {record.get('value')}"
        elif collection_name == TICollections.SUSPICIOUS_IP_OPEN_PROXY and record.get("port") is not None:
            # Each port of an open proxy is an incident of its own.
            name = f"{prefix}: {record['name']}:{record['port']}"
        else:
            raw_name = record["name"]
            if isinstance(raw_name, list):
                raw_name = cls._joined(raw_name)
            if raw_name in (None, "") and collection_name == TICollections.SUSPICIOUS_IP_SCANNER:
                # ipv4 is null on the IPv6 scanners, whose record id is their address.
                raw_name = record.get("id")
            if raw_name in (None, "") and collection_name == TICollections.ATTACKS_DDOS:
                target = record.get("target") or {}
                raw_name = target.get("domain") or target.get("url") or record.get("id")
            if collection_name == TICollections.ATTACKS_PHISHING_GROUP:
                raw_name = cls._phishing_group_title(collection_name, record, raw_name)
            name = f"{prefix}: {raw_name}"
        return name.strip()

    @classmethod
    def _phishing_group_title(cls, collection_name: str, record: dict, domain: Any) -> Any:
        """The domain of a phishing group, followed by the brand it impersonates unless the brand is the domain."""
        domain = domain or (record.get("domainInfo") or {}).get("domain")
        brand = record.get("brand")
        brand = cls._joined(brand) if isinstance(brand, list) else brand
        brand = str(brand or "").strip()
        markers = CollectionSpec.of(collection_name).brand_markers
        if not brand or brand.lower() in markers or brand.lower() == str(domain or "").lower():
            return domain
        return f"{domain} ({brand})"

    @classmethod
    def _severity(cls, collection_name: str, record: dict) -> int:
        """High for a breached credential; else the evaluation raised by the worst file, the threat level, or the default."""
        spec = CollectionSpec.of(collection_name)
        if collection_name == TICollections.COMPROMISED_BREACHEDDB and record.get("hasPassword"):
            return IncidentSeverity.HIGH
        severity = str((record.get("evaluation") or {}).get("severity") or "")
        if spec.file_severities:
            files = record.get("files")
            file_severities = texts(files.get("severity") if isinstance(files, dict) else None)
            return max(
                [cls.SEVERITIES.get(severity, IncidentSeverity.UNKNOWN)]
                + [spec.file_severities[value] for value in file_severities if value in spec.file_severities]
            )
        if severity in cls.SEVERITIES:
            return cls.SEVERITIES[severity]
        threat_level = str(record.get("threatLevel") or "").lower()
        if threat_level in spec.threat_level_severities:
            return spec.threat_level_severities[threat_level]
        return spec.default_severity

    @classmethod
    def _name_severity(cls, record: dict) -> None:
        """GIB Severity in words."""
        severity = record.get("evaluation", {}).get("severity")
        if severity:
            record["evaluation"]["severity"] = cls.SEVERITY_NAMES.get(severity, "Unknown")

    @staticmethod
    def _occurred(collection_name: str, record: dict) -> str | None:
        """The first date of the collection's occurred_fields in UTC; None lets Cortex XSOAR date the incident by its creation."""
        last_exception = None
        occurred_fields = list(CollectionSpec.of(collection_name).occurred_fields)
        for variant in occurred_fields:
            try:
                date_value = record.get(variant, "")
                if date_value is None:
                    continue
                if not isinstance(date_value, str):
                    date_value = str(date_value)
                if not date_value.strip():
                    continue
                occurred = dateparser_parse(date_string=date_value)
                if occurred is None:
                    raise DemistoException(f"{variant} is not a date: {date_value!r}")
                if occurred.year < FIRST_RECORD_YEAR:
                    raise DemistoException(f"{variant} holds the placeholder {date_value!r}")
                if occurred.tzinfo is not None:
                    # dateparser keeps the offset of the string; DATE_FORMAT writes UTC.
                    occurred = occurred.astimezone(UTC)
                return occurred.strftime(DATE_FORMAT)
            except DemistoException as e:
                last_exception = e
        demisto.debug(
            f"None of the date fields {occurred_fields} of {collection_name} record {record.get('id', None)!r} holds a "
            f"valid date (last error: {last_exception}); the incident takes its creation time."
        )
        return None

    @staticmethod
    def _related_observables(collection_name: str, record: dict) -> list[tuple[str, str]]:
        """The record's observables as (type, value), none for a flagged record; of the wallets, Bitcoin ones only."""
        # Extraction finds base58check Bitcoin wallets only; GIBTIEnrichIncidentIndicators creates bc1 wallets and those of
        # other chains.
        block = record.get("indicators")
        if not isinstance(block, dict) or CollectionSpec.of(collection_name).withdrawal_flags(record):
            return []
        return [
            (kind, str(value))
            for kind, value, _ in IndicatorBuilder.observables(collection_name, block)
            if kind != CRYPTOCURRENCY_TYPE or str(value).startswith(IndicatorBuilder.BITCOIN_PREFIX)
        ]

    @classmethod
    def _related_indicators(cls, collection_name: str, record: dict) -> str | None:
        """The record's observables other than e-mail addresses, one per line, for GIB Related Indicators Data."""
        values = dict.fromkeys(value for kind, value in cls._related_observables(collection_name, record) if kind != "Email")
        return "\n".join(values) or None

    @classmethod
    def _related_emails(cls, collection_name: str, record: dict) -> str | None:
        """The record's e-mail addresses, one per line, for GIB Related Emails: extracted as Email only, without their domains."""
        values = dict.fromkeys(value for kind, value in cls._related_observables(collection_name, record) if kind == "Email")
        return "\n".join(values) or None

    @classmethod
    def _source_type(cls, collection_name: str, record: dict) -> str:
        """The record's source type, its distinct values joined, else the collection name."""
        raw = record.get("sourceType") or record.get("source_type") or collection_name
        return cls._joined(raw if isinstance(raw, list) else [raw], unique=True) or collection_name

    @staticmethod
    def _date_conversion(date: Any) -> str | None:
        """A bare calendar date as an ISO timestamp; any other value gives None."""
        if not isinstance(date, str) or not date.strip():
            return None
        try:
            return datetime.strptime(date, "%Y-%m-%d").isoformat()
        except ValueError:
            return None

    @classmethod
    def blank_placeholder_dates(cls, record: dict) -> dict:
        """The record with its placeholder dates and those of its indicators block read as no date."""
        for block in (record, record.get("indicators")):
            if isinstance(block, dict):
                for key in cls.DATE_FIELDS & block.keys():
                    if known_date(block[key]) is None:
                        block[key] = None
        return record

    @classmethod
    def _expand_bare_dates(cls, record: dict) -> None:
        for key, value in record.items():
            if key in cls.DATE_FIELDS and value is not None:
                if known_date(value) is None:
                    record[key] = None
                    continue
                new_value = cls._date_conversion(value)
                if new_value:
                    record[key] = new_value

    @staticmethod
    def _fill_card_summary(collection_name: str, record: dict) -> None:
        """The first known CVV and expiry of a card group's events at record level, where the group keeps them per event."""
        if collection_name != TICollections.COMPROMISED_BANK_CARD_GROUP:
            return
        events = record.get("compromised_events")
        if not isinstance(events, dict):
            return
        for key, event_key in (("cvv", "cvv"), ("validThru", "valid_thru")):
            if record.get(key):
                continue
            first = first_value(events.get(event_key))
            if first is not None:
                record[key] = first

    @classmethod
    def _grid_tables(cls, collection_name: str, record: dict) -> None:
        """Every grid table of the collection the record carries as rows, None for a table without a row."""
        for name in CollectionSpec.of(collection_name).grid_tables:
            if collection_name == TICollections.OSI_PUBLIC_LEAK and name == "matches":
                record[name] = cls._matches_rows(record.get(name, {}))
            elif collection_name == TICollections.COMPROMISED_BREACHEDDB and name == "record_details":
                record[name] = cls._detail_rows(record.get(name))
            else:
                record[name] = cls._table_rows(collection_name, name, record.get(name, {}))

    @classmethod
    def _table_rows(cls, collection_name: str, name: str, columns: Any) -> list[dict] | None:
        if not columns or cls._all_lists_empty(columns):
            return None
        rows = cls.rows(columns)
        if collection_name == TICollections.OSI_GIT_REPOSITORY and name == "files":
            rows = cls._join_cells(rows)
        rows = cls._full_dates(cls._lowercase_keys(cls._blank_to_none(rows)))
        if collection_name == TICollections.COMPROMISED_SPD and name == "events":
            # The malware and actor ids and names of an event as one text each.
            rows = cls._join_cells(rows)
        # A block the API sends as nulls or empty lists (a phishing group without a kit) is no table: a row of them would
        # show as empty or "null" cells.
        rows = [row for row in rows if not all(cls._is_blank(value) for value in row.values())]
        return rows or None

    @staticmethod
    def _lowercase_keys(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The keys as the grid columns name them: lowercase, no underscores."""
        return [{key.replace("_", "").lower(): value for key, value in row.items()} for row in rows]

    @classmethod
    def _full_dates(cls, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Date-only values of the grid date columns as timestamps, which ``setIncident`` requires."""
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key, value in row.items():
                if key in cls.GRID_DATE_COLUMNS and isinstance(value, str) and cls.DATE_ONLY_RE.fullmatch(value.strip()):
                    row[key] = f"{value.strip()}T00:00:00Z"
        return rows

    @classmethod
    def _blank_to_none(cls, data: Any) -> Any:
        """Empty strings, empty lists and lists of empty lists as None, all the way down."""
        if isinstance(data, dict):
            return {key: cls._blank_to_none(value) for key, value in data.items()}
        if isinstance(data, list):
            if not data or all(isinstance(item, list) and not item for item in data):
                return None
            return [cls._blank_to_none(item) for item in data]
        return None if data == "" else data

    @classmethod
    def _all_lists_empty(cls, data: dict[str, Any] | list[Any]) -> bool:
        """Whether every list of the object, its nested objects included, is empty."""
        if isinstance(data, dict):
            values = list(data.values())
            return all(not value for value in values if isinstance(value, list)) and all(
                cls._all_lists_empty(value) for value in values if isinstance(value, dict)
            )
        if isinstance(data, list):
            return all(cls._all_lists_empty(item) for item in data if isinstance(item, dict))
        return True

    @staticmethod
    def _join_cells(rows: list[dict]) -> list[dict]:
        """Each list cell as one text, empty values keeping their place; a cell of empty values only is None."""
        for row in rows:
            if isinstance(row, dict):
                for key, value in row.items():
                    if isinstance(value, list):
                        texts = ["" if item in (None, "") else str(item) for item in value]
                        row[key] = ", ".join(texts) if any(texts) else None
        return rows

    @classmethod
    def _matches_rows(cls, matches: Any) -> list[dict] | None:
        """A public leak's matches ({type: {sub type: [values]}}) as rows; a leak can match no detector at all."""
        if not matches:
            return None
        rows = [
            {"type": type_, "sub_type": sub_type, "value": value}
            for type_, sub_dict in (matches.items() if isinstance(matches, dict) else ())
            if isinstance(sub_dict, dict)
            for sub_type, sub_list in sub_dict.items()
            for value in (sub_list if isinstance(sub_list, list) else [sub_list])
            if value is not None
        ]
        return cls._lowercase_keys(cls._blank_to_none(rows) or []) or None

    @classmethod
    def _detail_rows(cls, details: Any) -> list[dict] | None:
        """A flat attribute block (a breached record's ``addInfo``) as key/value rows; an attribute without a value has no row."""
        if not isinstance(details, dict):
            return None
        rows = []
        for key, value in details.items():
            joined = cls._joined(value if isinstance(value, list) else [value])
            if joined:
                rows.append({"key": key, "value": joined})
        return rows or None

    @staticmethod
    def _report_columns(reports: Any) -> Any:
        """An actor profile's ``stat.reports`` as table columns; the API lists a report as an object or as its bare id."""
        if not isinstance(reports, list):
            return reports
        columns: dict[str, list] = {"id": [], "name": [], "datePublished": []}
        for report in reports:
            if report in (None, ""):
                continue
            report = report if isinstance(report, dict) else {"id": str(report)}
            name = report.get("name")
            columns["id"].append(report.get("id"))
            columns["name"].append(name.get("en") if isinstance(name, dict) else name)
            columns["datePublished"].append(report.get("datePublished"))
        return columns

    @classmethod
    def _fill_ip_geography(cls, record: dict) -> None:
        """A suspicious_ip/* entry's missing AS and country, from the relay's newest state or the scanner's IPv6 block."""
        state = cls._newest_tor_state(record.pop("nodes", None))
        if not state.get("countryCode") and state.get("country"):
            state["countryCode"] = str(state["country"]).upper()
        observables = record.get("indicators")
        if not isinstance(observables, dict):
            observables = {}
        ipv6 = {"countryCode": observables.get("ipv6_country_code"), "countryName": observables.get("ipv6_country_name")}
        # The AS number goes with its name and the country code with its name, both from one source.
        for source, pair in (
            (state, (("asn", "as"), ("provider", "asName"))),
            (state, (("countryCode", "countryCode"), ("countryName", "countryName"))),
            (ipv6, (("countryCode", "countryCode"), ("countryName", "countryName"))),
        ):
            if all(record.get(key) in (None, "") for key, _ in pair):
                record.update({key: source[source_key] for key, source_key in pair if source.get(source_key) not in (None, "")})
        if record.get("countryName") in (None, "") and record.get("countryCode") not in (None, ""):
            record["countryName"] = record["countryCode"]
        # A relay's IP indicator reads the address block too, and takes a group from the same consensus state where the
        # block holds none of it; the region goes with the country.
        for pair in (
            (("ipv4_asn", "as"), ("ipv4_provider", "asName")),
            (("ipv4_country_code", "countryCode"), ("ipv4_country_name", "countryName"), ("ipv4_region", "region")),
        ):
            if all(observables.get(key) in (None, "") for key, _ in pair):
                observables.update({key: state[state_key] for key, state_key in pair if state.get(state_key) not in (None, "")})

    @staticmethod
    def _newest_tor_state(nodes: Any) -> dict:
        """The data of the most recently seen state of a relay's consensus snapshots, {} without one."""
        states: list[dict] = [
            state["data"]
            for node in (nodes if isinstance(nodes, list) else [])
            if isinstance(node, dict)
            for state in node.get("states") or []
            if isinstance(state, dict) and isinstance(state.get("data"), dict)
        ]
        newest = max(states, key=lambda data: str(data.get("dateLastSeen") or data.get("lastSeen") or ""), default={})
        return dict(newest)

    @classmethod
    def _html_text(cls, text: str) -> str:
        """An HTML narrative as text, in linear time; "<stdio.h>" is no tag."""
        # No pattern reaches past the next "<", which keeps the strip linear.
        if not text:
            return text
        parts, position = [], 0
        while (opening := cls.HTML_FIGURE_OPEN_RE.search(text, position)) and (
            closing := cls.HTML_FIGURE_CLOSE_RE.search(text, opening.end())
        ):
            parts.append(text[position : opening.start()])
            position = closing.end()
        parts.append(text[position:])
        text = cls.HTML_BLOCK_RE.sub("\n", "".join(parts))
        text = html.unescape(cls.HTML_TAG_RE.sub("", text))
        text = re.sub(r"[^\S\n]+", " ", text)
        return re.sub(r" ?\n\s*", "\n", text).strip()

    @staticmethod
    def _joined(values: Iterable[Any], unique: bool = False) -> str:
        """The non-empty values joined with ", "; ``unique`` keeps the first of equal texts."""
        texts = [str(value) for value in values if value not in (None, "")]
        return ", ".join(dict.fromkeys(texts) if unique else texts)

    @classmethod
    def _is_blank(cls, value: Any) -> bool:
        """True for None, an empty string, an empty list or dict, and a list or dict made of those only."""
        if value in (None, "", [], {}):
            return True
        if isinstance(value, (list, tuple)):
            return all(cls._is_blank(item) for item in value)
        if isinstance(value, dict):
            return all(cls._is_blank(item) for item in value.values())
        return False


class IndicatorBuilder:
    """The Common.* indicators of the observables a record names, with their DBotScore, tags, TLP and relationships."""

    @dataclass(frozen=True)
    class Item:
        """One indicator of a record: its observed type, its War Room row, the Common.* object and its relationships."""

        observable_type: str
        row: dict[str, Any]
        indicator: Any
        relationships: list[EntityRelationship]

    # Bad from a Group-IB score of 80: "confirmed malicious" on the risk score scale, applied to the illegal score too.
    MALICIOUS_SCORE = 80
    TLP_ORDER = {"WHITE": 0, "GREEN": 1, "AMBER": 2, "RED": 3}
    # TLP 2.0 names outside the four colors: CLEAR is stored as WHITE, AMBER+STRICT as AMBER (the nearest of the four).
    TLP_ALIASES = {"CLEAR": "WHITE", "AMBER+STRICT": "AMBER"}
    # Attributes that describe the whole record: not split one per observable when their list length happens to match
    # the number of observables, unless the collection's per_element_fields names them.
    RECORD_LEVEL_FIELDS = frozenset({"malware_family", "threat_actor_names", "brand", "category", "trafficlightprotocol"})
    # The observable types whose defanged notation (hxxps://host[.]tld) is restored: it never matches traffic.
    REFANGED_TYPES = frozenset({FeedIndicatorType.URL, FeedIndicatorType.Domain, FeedIndicatorType.IP, FeedIndicatorType.Email})
    DEFANGED_PARTS = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://"), ("[@]", "@"))
    # The indicator types a placeholder can stand in for. A payment string is no network value and routinely
    # holds blanks: a PIX, VietQR or UPI payee name.
    TEMPLATE_CHECKED_TYPES = frozenset(
        {FeedIndicatorType.URL, FeedIndicatorType.Domain, FeedIndicatorType.IP, FeedIndicatorType.IPv6, FeedIndicatorType.Email}
    )
    # osi/vulnerability also carries Nessus, Red Hat, Microsoft, Oracle and WordPress advisories under their own ids,
    # which are not CVE indicators.
    CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
    # A dotted-quad IPv4 address, each octet 0-255; no port.
    IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    # A hash is hex digits; get_hash_type tells its kind by length.
    HEX_RE = re.compile(r"[0-9a-fA-F]+")
    BITCOIN_PREFIX = "bitcoin:"
    BASE58_DIGITS = "".join(c for c in string.digits + string.ascii_uppercase + string.ascii_lowercase if c not in "0OIl")
    BECH32_BITCOIN_RE = re.compile(r"bc1[ac-hj-np-z02-9]{11,71}", re.IGNORECASE)
    # Cryptocurrency address types Cortex XSOAR knows, by the SPD serviceType.
    CRYPTO_ADDRESS_TYPES = {
        "BTCLike": "bitcoin",
        "ETHLike": "ethereum",
        "XMRLike": "monero",
        "SOLLike": "solana",
        "TRXLike": "tron",
    }
    # Long texts stay out of the War Room rows: the entries are auto-extracted, and a CVE description or software table
    # would seed the War Room with the URLs it mentions.
    READABLE_SKIPPED_FIELDS = frozenset({"description", "gibsoftwaremixed"})

    def __init__(self, reliability: str | None = None, create_relationships: bool = False) -> None:
        self.reliability = reliability
        self.create_relationships = create_relationships

    def items(self, record: str | dict[Any, Any], collection_name: str) -> list[Item]:
        """The indicators of one record, one per observable, with the War Room row of each."""
        if not isinstance(record, dict) or record.get("indicators") is None:
            return []
        severity = record.get("evaluation", {}).get("severity") or record["indicators"].get("severity")
        record_tlp = record.get("evaluation", {}).get("tlp")
        # A copy: the record itself goes to the context, and the severity is an attribute of the entries only.
        block: dict = {**record["indicators"], "severity": severity}
        items = []
        for observable_type, value, fields in self.observables(collection_name, block):
            if record_tlp and not fields.get("trafficlightprotocol"):
                fields["trafficlightprotocol"] = record_tlp
            output = self._indicator(value, observable_type, fields, collection_name)
            if not output:
                continue
            relationships = self.relationships(
                value,
                observable_type,
                texts(fields.get("malware_family")),
                texts(fields.get("threat_actor_names")),
            )
            row = {
                "value": value,
                "severity": severity,
                **{k: v for k, v in fields.items() if k not in self.READABLE_SKIPPED_FIELDS},
            }
            items.append(self.Item(observable_type, row, output, relationships))
        return items

    def results(self, record: str | dict[Any, Any], collection_name: str) -> list[CommandResults]:
        """The War Room entries of a record's indicators, one per type; a defacement's are not auto-extracted."""
        groups: dict[str, list[IndicatorBuilder.Item]] = {}
        for item in self.items(record, collection_name):
            groups.setdefault(item.observable_type, []).append(item)
        results = []
        for observable_type, items in groups.items():
            rows = [item.row for item in items]
            headers = list(dict.fromkeys(key for row in rows for key in row))
            relationships = [relationship for item in items for relationship in item.relationships]
            # One entry carries the context of every indicator of the type: CommandResults.indicator takes a single
            # indicator.
            context: dict[str, list] = {}
            for item in items:
                for key, value in item.indicator.to_context().items():
                    context.setdefault(key, []).append(value)
            results.append(
                CommandResults(
                    readable_output=tableToMarkdown(f"{observable_type} indicators", rows, headers=headers, removeNull=True),
                    outputs=context,
                    relationships=relationships or None,
                    ignore_auto_extract=CollectionSpec.of(collection_name).victim_site,
                )
            )
        return results

    def relationships(
        self, value: str, indicator_type: str, malware_names: list[str], actor_names: list[str]
    ) -> list[EntityRelationship]:
        """The observable as indicator-of its Malware and related-to its Threat Actors, when "Create relationships" is on."""
        if not self.create_relationships:
            return []
        relationships: list[EntityRelationship] = []
        for name in malware_names:
            relationships.append(
                EntityRelationship(
                    name=EntityRelationship.Relationships.INDICATOR_OF,
                    reverse_name=EntityRelationship.Relationships.INDICATED_BY,
                    entity_a=value,
                    entity_a_type=indicator_type,
                    entity_b=name,
                    entity_b_type=ThreatIntel.ObjectsNames.MALWARE,
                )
            )
        for name in actor_names:
            relationships.append(
                EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    reverse_name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=value,
                    entity_a_type=indicator_type,
                    entity_b=name,
                    entity_b_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                )
            )
        return relationships

    @classmethod
    def observables(cls, collection_name: str, block: dict) -> Iterator[tuple[str, Any, dict]]:
        """(type, value, attributes) of each observable of an ``indicators`` block, per the collection's indicator_types."""
        spec: dict = CollectionSpec.of(collection_name).indicator_types
        add_fields_types: dict = spec.get("add_fields_types", {})
        value_fallbacks: dict = spec.get("value_fallbacks", {})
        element_kinds: dict = spec.get("element_kinds", {})
        per_element_fields: tuple = spec.get("per_element_fields", ())
        for indicator_type_name, type_spec in spec.get("types", {}).items():
            indicator_type = cls._resolve_type(type_spec, block)
            if not indicator_type:
                continue
            add_fields = {
                field_type: block[field_name]
                for field_name, field_type in add_fields_types.get(indicator_type_name, {}).items()
                if block.get(field_name) is not None
            }
            keys = [indicator_type_name, *value_fallbacks.get(indicator_type_name, [])]
            raw_value = cls._first_present_per_element([block.get(key) for key in keys])
            if indicator_type_name in element_kinds:
                raw_value = cls._of_element_kind(raw_value, block.get("element_type"), element_kinds[indicator_type_name])
            for value, fields in cls._expand(raw_value, add_fields, per_element_fields):
                if indicator_type in cls.REFANGED_TYPES:
                    value = cls.refang(value)
                if (
                    (indicator_type in cls.TEMPLATE_CHECKED_TYPES and cls._is_template(value))
                    or (indicator_type == FeedIndicatorType.CVE and not cls.CVE_ID_RE.match(str(value)))
                    or (indicator_type == FeedIndicatorType.Email and ASSET_ADDRESS_RE.search(str(value)))
                ):
                    continue
                if indicator_type == CRYPTOCURRENCY_TYPE:
                    value = cls._wallet(value)
                yield cls._observable_type(indicator_type, value), value, fields

    @classmethod
    def cvss(cls, merged: Any, merged_vector: Any, legacy: Any, legacy_vector: Any) -> tuple[float | None, Any]:
        """A vulnerability's CVSS score and vector: mergedCvss, else the legacy cvss.score; 0 without a vector is unknown."""
        for score, vector in ((merged, merged_vector), (legacy, legacy_vector)):
            number = as_number(score)
            vector = first_value(vector) or None
            if number is None or (number == 0 and str(vector or "NONE").upper() == "NONE"):
                continue
            return number, vector
        return None, None

    @classmethod
    def tlp(cls, value: Any) -> str | None:
        """A TLP as Cortex XSOAR names it, read from ``amber``, ``TLP:AMBER`` or TLP 2.0 ``CLEAR``; an unknown marking is RED."""
        values = texts(value)
        if not values:
            return None
        text = values[0].upper()
        if text.startswith("TLP:"):
            text = text[4:].strip()
        text = cls.TLP_ALIASES.get(text, text)
        if text not in cls.TLP_ORDER:
            demisto.info(f"[IndicatorBuilder] unknown TLP {values[0]!r}: the indicator gets RED")
            return "RED"
        return text

    @classmethod
    def most_restrictive_tlp(cls, current: str | None, candidate: Any) -> str | None:
        normalized = cls.tlp(candidate)
        if normalized is None:
            return current
        if current is None or cls.TLP_ORDER[normalized] > cls.TLP_ORDER[current]:
            return normalized
        return current

    @classmethod
    def file_hashes(cls, values: Any) -> dict[str, str]:
        """The first hash of each kind (md5, sha1, sha256, sha512) among ``values``, told apart by their length."""
        hashes: dict[str, str] = {}
        for value in texts(values):
            kind = get_hash_type(value)
            if kind != "Unknown" and kind not in hashes and cls.HEX_RE.fullmatch(value):
                hashes[kind] = value
        return hashes

    @classmethod
    def refang(cls, value: Any) -> Any:
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
    def is_ipv6(value: Any) -> bool:
        """An IPv6 address, surrounding blanks and a zone index (``fe80::1%eth0``) included."""
        try:
            return isinstance(value, str) and isinstance(ipaddress.ip_address(value.strip()), ipaddress.IPv6Address)
        except ValueError:
            return False

    @classmethod
    def risk_score_verdict(cls, score: Any) -> int:
        """Group-IB's risk score as a DBotScore: 0-39 Good, 40-79 Suspicious, 80-100 Bad; Unknown without a score in 0-100."""
        number = as_number(score)
        if number is None or number < 0 or number > 100:
            return Common.DBotScore.NONE
        if number < 40:
            return Common.DBotScore.GOOD
        if number < cls.MALICIOUS_SCORE:
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.BAD

    def _indicator(self, value: Any, indicator_type: str, fields: dict, collection_name: str) -> Any:
        """The Common.* object of one observable, None without a value or usable data."""
        if value in (None, "") or isinstance(value, list) or self._carries_no_data(fields):
            return None

        def dbot_score(type_: str) -> Common.DBotScore:
            # A vulnerability Group-IB tracks is Bad, the verdict of osi/vulnerability; the graded CVE rules (exploit evidence,
            # EPSS, CVSS, Group-IB's severity) belong to gibti-cve-scoring.
            return Common.DBotScore(
                indicator=value,
                indicator_type=type_,
                integration_name=DBOT_VENDOR_NAME,
                score=self._verdict(collection_name, fields.get("illegal_score")),
                reliability=self.reliability,
            )

        tags = self._tags(collection_name, fields) or None
        malware_family = texts(fields.get("malware_family")) or None
        tlp = self.tlp(fields.get("trafficlightprotocol"))
        common_kwargs = assign_params(tags=tags, malware_family=malware_family, traffic_light_protocol=tlp)

        def scalar(key: str) -> str | None:
            # One string for a Common.* attribute: lists (one entry per event) are joined, empty values dropped.
            return ", ".join(texts(fields.get(key))) or None

        if indicator_type in (FeedIndicatorType.IP, FeedIndicatorType.IPv6):
            return Common.IP(
                ip=value,
                ip_type=indicator_type,
                asn=scalar("asn"),
                # Without a country name, the ISO country code stands in.
                geo_country=scalar("geocountry") or scalar("geocountrycode"),
                geo_description=scalar("geolocation"),
                organization_name=scalar("organization"),
                dbot_score=dbot_score(DBotScoreType.IP),
                **common_kwargs,
            )
        if indicator_type == FeedIndicatorType.Domain:
            return Common.Domain(domain=value, dbot_score=dbot_score(DBotScoreType.DOMAIN), **common_kwargs)
        if indicator_type == FeedIndicatorType.File:
            # The observable is the file's SHA-256, else its SHA-1, MD5 or SHA-512; each hash goes to the attribute of its
            # kind.
            hashes = self.file_hashes([value, fields.get("sha256"), fields.get("sha1"), fields.get("md5"), fields.get("sha512")])
            return Common.File(
                md5=hashes.get("md5"),
                sha1=hashes.get("sha1"),
                sha256=hashes.get("sha256"),
                sha512=hashes.get("sha512"),
                name=scalar("gibfilename"),
                size=first_value(fields.get("size")),
                dbot_score=dbot_score(DBotScoreType.FILE),
                **common_kwargs,
            )
        if indicator_type == FeedIndicatorType.URL:
            return Common.URL(url=value, dbot_score=dbot_score(DBotScoreType.URL), **common_kwargs)
        if indicator_type == FeedIndicatorType.CVE:
            cvss_score, cvss_vector = self.cvss(
                fields.get("merged_cvss"), fields.get("merged_cvss_vector"), fields.get("cvss"), fields.get("cvss_vector")
            )
            return Common.CVE(
                id=value,
                cvss=cvss_score,
                published=known_date(fields.get("published")),
                modified=known_date(fields.get("cvemodified")),
                description=fields.get("description"),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                tags=tags,
                traffic_light_protocol=tlp,
                dbot_score=dbot_score(DBotScoreType.CVE),
            )
        if indicator_type == FeedIndicatorType.Email:
            return Common.EMAIL(address=value, dbot_score=dbot_score(DBotScoreType.EMAIL), tags=tags, traffic_light_protocol=tlp)
        if indicator_type == CRYPTOCURRENCY_TYPE:
            service_type = texts(fields.get("service_type"))
            address_type = self.CRYPTO_ADDRESS_TYPES.get(service_type[0], service_type[0].lower()) if service_type else "unknown"
            if str(value).startswith(self.BITCOIN_PREFIX):
                address_type = "bitcoin"
            return Common.Cryptocurrency(
                address=value, address_type=address_type, dbot_score=dbot_score(DBotScoreType.CRYPTOCURRENCY)
            )
        return None

    @classmethod
    def _verdict(cls, collection_name: str, group_ib_score: Any) -> int:
        """The collection's verdict, or Bad from an illegal score of 80 and Suspicious below."""
        number = as_number(group_ib_score)
        if number is not None and 0 <= number <= 100:
            return Common.DBotScore.BAD if number >= cls.MALICIOUS_SCORE else Common.DBotScore.SUSPICIOUS
        return CollectionSpec.of(collection_name).verdict

    @classmethod
    def _tags(cls, collection_name: str, fields: dict) -> list[str]:
        """The collection name and the malware families, threat actors and targeted brand the record names."""
        tags: list[str] = [collection_name] if collection_name else []
        markers = CollectionSpec.of(collection_name).brand_markers
        for key in ("malware_family", "threat_actor_names", "brand"):
            for name in texts(fields.get(key)):
                if key == "brand" and name.casefold() in markers:
                    continue
                if name not in tags:
                    tags.append(name)
        return tags

    @classmethod
    def _carries_no_data(cls, fields: dict) -> bool:
        """True when every attribute but the record-level ones is an empty list; an observable with no such attribute is kept."""
        attributes = {key: value for key, value in fields.items() if key not in cls.RECORD_LEVEL_FIELDS}
        if not attributes:
            return False
        return all(isinstance(value, list) and len(value) < 1 for value in attributes.values())

    @classmethod
    def _resolve_type(cls, type_spec: Any, block: dict) -> str | None:
        """A ``types`` entry's type: a plain type, or one chosen by a record field through ``{"field", "map", "default"}``."""
        if isinstance(type_spec, str):
            return type_spec
        if not isinstance(type_spec, dict):
            return None
        raw = first_value(block.get(type_spec.get("field", "")))
        return type_spec.get("map", {}).get(raw, type_spec.get("default"))

    @classmethod
    def _expand(cls, raw_value: Any, add_fields: dict, per_element_fields: Iterable[str] = ()) -> list[tuple[Any, dict]]:
        """One (value, attributes) pair per observable; an aligned list attribute is the element's own unless record-level."""
        if not isinstance(raw_value, list):
            return [(raw_value, dict(add_fields))] if raw_value not in (None, "") else []
        positioned: list[tuple[str, int]] = []
        seen: set[str] = set()
        for position, element in enumerate(raw_value):
            for value in texts(element):
                if value not in seen:
                    seen.add(value)
                    positioned.append((value, position))
        if len(positioned) == 1 and len(raw_value) == 1:
            return [(positioned[0][0], dict(add_fields))]
        expanded = []
        for value, position in positioned:
            per_value = {}
            for key, field_value in add_fields.items():
                aligned = (
                    isinstance(field_value, list)
                    and len(field_value) == len(raw_value)
                    and (key not in cls.RECORD_LEVEL_FIELDS or key in per_element_fields)
                )
                per_value[key] = field_value[position] if aligned else field_value
            expanded.append((value, per_value))
        return expanded

    @classmethod
    def _first_present_per_element(cls, columns: list[Any]) -> Any:
        """The first column that holds values, chosen per element when the columns are lists of one length."""
        present = [column for column in columns if texts(column)]
        if present and all(isinstance(column, list) for column in present) and len({len(column) for column in present}) == 1:
            return [
                next((column[position] for column in present if texts(column[position])), None)
                for position in range(len(present[0]))
            ]
        return present[0] if present else None

    @staticmethod
    def _of_element_kind(values: Any, kinds: Any, wanted: str) -> list | None:
        """``values`` kept where the element's ``type`` is ``wanted``; None when the two lists do not line up."""
        if not isinstance(values, list) or not isinstance(kinds, list) or len(values) != len(kinds):
            return None
        return [value if kind == wanted else None for value, kind in zip(values, kinds)]

    @staticmethod
    def _is_template(value: Any) -> bool:
        """Whether a value is a placeholder (``/contents/{machineId}/``): it holds braces or blanks; brackets alone are real."""
        return isinstance(value, str) and (any(char in value for char in "{}") or any(char.isspace() for char in value))

    @classmethod
    def _observable_type(cls, indicator_type: str, value: Any) -> str:
        """IP for an address in a domain field, IPv6 for an IPv6 address in a domain or IP field."""
        if indicator_type == FeedIndicatorType.Domain and isinstance(value, str) and cls.IPV4_RE.match(value.strip()):
            return FeedIndicatorType.IP
        if indicator_type in (FeedIndicatorType.IP, FeedIndicatorType.Domain) and cls.is_ipv6(value):
            return FeedIndicatorType.IPv6
        return indicator_type

    @classmethod
    def _wallet(cls, value: Any) -> Any:
        """A Bitcoin address with the ``bitcoin:`` prefix, as extraction writes a base58check one; any other wallet as it is."""
        if not isinstance(value, str):
            return value
        address = value.strip()
        if address.lower().startswith(cls.BITCOIN_PREFIX):
            address = address[len(cls.BITCOIN_PREFIX) :]
        return f"{cls.BITCOIN_PREFIX}{address}" if cls._is_bitcoin_address(address) else address

    @classmethod
    def _is_bitcoin_address(cls, address: str) -> bool:
        """Base58check starting with 1 or 3 (what extraction and CryptoCurrenciesFormat accept) or bech32 starting with bc1."""
        if cls.BECH32_BITCOIN_RE.fullmatch(address):
            return True
        if address[:1] not in ("1", "3") or not 26 <= len(address) <= 35:
            return False
        number = 0
        for char in address:
            digit = cls.BASE58_DIGITS.find(char)
            if digit < 0:
                return False
            number = number * 58 + digit
        try:
            raw = number.to_bytes(25, "big")
        except OverflowError:
            return False
        return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


""" COMMANDS """


class FetchIncidentsCommand:
    """fetch-incidents: the records of every selected collection since its cursor, as incidents, and the next last_run."""

    # The duplicate-cache key of the 3.x last_run, so that a 3.x cache carries over.
    SEEN_IDS_KEY = "found_incident_ids"
    # "Incidents first fetch" as the run that stored the cursors read it: a change drops them, so the fetch
    # restarts from the new date.
    FIRST_FETCH_KEY = "first_fetch_time"
    HUNTING_RULES_KEY = "hunting_rules"
    # The key of a record in the duplicate cache, carried by the record until its incident is built.
    DEDUP_ID_KEY = "gibDedupId"
    # The digests of the records read at each BoundaryPages cursor, stored with it.
    BOUNDARY_KEYS_KEY = "boundary_keys"

    class NoStartCursor(ConnectionException):
        """A collection that waits for a sequence_list cursor of the first-fetch date."""

    def __init__(self, client: Client, settings: Settings, clock: Callable[[], float] | None = None) -> None:
        self._client = client
        self._settings = settings
        self._clock = clock or time.time
        self._boundary_keys: dict[str, list[str]] = {}
        self._stalls: list[str] = []

    def run(self, last_run: Any) -> tuple[dict, list]:
        """The next last_run and the incidents; it fails only when each collection reports a failure and no incident was built."""
        settings = self._settings
        demisto.debug(f"[fetch-incidents] Starting fetch with settings: {settings}")
        dedup_enabled = settings.dedup_enabled()
        for collection_name in settings.incident_collections:
            CollectionSpec.validate(collection_name)
        state = self._state(last_run)
        demisto.debug(f"[fetch-incidents] Initial last_run summary: {self._summary(state)}")
        if dedup_enabled:
            # An entry past the lookback hides no record: the cache is pruned before the first page is filtered.
            seen_ids = state.get(self.SEEN_IDS_KEY)
            state[self.SEEN_IDS_KEY] = self._prune(seen_ids if isinstance(seen_ids, dict) else {}, settings.retention_seconds)
        incidents: list[dict] = []
        next_run: dict[str, Any] = {"last_fetch": {}}
        refusals: list[str] = []
        for collection_name in settings.incident_collections:
            next_run["last_fetch"][collection_name], refusal = self._fetch(collection_name, state, incidents, dedup_enabled)
            if refusal:
                refusals.append(refusal)
        if refusals or self._stalls:
            message = " ".join(refusals + self._stalls)
            if len(refusals) == len(settings.incident_collections) and not incidents:
                raise DemistoException(message)
            demisto.error(f"[fetch-incidents] {message}")
            demisto.updateModuleHealth(message, is_error=True)
        # The duplicate cache is kept only while the built-in deduplication is on; turned on again, it starts empty.
        next_run[self.SEEN_IDS_KEY] = state.get(self.SEEN_IDS_KEY, {}) if dedup_enabled else {}
        next_run[self.FIRST_FETCH_KEY] = settings.first_fetch
        next_run[self.HUNTING_RULES_KEY] = bool(settings.hunting_rules)
        if self._boundary_keys:
            next_run[self.BOUNDARY_KEYS_KEY] = self._boundary_keys
        demisto.debug(f"[fetch-incidents] Final next_run summary: {self._summary(next_run)}")
        demisto.debug(f"[fetch-incidents] Incidents created this run: count={len(incidents)}")
        return next_run, incidents

    NO_ADVANCE = (
        "Group-IB answered {collection} with a page whose seqUpdate does not advance; the collection is read no "
        "further this run."
    )

    def _fetch(
        self, collection_name: str, state: dict, incidents: list[dict], dedup_enabled: bool
    ) -> tuple[str | None, str | None]:
        """Appends one collection's incidents and returns its next cursor and any refusal; a refusal keeps earlier pages."""
        cursor = self._cursor(state, collection_name)
        seen_keys = (state.get(self.BOUNDARY_KEYS_KEY) or {}).get(collection_name) or () if cursor else ()
        try:
            hunting_rules = self._hunting_rules(collection_name)
            pages, start_cursor = self._open_feed(
                collection_name=collection_name, cursor=cursor, hunting_rules=hunting_rules, seen_keys=seen_keys
            )
        except self.NoStartCursor as waiting:
            return cursor, f"{collection_name} is not fetched yet: {waiting}."
        except ConnectionException as refused:
            if seen_keys:
                self._boundary_keys[collection_name] = list(seen_keys)
            return cursor, self._refusal(collection_name, refused)
        start = seq_update_number(start_cursor)
        spec = CollectionSpec.of(collection_name)
        hunting_rules_applied = hunting_rules == 1 or spec.server_scoped
        max_seen: int | None = None
        refusal: str | None = None
        requests_count = 0
        try:
            for page in Client.refusals_as_messages(pages, lambda exc: self._refusal(collection_name, exc)):
                page_seq = seq_update_number(page.sequpdate)
                demisto.debug(
                    f"[fetch-incidents] Portion received: collection={collection_name}, seqUpdate={page.sequpdate}, "
                    f"portion_size={page.portion_size}, count={page.count}"
                )
                floor = start if max_seen is None else max_seen
                if (
                    isinstance(floor, int)
                    and isinstance(page_seq, int)
                    and page_seq <= floor
                    and not isinstance(pages, BoundaryPages)
                ):
                    # ciaops would ask for the same page again.
                    refusal = self.NO_ADVANCE.format(collection=collection_name)
                    demisto.debug(f"[fetch-incidents] seqUpdate did not advance past {floor}; the collection is read no further")
                    break
                # Every page read counts against "Number of requests per collection" and moves the cursor past it, even a
                # page without a usable record: it must not be read again on the next run.
                requests_count += 1
                if isinstance(page_seq, int) and page_seq > 0:
                    max_seen = page_seq if max_seen is None else max(max_seen, page_seq)
                records = self._records(collection_name, page)
                if records:
                    seen_ids = (state.get(self.SEEN_IDS_KEY) or {}) if dedup_enabled else None
                    built = self._build(collection_name, records, hunting_rules_applied, incidents, seen_ids)
                    if dedup_enabled and built:
                        self._remember(state, built, self._settings.retention_seconds)
                if requests_count >= self._settings.max_requests or spec.cursor_from_items:
                    break
        except DemistoException as exc:
            refusal = str(exc)
        if isinstance(pages, BoundaryPages):
            self._boundary_keys[collection_name] = pages.seen_keys
            self._stalls.extend(pages.stalls)
        next_cursor = max_seen if isinstance(max_seen, int) and max_seen > 0 else start
        return (str(next_cursor) if isinstance(next_cursor, int) and next_cursor > 0 else None), refusal

    def _hunting_rules(self, collection_name: str) -> int | None:
        """``apply_hunting_rules``: 1 when the spec forces it or the setting, the collection and the grant allow it."""
        if CollectionSpec.of(collection_name).forces_hunting_rules:
            return 1
        if not self._settings.hunting_rules:
            return None
        if collection_name not in TICollections.APPLY_HUNTING_RULES:
            demisto.debug(f"[hunting-rules] {collection_name} takes no apply_hunting_rules parameter")
            return None
        if collection_name not in self._client.hunting_rules_collections():
            demisto.debug(f"[hunting-rules] no hunting rules granted for {collection_name}; the parameter is not sent")
            return None
        return 1

    def _open_feed(
        self, collection_name: str, cursor: str | None, hunting_rules: int | None, seen_keys: Iterable[str] = ()
    ) -> tuple[Any, Any]:
        """The pages and the start cursor: the stored one, else sequence_list's; NoStartCursor when a collection must wait."""
        date_from = None if cursor else self._settings.first_fetch_date
        demisto.debug(f"[fetch-incidents] {collection_name}: cursor={cursor}, date_from={date_from}")
        sequpdate: int | str | None = cursor
        date_from_for_generator: str | None = date_from
        if not cursor and date_from:
            failure, remedy = f"gave no start cursor for {date_from} (an empty answer)", "; the next fetch asks again"
            try:
                resolved_seq = self._client.sequence_cursor(collection_name, date_from, hunting_rules)
            except Exception as e:
                resolved_seq, failure = None, f"gave no start cursor for {date_from} ({e})"
            if resolved_seq == 1:
                failure = f"answered 1 for {date_from}, the start of the collection rather than a cursor for that date"
                remedy = "; the next fetch asks again"
            elif resolved_seq == 0:
                failure = f"answered {resolved_seq} for {date_from}"
                remedy = (
                    ". A later 'Incidents first fetch' date gives it a cursor, though changing the setting restarts "
                    "every selected collection from the new date"
                )
            if isinstance(resolved_seq, int) and resolved_seq > 1:
                sequpdate = resolved_seq
                date_from_for_generator = None
            elif CollectionSpec.of(collection_name).starts_from_date:
                demisto.debug(f"[fetch-incidents] {collection_name}: sequence_list {failure}; reading from {date_from}")
            else:
                raise self.NoStartCursor(
                    f"sequence_list {failure}; the collection cannot start from a date, so it waits for a sequence_list "
                    f"cursor instead of being read from its oldest record{remedy}"
                )
        record_filter = self._settings.record_filter
        if record_filter.rules.get(collection_name):
            demisto.debug(f"[fetch-incidents] {collection_name}: filters {record_filter.describe(collection_name)}")
        # The account type flags are compromised/account_group's own; the other collections get none of them.
        account_group = collection_name == TICollections.COMPROMISED_ACCOUNT_GROUP
        # The binary filters go out as 0/1; a bool would be sent as True/False.
        request_params = TIRequestParams(
            date_from=date_from_for_generator,
            limit=Client.page_size(collection_name, self._client.limit),
            apply_hunting_rules=None if hunting_rules is None else int(bool(hunting_rules)),
            probable_corporate_access=int(bool(self._settings.enable_probable_corporate_access)) if account_group else None,
            unique=int(bool(self._settings.unique)) if account_group else None,
            combolist=int(bool(self._settings.combolist)) if account_group else None,
            **record_filter.request_params(collection_name),
        )
        return self._client.update_feed(collection_name, request_params, sequpdate, seen_keys), sequpdate

    def _records(self, collection_name: str, page: Any) -> list[dict]:
        """The masked records of a page that carry an id, each with its duplicate-cache key."""
        parsed = page.parse_portion(keys=CollectionSpec.of(collection_name).mapping)
        records = [
            IncidentBuilder.scalar_fields(self._settings.masking.apply(collection_name, record), ("id",))
            for record in (parsed if isinstance(parsed, list) else [])
            if isinstance(record, dict) and record.get("id")
        ]
        for record in records:
            record[self.DEDUP_ID_KEY] = self._dedup_id(collection_name, record)
        return records

    def _build(
        self, collection_name: str, records: list[dict], hunting_rules_applied: bool, incidents: list[dict], seen_ids: dict | None
    ) -> list[dict]:
        """Appends the incidents of the kept records and returns those records; a record that fails to build is skipped."""
        built = []
        for record in self._keep(records, collection_name, seen_ids):
            try:
                incidents.append(
                    IncidentBuilder().build(
                        collection_name=collection_name,
                        record={key: value for key, value in record.items() if key != self.DEDUP_ID_KEY},
                        hunting_rules_applied=hunting_rules_applied,
                    )
                )
                built.append(record)
            except Exception as exc:  # noqa: BLE001 - a record that fails to build does not block the collection
                # The record is skipped and the cursor moves on; the log names it without its content.
                demisto.error(f"[fetch-incidents] {collection_name} record {record.get('id')!r} skipped: {exc}")
        return built

    def _keep(self, records: list[dict], collection_name: str, seen_ids: dict | None) -> list[dict]:
        """Records the filters pass: unflagged ones not cached, flagged ones passed on with a cached group; both with no cache."""
        spec = CollectionSpec.of(collection_name)
        now = datetime.fromtimestamp(self._clock(), tz=UTC)
        kept = []
        filtered = 0
        for record in records:
            flagged = bool(spec.withdrawal_flags(record))
            if flagged and not self._settings.pass_flagged_phishing_groups:
                continue
            if not self._settings.record_filter.accepts(collection_name, record, now):
                filtered += 1
                continue
            # A flagged record passed on goes only when the cache holds its group, whose open incident the rule updates,
            # or when the cache is off.
            if seen_ids is None or self._contains(record[self.DEDUP_ID_KEY], seen_ids) == flagged:
                kept.append(record)
        if filtered:
            demisto.debug(f"[fetch-incidents] {collection_name}: {filtered} record(s) skipped by the instance filters")
        return kept

    def _refusal(self, collection_name: str, exc: Exception) -> str:
        """The message of a failed fetch, with the usual causes of an HTTP 400 and of an HTTP 500 to a forums query."""
        hint = (
            " The usual causes: 'Incidents first fetch' asks for more than your license serves (on a trial or POC"
            " account, some collections serve only the last 30 days), or a 'Collection filters' value the API cannot"
            " parse; shorten the window or correct the filter."
            if str(exc).startswith("HTTP 400")
            else ""
        )
        query = self._settings.record_filter.rules.get(collection_name, {}).get("query")
        if http_status(exc) == "500" and query and CollectionSpec.of(collection_name).cursor_from_items:
            hint = " The collection answers HTTP 500 to a query it cannot parse; check its query in 'Collection filters'."
        return f"The fetch of {collection_name} failed: {exc}.{hint}"

    def _state(self, last_run: Any) -> dict:
        """The working copy of last_run: the cursors, the first-fetch fingerprint and the duplicate cache."""
        state = last_run.copy() if isinstance(last_run, dict) else {}
        state = self._migrate(state)
        state = self._drop_cursors_if_first_fetch_changed(state, self._settings.first_fetch)
        return self._drop_cursors_if_hunting_rules_changed(state, bool(self._settings.hunting_rules))

    @classmethod
    def _drop_cursors_if_first_fetch_changed(cls, state: dict, first_fetch: str) -> dict:
        """The state without its cursors when "Incidents first fetch" changed; one without the fingerprint keeps them."""
        previous = state.get(cls.FIRST_FETCH_KEY)
        if previous is None or previous == first_fetch:
            return state
        demisto.info(
            f"[fetch-incidents] 'Incidents first fetch' changed from {previous!r} to {first_fetch!r}; "
            "dropping the stored seqUpdate cursors so every collection restarts from the new date."
        )
        reset = {key: value for key, value in state.items() if "/" not in str(key)}
        reset["last_fetch"] = {}
        return reset

    @classmethod
    def _drop_cursors_if_hunting_rules_changed(cls, state: dict, hunting_rules: bool) -> dict:
        """The state without its cursors when "Hunting Rules" changed; one without the fingerprint keeps them."""
        # The filtered and the unfiltered views of a collection move through different cursors.
        previous = state.get(cls.HUNTING_RULES_KEY)
        if previous is None or bool(previous) == hunting_rules:
            return state
        demisto.info(
            f"[fetch-incidents] 'Hunting Rules' changed from {bool(previous)} to {hunting_rules}; "
            "dropping the stored seqUpdate cursors so every collection restarts from the first-fetch date."
        )
        reset = {key: value for key, value in state.items() if "/" not in str(key)}
        reset["last_fetch"] = {}
        return reset

    @classmethod
    def _cursor(cls, state: dict, collection_name: str) -> str | None:
        """The stored cursor of a collection as the update feed takes it, None when there is none."""
        embedded = state.get("last_fetch")
        raw = embedded.get(collection_name) if isinstance(embedded, dict) else state.get(collection_name)
        demisto.debug(f"[fetch-incidents] Collection={collection_name} previous_last_fetch={raw}")
        number = seq_update_number(raw)
        return str(number) if isinstance(number, int) and number > 0 else None

    @classmethod
    def _summary(cls, state: dict | None) -> dict[str, Any]:
        """The cursors and the size of the duplicate cache, for the debug log."""
        if not isinstance(state, dict):
            return {"last_fetch": {}, "seen_incident_ids_cache_size": 0}
        last_fetch = state.get("last_fetch", {})
        seen = state.get(cls.SEEN_IDS_KEY, {})
        return {
            "last_fetch": last_fetch if isinstance(last_fetch, dict) else {},
            "seen_incident_ids_cache_size": len(seen) if isinstance(seen, dict) else 0,
        }

    def _prune(self, seen_ids: dict[str, float], retention_seconds: int, now: float | None = None) -> dict[str, float]:
        """A new duplicate cache without the entries older than ``retention_seconds``; an entry of unknown age is dropped."""
        if retention_seconds <= 0:
            return {}
        threshold = (self._clock() if now is None else now) - retention_seconds
        pruned: dict[str, float] = {}
        for record_id, added in seen_ids.items():
            if not isinstance(added, int | float) or added < 0:
                continue
            if added >= threshold:
                pruned[record_id] = float(added)
        return pruned

    def _remember(self, state: dict, records: list[dict], retention_seconds: int) -> None:
        """Adds the keys of ``records`` to the duplicate cache (key -> unix seconds) and prunes it."""
        if not records:
            return
        raw_cache = state.get(self.SEEN_IDS_KEY) or {}
        if not isinstance(raw_cache, dict):
            raw_cache = {}
        cache = {str(record_id): float(added) for record_id, added in raw_cache.items() if isinstance(added, int | float)}
        now = self._clock()
        for record in records:
            record_id = record.get(self.DEDUP_ID_KEY, record.get("id"))
            if record_id is not None:
                cache[str(record_id)] = now
        state[self.SEEN_IDS_KEY] = self._prune(cache, retention_seconds, now)

    @classmethod
    def _contains(cls, dedup_id: str, seen_ids: dict) -> bool:
        """Whether the cache holds the record, under its key or, for a collection keyed by id alone, under its 3.x bare id."""
        if dedup_id in seen_ids:
            return True
        collection_name, _, record_id = dedup_id.partition("|")
        return CollectionSpec.of(collection_name).dedup_fields == ("id",) and record_id in seen_ids

    @classmethod
    def _migrate(cls, state: dict) -> dict:
        """The state with the bare addresses of a 3.x cache keyed for its one suspicious_ip/* collection, else dropped."""
        seen_ids = state.get(cls.SEEN_IDS_KEY)
        if not isinstance(seen_ids, dict):
            return state
        addresses = {key for key in seen_ids if cls._is_bare_address(key)}
        if not addresses:
            return state
        cursors = state.get("last_fetch")
        previous = {str(key) for key in (cursors if isinstance(cursors, dict) else {})}
        previous.update(str(key) for key in state if "/" in str(key))
        readers = [name for name in previous if name.startswith("suspicious_ip/")]
        keyed_by_address = len(readers) == 1 and CollectionSpec.of(readers[0]).dedup_fields == ("id",)
        owner = readers[0] if keyed_by_address else None
        migrated = {key: added for key, added in seen_ids.items() if key not in addresses}
        if owner:
            for key in addresses:
                migrated.setdefault(f"{owner}|{key}", seen_ids[key])
        demisto.debug(f"[fetch-incidents] {len(addresses)} cached bare addresses {'keyed for ' + owner if owner else 'dropped'}")
        return {**state, cls.SEEN_IDS_KEY: migrated}

    @staticmethod
    def _is_bare_address(key: Any) -> bool:
        """Whether a cache key is an address without the collection ``_dedup_id`` puts first."""
        if "|" in str(key):
            return False
        try:
            ipaddress.ip_address(str(key))
        except ValueError:
            return False
        return True

    @staticmethod
    def _dedup_id(collection_name: str, record: dict) -> str:
        """The record's duplicate-cache key: the collection and its dedup_fields."""
        fields = CollectionSpec.of(collection_name).dedup_fields
        return "|".join([collection_name, *("" if record.get(name) is None else str(record.get(name)) for name in fields)])


class LookupCommand:
    """The gibti-get-*-info commands: the record of an id with its War Room tables and its indicators."""

    # The threat lookups read hi/<target> or, with the isAPT argument, apt/<target>, and fall back to the other one.
    THREAT_TARGETS = ("threat", "threat_actor")
    # One page of a q=<ip> search, large enough for every listing of one address.
    LISTINGS_PAGE_SIZE = 1000
    # A War Room table cell is cut at CELL_LIMIT characters and a table at ROW_LIMIT rows; the context keeps everything.
    # A CVE's description and software list otherwise make the entry too big to be displayed.
    CELL_LIMIT = 1000
    ROW_LIMIT = 200
    # The context key of a listing, "<ip>:<port>": the context merges an entry into the object whose key fields are all
    # truthy and equal, which a port of 0 never is.
    LISTING_KEY_FIELD = "listing"

    def __init__(self, target: str, client: Client, settings: Settings) -> None:
        # A collection, or one of THREAT_TARGETS.
        self.target = target
        self._client = client
        self._masking = settings.masking
        self._indicators = IndicatorBuilder(settings.source_reliability, settings.create_relationships)

    def run(self, args: dict) -> list[CommandResults]:
        if self.target in self.THREAT_TARGETS:
            return self._threats(args)
        if args.get("id") in (None, ""):
            raise DemistoException("Argument 'id' is required.")
        record_id = str(args.get("id"))
        results = self._results(self.target, record_id)
        if results is None:
            raise DemistoException(f"No record with id {record_id!r} was found in {self.target}.")
        return results

    def _threats(self, args: dict) -> list[CommandResults]:
        """Each id from the collection isAPT names, else the other; refusals fail the command only when no id was read."""
        ids = texts(argToList(args.get("id")))
        if not ids:
            raise DemistoException("Argument 'id' is required.")
        collections = self._threat_collections(args)
        results: list[CommandResults] = []
        missing: list[str] = []
        refusals: list[str] = []
        unread: list[str] = []
        for id_ in ids:
            errors: list[str] = []
            not_found = False
            for collection in collections:
                try:
                    found = self._results(collection, id_)
                except DemistoException as exc:
                    errors.append(str(exc))
                    continue
                if found is None:
                    not_found = True
                    continue
                results.extend(found)
                break
            else:
                if errors and not not_found:
                    refusals.extend(errors)
                else:
                    # Not published in the collection the key can read; the one it cannot read (a key without APT
                    # access) cannot say otherwise, so its refusal is a note, not an error.
                    missing.append(id_)
                    unread.extend(errors)
        if refusals and not results:
            raise DemistoException(" ".join(refusals))
        notes = []
        if missing:
            notes.append(f"Group-IB publishes no {' or '.join(collections)} record with id {' or '.join(missing)}.")
        notes.extend(unread)
        notes.extend(refusals)
        if notes:
            results.append(
                CommandResults(
                    readable_output=" ".join(notes) + " Nothing was added to the context for these ids.",
                    raw_response={"missing": missing, "refused": refusals, "unread": unread, "collections": list(collections)},
                )
            )
        return results

    def _threat_collections(self, args: dict) -> tuple[str, str]:
        """The collection read first and the other one."""
        raw = args.get("isAPT")
        is_apt = argToBoolean(raw) if raw not in (None, "") else False
        return (f"apt/{self.target}", f"hi/{self.target}") if is_apt else (f"hi/{self.target}", f"apt/{self.target}")

    def _results(self, collection_name: str, record_id: str) -> list[CommandResults] | None:
        """The entries of the record of ``record_id`` (every listing of an open proxy), None when there is none."""
        spec = CollectionSpec.of(collection_name)
        if spec.lookup_route != "listings":
            record = self._record(collection_name, record_id)
            if record is None:
                return None
            record_entry, tables, indicators = self._entries(collection_name, record)
            return [record_entry, *tables, *indicators]
        listings = self._listings(collection_name, record_id)
        if not listings:
            return None
        results: list[CommandResults] = []
        for position, listing in enumerate(listings):
            key = ":".join("" if listing.get(name) is None else str(listing[name]) for name in spec.listing_keys)
            record_entry, tables, indicators = self._entries(collection_name, listing, key)
            # The indicator of the listings (the address) comes with the first listing only.
            results.extend([record_entry, *tables, *(indicators if position == 0 else [])])
        return results

    def _record(self, collection_name: str, record_id: str) -> dict | None:
        """The record of ``record_id``, masked and shaped as its incident; None when the collection has none."""
        route = CollectionSpec.of(collection_name).lookup_route
        record: Any = {}
        if route == "route":
            record = self._from_route(collection_name, record_id)
        elif route in ("id query", "text query"):
            query = f"id:{record_id}" if route == "id query" else record_id
            record = self._from_update_feed(collection_name, record_id, query)
        else:
            record = self._by_id(collection_name, record_id)
        if not isinstance(record, dict) or not record:
            return None
        record = self._masking.apply(collection_name, record)
        record = IncidentBuilder.blank_placeholder_dates(IncidentBuilder.shape(collection_name, record))
        # The War Room table and the context show a narrative as its incident does: as text.
        record = IncidentBuilder.plain_text(collection_name, record)
        # Breached records carry their id and their authors as lists; the context key and the readable need one string.
        return IncidentBuilder.scalar_fields(record, ("id", "threat_actor_name"))

    def _listings(self, collection_name: str, record_id: str) -> list[dict]:
        """Every record whose id is the address ``record_id``, once per listing key; ``q=<ip>`` also matches mere mentions."""
        spec = CollectionSpec.of(collection_name)
        listings: dict[str, dict] = {}
        for page in self._client.search_collection(collection_name, query=record_id, limit=self.LISTINGS_PAGE_SIZE) or []:
            if page is None:
                continue
            parsed = page.parse_portion(keys=spec.mapping)
            for record in parsed if isinstance(parsed, list) else [parsed]:
                if isinstance(record, dict) and str(record.get("id")) == record_id:
                    listings.setdefault(json.dumps([record.get(name) for name in spec.listing_keys]), record)
            break
        return [
            IncidentBuilder.shape(collection_name, self._masking.apply(collection_name, record)) for record in listings.values()
        ]

    def _by_id(self, collection_name: str, record_id: str) -> Any:
        """``GET /{collection}/{id}``, {} without such a record; a 403 is checked against the update feed where the spec says."""
        try:
            portion = self._client.record_by_id(collection_name, record_id)
        except NotFoundException:
            return {}
        except ConnectionException as exc:
            # `from None`: the War Room error shows the message, not the ciaops traceback chain.
            refusal = DemistoException(f"The lookup of id {record_id!r} in {collection_name} failed: {exc}")
            if not (str(exc).startswith("HTTP 403") and CollectionSpec.of(collection_name).checks_update_feed_on_refusal):
                raise refusal from None
            try:
                return self._from_update_feed(collection_name, record_id, f"id:{record_id}")
            except ConnectionException:
                # The update feed fails as well: the 403 stands.
                raise refusal from None
        if portion is None:
            return {}
        parsed = portion.parse_portion(keys=CollectionSpec.of(collection_name).mapping)
        return parsed[0] if isinstance(parsed, list) and parsed else parsed

    def _from_route(self, collection_name: str, record_id: str) -> Any:
        """The record from the collection's by_id_route, {} when there is none."""
        # A 4xx other than 429 is the key's error; any other failure is temporary.
        spec = CollectionSpec.of(collection_name)
        try:
            body = self._client.record_by_route(str(spec.by_id_route), record_id)
        except NotFoundException:
            return {}
        except ConnectionException as exc:
            status = http_status(exc)
            if status and status.startswith("4") and status != "429":
                raise DemistoException(f"Group-IB refused the lookup of id {record_id!r} in {collection_name}: {exc}") from None
            raise DemistoException(
                f"Group-IB did not answer the lookup of id {record_id!r} in {collection_name} ({exc}); try again later."
            ) from None
        if not isinstance(body, dict) or not body:
            return {}
        record = ParserHelper.find_by_template(body, spec.mapping)
        return record if self._has_id(record, record_id) else {}

    def _from_update_feed(self, collection_name: str, record_id: str, query: str) -> Any:
        """The record of ``record_id`` among the update feed's answer to ``query``, or {}."""
        for page in self._client.search_collection(collection_name, query=query, limit=1) or []:
            if page is None:
                continue
            parsed = page.parse_portion(keys=CollectionSpec.of(collection_name).mapping)
            records = parsed if isinstance(parsed, list) else [parsed]
            if query.startswith("id:"):
                return next((r for r in records if isinstance(r, dict) and self._has_id(r, record_id)), {})
            return next((r for r in records if isinstance(r, dict) and str(r.get("id")) == record_id), {})
        return {}

    @staticmethod
    def _has_id(record: dict, record_id: str) -> bool:
        """Whether a record is the one with ``record_id``: its id, one of its ids, or no id at all."""
        value = record.get("id")
        if value in (None, ""):
            return True
        ids = value if isinstance(value, list) else [value]
        return record_id in {str(item) for item in ids}

    def _entries(
        self, collection_name: str, record: dict, listing_key: str | None = None
    ) -> tuple[CommandResults, list[CommandResults], list[CommandResults]]:
        """One record's context entry, its nested-object tables and its indicator entries."""
        spec = CollectionSpec.of(collection_name)
        record = IncidentBuilder.portal_link(collection_name, self._without_empty_columns(record))
        flags = spec.withdrawal_flags(record)
        indicators = [] if flags else self._indicators.results(record, collection_name)
        table = deepcopy(record)
        # The indicators block restates the record for the indicator entries (a CVE's description, its software list):
        # in the main table it only makes the entry too big to show.
        table.pop("indicators", None)
        tables = [] if collection_name == TICollections.COMPROMISED_BREACHEDDB else self._nested_tables(table)
        readable_output = self._table(table, f"Feed from {collection_name} with ID {record.get('id')}")
        if flags:
            readable_output = (
                f"Group-IB flags this record as {' and '.join(flags)}: none of its observables is returned as an "
                "indicator.\n\n" + readable_output
            )
        if listing_key is not None:
            record[self.LISTING_KEY_FIELD] = listing_key
        record_entry = CommandResults(
            outputs_prefix=spec.context_prefix,
            outputs_key_field=self.LISTING_KEY_FIELD if spec.listing_keys else "id",
            outputs=record,
            readable_output=readable_output,
            raw_response=record,
            ignore_auto_extract=True,
        )
        return record_entry, tables, indicators

    @staticmethod
    def _without_empty_columns(record: dict) -> dict:
        """The record without the nested-object columns that are empty for every element (``string`` of most CPE rows)."""
        for key, value in record.items():
            if key != "indicators" and isinstance(value, dict):
                record[key] = {column: values for column, values in value.items() if texts(values)}
        return record

    def _nested_tables(self, table: dict) -> list[CommandResults]:
        """Takes the nested objects out of ``table``: one entry per object, one row per element."""
        tables = []
        for key in [key for key, value in table.items() if key not in ("evaluation", "indicators") and isinstance(value, dict)]:
            rows = [row for row in IncidentBuilder.rows(table.pop(key)) if any(v not in (None, "", []) for v in row.values())]
            if rows:
                tables.append(CommandResults(readable_output=self._table(rows, f"{key} table"), ignore_auto_extract=True))
        return tables

    @classmethod
    def _table(cls, table: dict[Any, Any] | list[dict[Any, Any]], name: str) -> str:
        rows = table if isinstance(table, list) else [table]
        shown = [{key: cls._cell(value) for key, value in row.items()} for row in rows[: cls.ROW_LIMIT]]
        if len(rows) > cls.ROW_LIMIT:
            name = f"{name} (first {cls.ROW_LIMIT} of {len(rows)} rows; every row is in the context)"
        return tableToMarkdown(name=name, t=shown if isinstance(table, list) else shown[0], removeNull=True)

    @classmethod
    def _cell(cls, value: Any) -> Any:
        """A cell of a War Room table, cut at CELL_LIMIT characters."""
        if isinstance(value, str):
            text = value
        elif isinstance(value, (dict, list)):
            text = json_text(value)
        else:
            return value
        if len(text) <= cls.CELL_LIMIT:
            return value
        return (
            f"{text[: cls.CELL_LIMIT]}... [incomplete: the first {cls.CELL_LIMIT} of {len(text)} characters; "
            "the full value is in the context]"
        )


# WHOIS records of the Graph endpoints. A field is a list of values; registry and registrar texts carry placeholders.
WHOIS_PLACEHOLDER_RE = re.compile(
    r"(?i)redacted|privacy|not disclosed|data protected|withheld|gdpr|please query|not allocated to|^\+?0+$|^https?://|rpki roa|"
    r"proxy-registered|statutory masking"
)


def whois_texts(values: Any) -> list[str]:
    """The non-placeholder texts of a WHOIS field, trimmed and without a tel: prefix, in order, without repeats."""
    seen: list[str] = []
    for value in values if isinstance(values, list) else [values]:
        text = str(value).strip().removeprefix("tel:") if value not in (None, "") else ""
        if text and not WHOIS_PLACEHOLDER_RE.search(text) and text not in seen:
            seen.append(text)
    return seen


def whois_first(values: list[str] | None) -> str | None:
    """The first value of a WHOIS field, None without one."""
    return values[0] if values else None


def whois_fields(parsed: Any) -> dict[str, list[str]]:
    """The ``{field, value}`` pairs of a parsed WHOIS object, by field name in lower case without underscores."""
    fields: dict[str, list[str]] = {}
    for pair in parsed if isinstance(parsed, list) else []:
        if isinstance(pair, dict) and pair.get("field"):
            name = str(pair["field"]).lower().replace("_", "")
            fields.setdefault(name, []).extend(whois_texts(pair.get("value")))
    return fields


@dataclass(frozen=True)
class IPWhois:
    """The registry record of an IP address from its Graph WHOIS snapshots, each field from the newest that has it."""

    ip: str
    range_start: str | None = None
    range_end: str | None = None
    cidr: str | None = None
    registry: str | None = None
    netname: str | None = None
    organization: str | None = None
    country: str | None = None
    asn: str | None = None
    as_owner: str | None = None
    abuse_emails: tuple[str, ...] = ()
    abuse_phones: tuple[str, ...] = ()
    status: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    history: tuple[dict[str, Any], ...] = ()

    ASN_RE: ClassVar[re.Pattern] = re.compile(r"(?i)^(?:AS)?(\d{1,10})$")

    @classmethod
    def parse(cls, ip: str, body: Any, history_limit: int = 0) -> "IPWhois":
        if not isinstance(body, dict):
            return cls(ip=ip)
        snapshots = sorted(
            (item for item in body.get("whoisHistory") or body.get("whois_history") or [] if isinstance(item, dict)),
            key=lambda item: str(item.get("last_seen") or ""),
            reverse=True,
        )
        # A snapshot can hold the route objects alone.
        latest: dict[str, Any] = {}
        for item in snapshots:
            for name, value in cls._snapshot(item).items():
                if value and not latest.get(name):
                    latest[name] = value
        return cls(
            ip=ip,
            range_start=texts(body.get("start"))[0] if texts(body.get("start")) else None,
            range_end=texts(body.get("end"))[0] if texts(body.get("end")) else None,
            registry=str(body.get("provider")).upper() if body.get("provider") else None,
            first_seen=snapshots[0].get("first_seen") if snapshots else None,
            last_seen=snapshots[0].get("last_seen") if snapshots else None,
            history=tuple(
                {"firstSeen": item.get("first_seen"), "lastSeen": item.get("last_seen"), **cls._summary(cls._snapshot(item))}
                for item in snapshots[1 : history_limit + 1]
            ),
            **latest,
        )

    @classmethod
    def _snapshot(cls, item: dict[str, Any]) -> dict[str, Any]:
        """The fields of one snapshot: its range, organization, AS and abuse contact objects."""
        objects: dict[str, list[dict[str, list[str]]]] = {}
        entries = item.get("data")
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict):
                objects.setdefault(str(entry.get("type") or "").lower(), []).append(whois_fields(entry.get("parsed")))

        def first(kinds: Iterable[str], *names: str) -> str | None:
            for kind in kinds:
                for fields in objects.get(kind, []):
                    for name in names:
                        if fields.get(name):
                            return fields[name][0]
            return None

        origins = [
            cls._asn(origin)
            for fields in objects.get("route", []) + objects.get("route6", [])
            for origin in fields.get("origin", [])
        ]
        origins = [origin for origin in origins if origin]
        asn = cls._asn(first(["aut-num"], "aut-num")) or (max(set(origins), key=origins.count) if origins else None)
        abuse_emails: list[str] = []
        abuse_phones: list[str] = []
        for kind in ("irt", "role", "contact", "organisation", "inetnum", "inet6num"):
            for fields in objects.get(kind, []):
                emails = fields.get("abuse-mailbox", []) + [mail for mail in fields.get("e-mail", []) if "abuse" in mail.lower()]
                for mail in emails:
                    if mail not in abuse_emails:
                        abuse_emails.append(mail)
                if emails:
                    abuse_phones.extend(phone for phone in fields.get("phone", []) if phone not in abuse_phones)
        country = first(["organisation", "inetnum", "inet6num"], "country")
        return {
            "cidr": first(["inetnum", "inet6num"], "cidr"),
            "netname": first(["inetnum", "inet6num"], "netname"),
            "organization": first(["organisation"], "org-name") or first(["inetnum", "inet6num"], "org-name", "owner"),
            "country": country.upper() if country and len(country) == 2 else None,
            "asn": asn,
            "as_owner": first(["aut-num"], "as-name", "org-name", "owner"),
            "abuse_emails": tuple(abuse_emails),
            "abuse_phones": tuple(abuse_phones),
            "status": first(["inetnum", "inet6num"], "status"),
        }

    @classmethod
    def _asn(cls, value: Any) -> str | None:
        match = cls.ASN_RE.match(str(value or "").strip())
        return f"AS{match.group(1)}" if match else None

    @staticmethod
    def _summary(fields: dict[str, Any]) -> dict[str, Any]:
        return {
            "organization": fields.get("organization"),
            "netname": fields.get("netname"),
            "asn": fields.get("asn"),
            "cidr": fields.get("cidr"),
        }

    def to_context(self) -> dict[str, Any]:
        return assign_params(
            ip=self.ip,
            rangeStart=self.range_start,
            rangeEnd=self.range_end,
            cidr=self.cidr,
            registry=self.registry,
            netname=self.netname,
            organization=self.organization,
            country=self.country,
            asn=self.asn,
            asOwner=self.as_owner,
            abuseEmails=list(self.abuse_emails) or None,
            abusePhones=list(self.abuse_phones) or None,
            status=self.status,
            firstSeen=self.first_seen,
            lastSeen=self.last_seen,
            history=list(self.history) or None,
        )


@dataclass(frozen=True)
class DomainWhois:
    """The registration of a domain from the Graph WHOIS: the registry and registrar answers and their history."""

    domain: str
    zone: str | None = None
    registered_domain: bool | None = None
    registrar: str | None = None
    registrar_iana_id: str | None = None
    registrar_abuse_email: str | None = None
    registrar_abuse_phone: str | None = None
    whois_server: str | None = None
    registrant_organization: str | None = None
    registrant_country: str | None = None
    registrant_name: str | None = None
    registrant_email: str | None = None
    statuses: tuple[str, ...] = ()
    creation_date: str | None = None
    updated_date: str | None = None
    expiration_date: str | None = None
    name_servers: tuple[str, ...] = ()
    checked_at: str | None = None
    history: tuple[dict[str, Any], ...] = ()

    # The labels a WHOIS text gives each field, in the order they are tried.
    TEXT_FIELDS: ClassVar[dict[str, tuple[str, ...]]] = {
        "registrar": ("registrar", "registrar name"),
        "creation_date": ("creation date", "created", "registered on", "registration time", "registered"),
        "expiration_date": (
            "registry expiry date",
            "registrar registration expiration date",
            "expiry date",
            "expiration date",
            "paid-till",
            "expires",
        ),
        "updated_date": ("updated date", "last updated", "last modified", "last-modified", "changed"),
        "registrar_iana_id": ("registrar iana id",),
        "registrar_abuse_email": ("registrar abuse contact email",),
        "registrar_abuse_phone": ("registrar abuse contact phone",),
        "whois_server": ("registrar whois server",),
        "registrant_organization": ("registrant organization",),
        "registrant_country": ("registrant country",),
        "registrant_name": ("registrant name", "registrant contact name"),
        "registrant_email": ("registrant email",),
    }
    TEXT_LINE_RE: ClassVar[re.Pattern] = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /\-_.()]{0,60}?)\s*:\s*(\S.*?)\s*$")

    @classmethod
    def parse(cls, domain: str, body: Any, history_limit: int = 0) -> "DomainWhois":
        if not isinstance(body, dict):
            return cls(domain=domain)
        answers = sorted(
            (item for item in body.get("whois") or [] if isinstance(item, dict)),
            key=lambda item: -(as_number(item.get("level")) or 0),
        )
        parsed: dict[str, list[str]] = {}
        texts_found: dict[str, str] = {}
        for answer in answers:
            for name, values in whois_fields(answer.get("parsed")).items():
                parsed.setdefault(name, values) if values else None
            lines = cls._text_fields(answer.get("response"))
            for name, labels in cls.TEXT_FIELDS.items():
                if name not in texts_found:
                    value = next((lines[label] for label in labels if lines.get(label)), None)
                    if value:
                        texts_found[name] = value
        history = sorted(
            (item for item in body.get("whois_history") or body.get("whoisHistory") or [] if isinstance(item, dict)),
            key=lambda item: str(item.get("last_seen") or ""),
            reverse=True,
        )
        # A parsed field the current answers leave empty comes from the newest WHOIS history record that has it.
        for item in history:
            for name, values in whois_fields(item.get("parsed")).items():
                parsed.setdefault(name, values) if values else None
        is_sld = body.get("is_sld", body.get("isSld"))

        def date(name: str) -> str | None:
            text = texts_found.get(name) or whois_first(parsed.get(name.replace("_", "")))
            if not text:
                return None
            moment = dateparser_parse(text)
            if moment is None or moment.year < FIRST_RECORD_YEAR:
                # A registry text such as "before Aug-1996" is no date, and neither is the placeholder 0001-01-01.
                return None
            if moment.tzinfo is not None:
                moment = moment.astimezone(UTC)
            return moment.strftime(DATE_FORMAT)

        return cls(
            domain=domain,
            zone=body.get("zone"),
            registered_domain=is_sld if isinstance(is_sld, bool) else None,
            registrar=texts_found.get("registrar") or whois_first(parsed.get("registrar")),
            registrar_iana_id=texts_found.get("registrar_iana_id"),
            registrar_abuse_email=texts_found.get("registrar_abuse_email"),
            registrar_abuse_phone=texts_found.get("registrar_abuse_phone"),
            whois_server=texts_found.get("whois_server") or whois_first(parsed.get("whoisserver")),
            registrant_organization=texts_found.get("registrant_organization") or whois_first(parsed.get("org")),
            registrant_country=texts_found.get("registrant_country") or whois_first(parsed.get("country")),
            registrant_name=texts_found.get("registrant_name"),
            registrant_email=texts_found.get("registrant_email"),
            # A status is its first word; a registry can list several in one value, separated by commas.
            statuses=tuple(
                dict.fromkeys(
                    part.split()[0].strip(";").lower()
                    for status in parsed.get("status", [])
                    for part in status.split(",")
                    if part.split()
                )
            ),
            creation_date=date("creation_date"),
            updated_date=date("updated_date"),
            expiration_date=date("expiration_date"),
            name_servers=tuple(dict.fromkeys(server.lower().rstrip(".") for server in parsed.get("nameservers", []))),
            checked_at=next((str(answer.get("checked_at")) for answer in answers if answer.get("checked_at")), None),
            # The newest snapshot is the current registration.
            history=tuple(cls._summary(item) for item in history[1 : history_limit + 1]),
        )

    @classmethod
    def _text_fields(cls, response: Any) -> dict[str, str]:
        """The ``label: value`` lines of a WHOIS text by lower-case label, the first of each, placeholders left out."""
        fields: dict[str, str] = {}
        for line in str(response or "").splitlines():
            match = cls.TEXT_LINE_RE.match(line)
            if match:
                values = whois_texts(match.group(2))
                if values:
                    fields.setdefault(match.group(1).strip().lower(), values[0])
        return fields

    @staticmethod
    def _summary(item: dict[str, Any]) -> dict[str, Any]:
        fields = whois_fields(item.get("parsed"))
        return assign_params(
            firstSeen=item.get("first_seen"),
            lastSeen=item.get("last_seen"),
            registrar=whois_first(fields.get("registrar")),
            nameServers=fields.get("nameservers") or None,
        )

    def to_context(self, personal_data: bool = True) -> dict[str, Any]:
        return assign_params(
            domain=self.domain,
            zone=self.zone,
            registeredDomain=self.registered_domain,
            registrar=self.registrar,
            registrarIanaId=self.registrar_iana_id,
            registrarAbuseEmail=self.registrar_abuse_email,
            registrarAbusePhone=self.registrar_abuse_phone,
            whoisServer=self.whois_server,
            registrantOrganization=self.registrant_organization,
            registrantCountry=self.registrant_country,
            registrantName=self.registrant_name if personal_data else None,
            registrantEmail=self.registrant_email if personal_data else None,
            statuses=list(self.statuses) or None,
            creationDate=self.creation_date,
            updatedDate=self.updated_date,
            expirationDate=self.expiration_date,
            nameServers=list(self.name_servers) or None,
            checkedAt=self.checked_at,
            history=list(self.history) or None,
        )


MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def day_first_safe_date(value: str) -> str:
    """A DATE_FORMAT timestamp as ``03 Feb 2001 04:05:06 UTC``, which reads alike day-first and month-first."""
    moment = datetime.strptime(value, DATE_FORMAT)
    return f"{moment.day:02d} {MONTHS[moment.month - 1]} {moment.year} {moment:%H:%M:%S} UTC"


class DomainIndicator(Common.Domain):
    """A Domain indicator that also writes its WHOIS data where the Domain indicator type maps it to fields."""

    def to_context(self) -> dict:
        context = super().to_context()
        domain = context[Common.Domain.CONTEXT_PATH]
        # These two take the form the Domain indicator type reads into Creation Date and Updated Date; Domain.WHOIS keeps
        # the ISO form.
        for key in ("CreationDate", "UpdatedDate"):
            if domain.get(key):
                domain[key] = day_first_safe_date(domain[key])
        # The Domain indicator type reads Registrar Name and Registrar Abuse Email from Whois.Registrar, Organization from
        # Admin.Organization, and the registrant fields from lower-case keys.
        registrar = {"Name": self.registrar_name, "AbuseEmail": self.registrar_abuse_email}
        if any(registrar.values()):
            domain["Whois"] = {"Registrar": {key: item for key, item in registrar.items() if item}}
        if self.organization:
            domain.setdefault("Admin", {})["Organization"] = self.organization
        registrant = {"name": self.registrant_name, "email": self.registrant_email, "country": self.registrant_country}
        whois = domain.get("WHOIS") or {}
        for owner in (domain, whois):
            # Common.Domain gives both the same registrant object, with a key for each field, empty or not.
            if owner.get("Registrant"):
                owner["Registrant"] = {key: item for key, item in owner["Registrant"].items() if item}
        if any(registrant.values()):
            domain["Registrant"] = {**domain.get("Registrant", {}), **{key: item for key, item in registrant.items() if item}}
        return context


class WhoisCommand:
    """gibti-ip-whois and gibti-domain-whois: the registry record of each IP or domain of the list."""

    def __init__(self, kind: str, client: Client, settings: Settings) -> None:
        # "ip" or "domain".
        self.kind = kind
        self._client = client
        self._settings = settings

    def run(self, args: dict) -> list[CommandResults]:
        history = argToBoolean(args.get("history") or False)
        limit = SearchCommand._optional_int(args.get("history_limit"), "history_limit")
        limit = 10 if limit is None else limit
        if limit < 1:
            raise DemistoException("history_limit must be 1 or more.")
        return [
            value_result(lambda value: self._result(value, limit if history else 0), value)
            for value in argument_values(args, [self.kind], self.kind, unique=True)
        ]

    def _result(self, typed: str, history_limit: int) -> CommandResults:
        value = str(IndicatorBuilder.refang(typed) or "").strip()
        if self.kind == "ip":
            return self._ip(value, history_limit)
        return self._domain(value.lower().rstrip("."), history_limit)

    def _ip(self, value: str, history_limit: int) -> CommandResults:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return self._note(value, f"`{value}` is not an IP address; no lookup was made.")
        if not self._settings.lookup_internal_addresses and not address.is_global:
            return self._note(
                value,
                f"`{value}` is a private, shared or reserved address; Group-IB was not asked about it "
                "(instance setting 'Look up internal and reserved IP addresses').",
            )
        body = self._request(value, self._client.ip_graph)
        if body is None:
            return self._note(value, f"Group-IB has no WHOIS record for `{value}`.")
        record = IPWhois.parse(value, body, history_limit)
        rows = {
            "IP": record.ip,
            "Range": f"{record.range_start} - {record.range_end}" if record.range_start else None,
            "CIDR": record.cidr,
            "Registry": record.registry,
            "Network": record.netname,
            "Organization": record.organization,
            "Country": record.country,
            "ASN": record.asn,
            "AS Owner": record.as_owner,
            "Abuse Emails": ", ".join(record.abuse_emails) or None,
            "Abuse Phones": ", ".join(record.abuse_phones) or None,
            "Status": record.status,
            "Last Seen": record.last_seen,
        }
        return self._record(value, "GIBTI.IPWhois", "ip", record.to_context(), rows, record.history)

    @staticmethod
    def domain_body(graph: Callable[[str], Any], value: str) -> tuple[Any, str | None]:
        """The Graph WHOIS answer of a domain, or of its registered domain for a subdomain, and that registered domain."""
        try:
            # The Graph WHOIS knows an internationalized domain by its ASCII form.
            asked = value.encode("idna").decode("ascii")
        except UnicodeError:
            asked = value
        body = graph(asked)
        if isinstance(body, dict) and body.get("is_sld", body.get("isSld")) is False and not body.get("whois"):
            # A subdomain has no WHOIS record of its own; the domain registered under its zone has one.
            zone = str(body.get("zone") or "")
            labels = asked[: -len(zone) - 1].split(".") if zone and asked.endswith("." + zone) else []
            if labels:
                registered = f"{labels[-1]}.{zone}"
                return graph(registered), registered
        return body, None

    def _domain(self, value: str, history_limit: int) -> CommandResults:
        body, registered = self._request(value, partial(self.domain_body, self._client.domain_graph))
        note = f"`{value}` is a subdomain; this is the WHOIS record of `{registered}`.\n\n" if registered else ""
        if body is None:
            return self._note(value, f"Group-IB has no WHOIS record for `{value}`.")
        record = DomainWhois.parse(value, body, history_limit)
        context = record.to_context(personal_data=self._settings.whois_personal_data)
        rows = {
            "Domain": record.domain,
            "Registrar": record.registrar,
            "Registrar Abuse Email": record.registrar_abuse_email,
            "Registrar Abuse Phone": record.registrar_abuse_phone,
            "Registrant Organization": record.registrant_organization,
            "Registrant Country": record.registrant_country,
            "Creation Date": record.creation_date,
            "Expiration Date": record.expiration_date,
            "Updated Date": record.updated_date,
            "Name Servers": ", ".join(record.name_servers) or None,
            "Statuses": ", ".join(record.statuses) or None,
        }
        result = self._record(value, "GIBTI.DomainWhois", "domain", context, rows, record.history)
        result.readable_output = note + str(result.readable_output)
        return result

    def _request(self, value: str, call: Callable[[str], Any]) -> Any:
        try:
            return call(value)
        except ConnectionException as exc:
            refused = http_status(exc) in ("401", "403")
            hint = " Check the instance credentials." if refused else ""
            failure = CredentialsRefused if refused else DemistoException
            raise failure(
                f"The Group-IB WHOIS request for {value!r} failed: {ReputationCommand._failure_label(exc)}.{hint}"
            ) from None

    @staticmethod
    def _note(value: str, text: str) -> CommandResults:
        return CommandResults(readable_output=text, raw_response={"indicator": value})

    @staticmethod
    def _record(
        value: str, prefix: str, key: str, context: dict[str, Any], rows: dict[str, Any], history: tuple[dict[str, Any], ...]
    ) -> CommandResults:
        readable = tableToMarkdown(
            f"Group-IB WHOIS for {value}", {name: cell for name, cell in rows.items() if cell}, removeNull=True
        )
        if history:
            readable += tableToMarkdown("Earlier records", list(history), headerTransform=pascalToSpace, removeNull=True)
        return CommandResults(
            outputs_prefix=prefix, outputs_key_field=key, outputs=context, readable_output=readable, raw_response=context
        )


class ParallelCalls:
    """Named calls run on up to ``workers`` daemon threads, each with a client of its own, until a deadline, when one is set."""

    def __init__(self, client: Client, workers: int, timeout: float, local: threading.local) -> None:
        self._client = client
        self._workers = workers
        self._timeout = timeout
        self._local = local

    def run(self, calls: dict[str, Callable[[], Any]]) -> tuple[dict[str, tuple[bool, Any]], list[str]]:
        """(ok, result or exception) per finished call, and the names of the calls the deadline left unfinished."""
        pending: queue.Queue[str] = queue.Queue()
        for name in calls:
            pending.put(name)
        results: dict[str, tuple[bool, Any]] = {}
        lock = threading.Lock()
        finished = threading.Event()
        if not calls:
            finished.set()
        # A worker still running when the command returns finds the module globals cleared, so it reads Empty from here.
        empty = queue.Empty

        def work(client: Client) -> None:
            self._local.client = client
            while True:
                try:
                    name = pending.get_nowait()
                except empty:
                    return
                try:
                    outcome: tuple[bool, Any] = (True, calls[name]())
                except BaseException as exc:
                    # Recorded whatever it is, so the wait ends; run() raises what is not an Exception.
                    outcome = (False, exc)
                with lock:
                    results[name] = outcome
                    if len(results) == len(calls):
                        finished.set()

        workers = min(self._workers, len(calls))
        for index in range(workers):
            # The first thread reuses the client; a poller serves one thread at a time.
            client = self._client if index == 0 else self._client.fork()
            # A daemon thread never holds the process at exit; the result of a call the deadline leaves behind is ignored.
            threading.Thread(target=work, args=(client,), daemon=True).start()
        finished.wait(self._timeout if self._timeout > 0 else None)
        with lock:
            done = dict(results)
        for ok, outcome in done.values():
            if not ok and not isinstance(outcome, Exception):
                raise outcome
        return done, [name for name in calls if name not in done]


class ReputationCommand:
    """The ip, domain, file and url reputation commands: one result per value of the argument (a list)."""

    ENTITY_TYPES = {
        "ip": FeedIndicatorType.IP,
        "domain": FeedIndicatorType.Domain,
        "file": FeedIndicatorType.File,
        "url": FeedIndicatorType.URL,
    }
    DBOT_TYPES = {"ip": DBotScoreType.IP, "domain": DBotScoreType.DOMAIN, "file": DBotScoreType.FILE, "url": DBotScoreType.URL}
    # The collections a URL is read from (never through the global search), and whether the query quotes it; a record
    # counts only when it lists the URL itself (_lists_url).
    URL_SOURCES = ((TICollections.IOC_PRIMARY, True),)
    URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$")
    # A low-risk observable such as a public DNS resolver turns up in many malware and threat records: only a Suspicious
    # or Bad result carries their names.
    MIN_SCORE_FOR_CONTEXT = Common.DBotScore.SUSPICIOUS
    # The risk scores from which a value is Suspicious and Bad.
    SUSPICIOUS_FROM = 40
    BAD_FROM = 80
    SOURCE_HEADERS = {"collection": "Collection", "count": "Records", "firstSeen": "First seen", "lastSeen": "Last seen"}
    # One page per collection decides a verdict and gives the names and dates a result carries.
    SEARCH_PAGE_SIZE = 100

    def __init__(self, kind: str, client: Client, settings: Settings) -> None:
        self.kind = kind
        self._base_client = client
        self._local = threading.local()
        self._settings = settings
        self._indicators = IndicatorBuilder(create_relationships=settings.create_relationships)
        # The failed requests of the value being looked up, the number that answered, and those the deadline left behind.
        self._failures: list[tuple[str, Exception]] = []
        self._answers = 0
        self._unfinished: list[str] = []
        # The risk scores the batched scoring requests returned for the values of the command.
        self._scores: dict[str, Any] = {}

    @property
    def _client(self) -> Client:
        """The client of the thread a call runs on."""
        return getattr(self._local, "client", None) or self._base_client

    def _parallel(self, value: str, calls: dict[str, Callable[[], Any]]) -> dict[str, tuple[bool, Any]]:
        """Runs the calls of one value; failures are recorded, and the calls the deadline left behind go to _unfinished."""
        done, unfinished = ParallelCalls(
            self._base_client, self._settings.parallel_requests, float(self._settings.search_timeout), self._local
        ).run(calls)
        self._unfinished.extend(unfinished)
        if unfinished:
            # A call the deadline left behind may still run on the base client; later lookups take a client of their own.
            self._base_client = self._base_client.fork()
        for name, (ok, outcome) in done.items():
            if ok:
                self._answers += 1
            else:
                self._failed(name, value, outcome)
        return done

    def run(self, args: dict) -> CommandResults | list[CommandResults]:
        if self.kind not in self._settings.enabled_reputation_commands:
            return self._disabled()
        values = argument_values(args, [self.kind], self.kind, unique=True)
        self._scores = self._batch_scores(values)
        return [value_result(self._result, value) for value in values]

    def _batch_scores(self, values: list[str]) -> dict[str, Any]:
        """The batched risk scores of the list's IPs or domains; empty with fewer than two, or on a failure or timeout."""
        if self.kind not in ("ip", "domain"):
            return {}
        normalized = [self._normalized_input(self.kind, value) for value in values]
        scorable = list(dict.fromkeys(value for value in normalized if self._scorable(value)))
        if len(scorable) < 2:
            return {}
        # A client of its own: a request the deadline leaves behind shares none with the lookups.
        client = self._base_client.fork()
        done, _late = ParallelCalls(client, 1, float(self._settings.search_timeout), self._local).run(
            {"scoring": partial(client.risk_scores, self.kind, scorable)}
        )
        ok, outcome = done.get("scoring", (False, None))
        if not ok:
            reason = f"failed: {outcome}" if "scoring" in done else "was late"
            demisto.debug(f"[reputation] {self.kind} scoring of {len(scorable)} values together {reason}")
            return {}
        return outcome

    def _scorable(self, value: str) -> bool:
        """Whether the lookup of the value asks for its risk score: a domain, or an IPv4 address it looks up."""
        if self.kind == "domain":
            return bool(value)
        return not self._not_looked_up("ip", value) and not IndicatorBuilder.is_ipv6(value)

    def _whois(self, value: str) -> Any:
        """The Graph WHOIS answer of an IP, or of a domain as gibti-domain-whois asks for it."""
        if self.kind == "ip":
            return self._client.ip_graph(value)
        return WhoisCommand.domain_body(self._client.domain_graph, value)[0]

    def _risk_score(self, value: str) -> Any:
        """The risk score of the value from the command's batched requests, else from a request of its own."""
        if value in self._scores:
            return self._scores[value]
        return self._client.risk_score(self.kind, value)

    def _disabled(self) -> CommandResults:
        """One line without a DBotScore, so a disabled instance never taints the merged reputation."""
        return CommandResults(
            readable_output=(
                f"Group-IB Threat Intelligence: the '{self.kind}' reputation command is disabled on this instance "
                "(instance setting 'Enable reputation commands'); no enrichment was performed. "
                "To keep the instance from answering the generic reputation commands, select 'Do not use by default' "
                f'and call it explicitly with `!{self.kind} using="<instance name>"`.'
            ),
            raw_response={"command": self.kind, "enabled": False},
        )

    def _result(self, value: str) -> CommandResults:
        kind = self.kind
        self._failures, self._answers, self._unfinished = [], 0, []
        value = self._normalized_input(kind, value)
        skipped = self._not_looked_up(kind, value)
        if skipped:
            return CommandResults(readable_output=skipped, raw_response={"indicator": value, "score": Common.DBotScore.NONE})
        if kind == "file" and not IndicatorBuilder.file_hashes([value]):
            return CommandResults(
                readable_output=f"`{value}` is not an MD5, SHA-1, SHA-256 or SHA-512 hash; no lookup was made.",
                raw_response={"indicator": value, "score": Common.DBotScore.NONE},
            )
        if kind == "url" and not self.URL_RE.match(str(IndicatorBuilder.refang(value) or "")):
            return CommandResults(
                readable_output=f"`{value}` is not a URL (scheme://host); no lookup was made.",
                raw_response={"indicator": value, "score": Common.DBotScore.NONE},
            )
        floor_records: dict[str, list] = {}
        if kind == "url":
            data = self._url_data(value)
            self._raise_on_failures(value)
            collections = [path for path, records in data.items() if path != "scoring" and records]
        else:
            data, floor_records, mentions = self._lookup(kind, value)
            self._raise_on_failures(value)
            read = [path for path, records in data.items() if path not in ("scoring", "whois") and records]
            collections = list(dict.fromkeys(read + [path for path, records in floor_records.items() if records] + mentions))
        score = self._verdict(kind, data)
        reliability = self._reliability(kind, data)
        risk_score = (data.get("scoring") or {}).get("score")
        floor_hits, floor_tlp = self._floor_hits(kind, value, floor_records)
        floored = score < Common.DBotScore.SUSPICIOUS and bool(floor_hits)
        if floored:
            score = Common.DBotScore.SUSPICIOUS
        tags, malware_family, actors, tlp = self._context(kind, data, score, risk_score, floored)
        with_context = score >= self.MIN_SCORE_FOR_CONTEXT
        for path in floor_hits if with_context else []:
            if path not in tags:
                tags.append(path)
        if floor_hits and with_context:
            tlp = IndicatorBuilder.most_restrictive_tlp(tlp, floor_tlp)
        # HTTP 403 (no access) and HTTP 404 (no record) do not make the result partial; the verdict comes from the others.
        missing = [source for source in self._unfinished if self._decides(source)] + [
            source for source, exc in self._failures if self._decides(source) and http_status(exc) not in ("403", "404")
        ]
        partial = bool(missing)
        # A verdict stands only when no missing answer could have raised it.
        withheld = any(score < self._ceiling(source) for source in missing)
        entity_type = FeedIndicatorType.IPv6 if kind == "ip" and IndicatorBuilder.is_ipv6(value) else self.ENTITY_TYPES[kind]
        relationships = (
            self._indicators.relationships(value, entity_type, malware_family, actors) if with_context and not withheld else []
        )
        d_bot_score = Common.DBotScore(
            indicator=value,
            indicator_type=self.DBOT_TYPES[kind],
            integration_name=DBOT_VENDOR_NAME,
            score=score,
            malicious_description=self._malicious_description(score, collections, risk_score),
            reliability=reliability,
        )
        if not with_context and self._settings.collection_tags_always:
            # Below Suspicious the collections stay as tags, without the malware and actor names of their records; a floor
            # collection never does, since a listing that counts makes the result Suspicious.
            tags = [path for path in collections if path not in floor_records or path in floor_hits]
        first_seen, last_seen = self._seen(data, floor_records)
        enrichment = assign_params(
            tags=tags or None,
            malware_family=malware_family or None,
            traffic_light_protocol=tlp,
            first_seen_by_source=first_seen,
            last_seen_by_source=last_seen,
            publications=self._publications(self._context_records(kind, data, score, risk_score, floored)) or None,
        )
        table = score_table(
            title=f"Group-IB reputation for {value}",
            value=value,
            score=score,
            reliability=reliability,
            numerical_score=risk_score,
            extra={"Tags": tags, "Malware": malware_family, "TLP": tlp},
        )
        note = self._note(
            value,
            score,
            risk_score,
            collections,
            floor_hits if floored else [],
        )
        failed = [f"{source} ({self._failure_label(exc)})" for source, exc in self._failures] + [
            f"{source} (no answer within the lookup timeout of {float(self._settings.search_timeout):g} s)"
            for source in self._unfinished
        ]
        if failed and not withheld:
            note = (
                f"Some Group-IB requests for `{value}` failed: {', '.join(failed)}; the verdict comes from the others.\n\n" + note
            )
        if withheld:
            note = (
                f"The Group-IB lookup of `{value}` is incomplete: {', '.join(failed)}. "
                "No verdict is set, so the indicator keeps the one it has. Run the command again; when a request had no "
                "answer in time, raise the instance setting 'Lookup timeout (seconds)'.\n\n"
            )
        sources = self._sources(data, floor_records)
        if sources:
            table += "\n" + tableToMarkdown(
                "Group-IB records",
                sources,
                headers=["collection", "count", "firstSeen", "lastSeen"],
                headerTransform=self.SOURCE_HEADERS.get,
                removeNull=False,
            )
        return CommandResults(
            outputs_prefix="GIBTI.Reputation",
            outputs_key_field="indicator",
            outputs={
                "indicator": value,
                "type": kind,
                "score": None if withheld else score,
                "riskScore": risk_score,
                "collections": collections,
                "sources": sources,
                "partial": partial,
                "failedSources": [source for source, _exc in self._failures] + self._unfinished,
            },
            readable_output=note + table if not withheld else note,
            indicator=None if withheld else self._indicator(value, data, d_bot_score, enrichment),
            relationships=relationships or None,
            raw_response={
                "indicator": value,
                "score": score,
                "riskScore": risk_score,
                "reliability": str(reliability),
                "collections": collections,
                "tags": tags,
                "malwareFamily": malware_family,
                "threatActors": actors,
                "tlp": tlp,
            },
        )

    def _lookup(self, kind: str, value: str) -> tuple[dict[str, Any], dict[str, list], list[str]]:
        """Reads in parallel the collections, floor collections, risk score, WHOIS record and global search of the value."""
        reading = [path for path, spec in COLLECTIONS.items() if kind in spec.reputation_kinds]
        floors = [path for path in sorted(self._settings.floor_collections) if self._floors(kind, path)]
        calls: dict[str, Callable[[], Any]] = {}
        for path in reading:
            keys = CollectionSpec.of(path).domain_reputation_keys if kind == "domain" else None
            calls[f"reading {path}"] = partial(self._read, path=path, value=value, keys=keys)
        for path in floors:
            if path.startswith("suspicious_ip/"):
                calls[f"reading {path}"] = partial(self._listing, path, value)
            else:
                calls.setdefault(f"reading {path}", partial(self._read, path=path, value=value))
        if kind == "ip" and not IndicatorBuilder.is_ipv6(value):
            # scoring/ip scores IPv4 addresses only.
            calls["ip scoring"] = partial(self._risk_score, value)
        if kind == "domain":
            calls["domain scoring"] = partial(self._risk_score, value)
        if kind in ("ip", "domain") and self._settings.reputation_whois:
            calls[f"{kind} WHOIS"] = partial(self._whois, value)
        if self._settings.use_global_search:
            calls["collection search"] = lambda: self._client.global_search(value)
        done = self._parallel(value, calls)

        def answer(name: str) -> Any:
            ok, outcome = done.get(name, (False, None))
            return outcome if ok else None

        data: dict[str, Any] = {}
        for path in reading:
            # A read with no records can yield an empty record, which is dropped.
            records = [record for record in self._flatten(answer(f"reading {path}")) if record]
            if path == TICollections.IOC_COMMON:
                # A file record lists its hashes under hash; only the record of the hash asked about counts.
                wanted = value.lower()
                records = [record for record in records if wanted in {item.lower() for item in texts(record.get("hash"))}]
            elif path == TICollections.IOC_PRIMARY:
                # Only a record of the value itself decides: one that lists the hash of a file, or the IP or domain asked
                # about. A record that matches the query in another field, such as a URL on the domain, is dropped.
                if kind == "file":
                    wanted = value.lower()
                    records = [self._with_tlp(record) for record in records if wanted in self._hashes_of(record)]
                else:
                    wanted = self._normalized(value)
                    records = [self._with_tlp(record) for record in records if wanted in self._ioc_values(record)]
            elif CollectionSpec.of(path).victim_site:
                records = [record for record in self._flatten(records) if self._defaces(record, value)]
            data[path] = records
        if kind in ("ip", "domain"):
            data["scoring"] = {"score": answer(f"{kind} scoring")}
        if kind == "file":
            scores = [as_number(record.get("riskScore")) for record in data.get(TICollections.IOC_PRIMARY) or []]
            data["scoring"] = {"score": max((score for score in scores if score is not None), default=None)}
        whois = answer(f"{kind} WHOIS")
        if whois is not None:
            data["whois"] = IPWhois.parse(value, whois) if kind == "ip" else DomainWhois.parse(value, whois)
        floor_records = {path: [record for record in self._flatten(answer(f"reading {path}")) if record] for path in floors}
        search = answer("collection search")
        mentions = [
            str(hit.get("apiPath"))
            for hit in (search if isinstance(search, list) else [])
            if isinstance(hit, dict) and hit.get("apiPath") and hit.get("count")
        ]
        return data, floor_records, mentions

    @classmethod
    def _seen(cls, data: dict[str, Any], floor_records: dict[str, list]) -> tuple[str | None, str | None]:
        """The earliest first sighting and the latest last sighting of the records that list or mention the value."""
        groups = list(data.values()) + list(floor_records.values())
        return cls._sightings([record for items in groups for record in cls._flatten(items)])

    @classmethod
    def _sources(cls, data: dict[str, Any], floor_records: dict[str, list]) -> list[dict[str, Any]]:
        """Per collection with records: how many list or mention the value, and their earliest first and latest last sighting."""
        rows: list[dict[str, Any]] = []
        for path, items in list(data.items()) + list(floor_records.items()):
            records = cls._flatten(items)
            if records:
                first, last = cls._sightings(records)
                rows.append({"collection": path, "count": len(records), "firstSeen": first, "lastSeen": last})
        return rows

    @classmethod
    def _sightings(cls, records: list[dict]) -> tuple[str | None, str | None]:
        """The earliest dateFirstSeen and the latest dateLastSeen of the records, in UTC."""
        firsts = sorted(moment for record in records if (moment := cls._timestamp(known_date(record.get("dateFirstSeen")))))
        lasts = sorted(moment for record in records if (moment := cls._timestamp(known_date(record.get("dateLastSeen")))))
        # One format for every lookup, so a value read again is the same text.
        return (
            firsts[0].astimezone(UTC).strftime(DATE_FORMAT) if firsts else None,
            lasts[-1].astimezone(UTC).strftime(DATE_FORMAT) if lasts else None,
        )

    @staticmethod
    def _hashes_of(record: dict) -> set[str]:
        """The lower-case hashes of an ioc/primary file record."""
        hashes = record.get("hash")
        return {str(item).lower() for item in hashes.values() if item} if isinstance(hashes, dict) else set()

    @staticmethod
    def _floors(kind: str, path: str) -> bool:
        """Whether a floor collection applies to a value of this kind: a suspicious_ip/* collection to an IP only."""
        return kind == "ip" and path.startswith("suspicious_ip/")

    def _listing(self, path: str, value: str) -> list:
        """The record of an IP in a suspicious_ip/* collection, read by its id; none when the collection does not list it."""
        try:
            portion = self._client.record_by_id(path, value)
        except NotFoundException:
            return []
        except ConnectionException as exc:
            # The collection answers HTTP 400 "item with id ... not found" for an address it does not list.
            if http_status(exc) == "400" and "not found" in str(exc):
                return []
            raise
        record = getattr(portion, "raw_dict", None)
        return [record] if isinstance(record, dict) and record else []

    def _failed(self, source: str, value: str, exc: Exception) -> None:
        """Records a failed request of the lookup of ``value``."""
        demisto.debug(f"[reputation] {source} for {value!r} failed: {exc}")
        self._failures.append((source, exc))

    # The requests exception chained as the cause of a ciaops error, the most specific class first: a connect timeout or
    # a TLS failure is also a connection error.
    FAILURE_CAUSES: ClassVar[tuple[tuple[type[Exception], str], ...]] = (
        (requests.exceptions.Timeout, "timeout"),
        (requests.exceptions.SSLError, "TLS failure"),
        (requests.exceptions.JSONDecodeError, "not JSON"),
        (requests.exceptions.ConnectionError, "connection failure"),
    )
    FAILURE_MARKERS = (
        ("timed out", "timeout"),
        ("SSL", "TLS failure"),
        ("JSON decode error", "not JSON"),
        ("Connection refused", "connection failure"),
        ("NewConnectionError", "connection failure"),
    )

    @classmethod
    def _failure_label(cls, exc: Exception) -> str:
        """A failed request as the War Room note names it: its HTTP status, else the kind of failure."""
        text = str(exc)
        refused_page = next((refusal for refusal in (Client.NOT_A_PAGE, Client.NO_CURSOR) if refusal in text), None)
        if refused_page:
            return refused_page.removeprefix("HTTP 200 with ")
        status = http_status(exc)
        if status:
            return f"HTTP {status}"
        cause = next((kind for error, kind in cls.FAILURE_CAUSES if isinstance(exc.__cause__, error)), None)
        if cause:
            return cause
        # Without a chained error the kind is read from the text, its URLs left out: they carry the looked-up value.
        words = re.sub(r"\S*/\S*", "", text)
        return next((kind for marker, kind in cls.FAILURE_MARKERS if marker in words), type(exc).__name__)

    def _raise_on_failures(self, value: str) -> None:
        """Fails the lookup on a refused key, or when no request answered; a collection the key cannot read is skipped."""
        failures = [exc for _source, exc in self._failures]
        refused = next((exc for exc in failures if http_status(exc) == "401"), None)
        if refused is not None:
            raise CredentialsRefused(
                f"Group-IB refused the {self.kind} lookup of {value!r}: {self._failure_label(refused)}. "
                "Check the instance credentials."
            )
        if not self._answers and (failures or self._unfinished):
            reason = (
                self._failure_label(failures[0])
                if failures
                else f"no answer within the lookup timeout of {float(self._settings.search_timeout):g} s"
            )
            raise DemistoException(f"The Group-IB {self.kind} lookup of {value!r} failed: {reason}. Run the command again later.")

    def _read(self, path: str, value: str, keys: dict[str, str] | None = None) -> list:
        """The records of the first page of ``path`` searched with ``value``, parsed with ``keys`` or as raw envelopes."""
        pages = self._client.search_collection(path, query=value, limit=self.SEARCH_PAGE_SIZE)
        if pages is None:
            return []
        records: list[Any] = []
        for page in pages:
            if page is None:
                continue
            parsed = page.parse_portion(keys=keys) if keys else getattr(page, "raw_dict", None)
            if parsed in (None, "", []):
                continue
            if isinstance(parsed, list):
                records.extend(record for record in parsed if isinstance(record, dict))
            else:
                records.append(parsed)
            break
        return records

    def _url_data(self, value: str) -> dict[str, Any]:
        """The records of the URL sources that list the URL itself, and the highest ioc/primary risk score of the URL."""
        data: dict[str, Any] = {}
        scores: list[float] = []
        url = self._query_url(value)
        calls: dict[str, Callable[[], Any]] = {}
        for path, quoted in self.URL_SOURCES:
            query = '"' + url.replace('"', "") + '"' if quoted else url
            calls[f"reading {path}"] = partial(self._read, path=path, value=query)
        done = self._parallel(url, calls)
        for path, _quoted in self.URL_SOURCES:
            ok, records = done.get(f"reading {path}", (False, None))
            records = records if ok and records else []
            listed = [self._with_tlp(record) for record in self._flatten(records) if self._lists_url(path, record, value)]
            if path == TICollections.IOC_PRIMARY:
                scores.extend(self._url_scores(listed, value))
            data[path] = listed
        data["scoring"] = {"score": max(scores) if scores else None}
        return data

    @classmethod
    def _lists_url(cls, collection: str, record: dict, value: str) -> bool:
        """Whether an ioc/primary record lists the URL itself rather than a part of it."""
        return collection == TICollections.IOC_PRIMARY and any(
            cls._same_url(element.get("url"), value) for element in cls._url_elements(record)
        )

    @staticmethod
    def _url_elements(record: dict) -> list[dict]:
        entries = record.get("url")
        return [entry for entry in (entries if isinstance(entries, list) else []) if isinstance(entry, dict)]

    @classmethod
    def _url_scores(cls, records: list[dict], value: str) -> list[float]:
        """The risk scores of the ioc/primary url elements that are the URL."""
        return [
            score
            for record in records
            for element in cls._url_elements(record)
            if cls._same_url(element.get("url"), value) and (score := as_number(element.get("riskScore"))) is not None
        ]

    @staticmethod
    def _with_tlp(record: dict) -> dict:
        """The record with its TLP under ``evaluation.tlp``; ioc/primary writes ``evaluation.TLP``."""
        evaluation = record.get("evaluation")
        if isinstance(evaluation, dict) and "tlp" not in evaluation and "TLP" in evaluation:
            return {**record, "evaluation": {**evaluation, "tlp": evaluation["TLP"]}}
        return record

    @classmethod
    def _same_url(cls, candidate: Any, value: str) -> bool:
        return isinstance(candidate, str) and cls._normalized_url(candidate) == cls._normalized_url(value)

    @staticmethod
    def _query_url(value: str) -> str:
        """The URL as the API is asked for it: refanged and stripped, without a user name or password."""
        url = str(IndicatorBuilder.refang(value) or "").strip()
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            # A bracket in the host that is no IPv6 literal: the URL is sent as it is, without its user info.
            return re.sub(r"^([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@]*@", r"\1", url)
        if "@" not in parts.netloc:
            return url
        return urllib.parse.urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1]))

    @classmethod
    def _normalized_url(cls, value: str) -> str:
        """A URL as _query_url gives it, without a trailing slash, its scheme and host lowercase."""
        url = cls._query_url(value).rstrip("/")
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            return url.lower()
        return urllib.parse.urlunsplit(parts._replace(scheme=parts.scheme.lower(), netloc=parts.netloc.lower()))

    def _floor_hits(self, kind: str, value: str, floor_records: dict[str, list]) -> tuple[list[str], str | None]:
        """The suspicious_ip/* collections that list the IP itself within their window, and their most restrictive TLP."""
        if kind != "ip":
            return [], None
        now = datetime.now(UTC)
        hits: list[str] = []
        tlp: str | None = None
        for path, records in floor_records.items():
            listings = [
                record
                for record in self._flatten(records)
                if self._lists_observable(path, record, kind, value)
                and self._listed_recently(path, record, self._settings.floor_max_age_days, now)
            ]
            if listings:
                hits.append(path)
            for record in listings:
                tlp = IndicatorBuilder.most_restrictive_tlp(tlp, ParserHelper.find_element_by_key(record, "evaluation.tlp"))
        return hits, tlp

    @classmethod
    def _lists_observable(cls, collection: str, record: dict, kind: str, value: str) -> bool:
        """Whether a suspicious_ip/* record is the IP itself."""
        entries: list[Any] = []
        for key in ("ipv4", "ipv6"):
            entry = record.get(key)
            entries.extend(entry if isinstance(entry, list) else [entry])
        addresses = [record.get("id"), *(entry.get("ip") for entry in entries if isinstance(entry, dict))]
        return collection.startswith("suspicious_ip/") and any(cls._same(address, value) for address in addresses)

    @classmethod
    def _listed_recently(cls, collection: str, record: dict, max_age_days: int | None, now: datetime) -> bool:
        """Whether a suspicious_ip/* listing still keeps the IP at least Suspicious: at any age, or within the set window."""
        days = CollectionSpec.of(collection).floor_max_age_days if max_age_days is None else max_age_days
        if not days:
            return True
        last_seen = cls._timestamp(record.get("dateLastSeen"))
        return last_seen is not None and now - last_seen <= timedelta(days=days)

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        """An ISO 8601 timestamp as an aware datetime (UTC when it carries no offset), or None."""
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    @classmethod
    def _verdict(cls, kind: str, data: dict[str, Any]) -> int:
        """The verdict of a file, a URL, or an IP or domain, from the sources that decide it."""
        score = as_number((data.get("scoring") or {}).get("score"))
        if kind in ("file", "url"):
            # ioc/common lists a file Group-IB holds bad; ioc/primary is Bad from a risk score of 80.
            if kind == "file" and data.get(TICollections.IOC_COMMON):
                return Common.DBotScore.BAD
            if not data.get(TICollections.IOC_PRIMARY):
                return Common.DBotScore.NONE
            return Common.DBotScore.BAD if score is not None and score >= cls.BAD_FROM else Common.DBotScore.SUSPICIOUS
        if kind in ("ip", "domain"):
            if cls._scored(score) and score >= cls.BAD_FROM:
                return Common.DBotScore.BAD
            if (cls._scored(score) and score >= cls.SUSPICIOUS_FROM) or data.get(TICollections.IOC_PRIMARY):
                return Common.DBotScore.SUSPICIOUS
            # A risk score of 0 to 39 is Good; a suspicious_ip/* listing raises Good or Unknown to Suspicious (_floor_hits).
            return Common.DBotScore.GOOD if cls._scored(score) else Common.DBotScore.NONE
        return Common.DBotScore.NONE

    @staticmethod
    def _scored(score: float | None) -> TypeGuard[float]:
        """Whether Group-IB gave a risk score from 0 to 100."""
        return score is not None and 0 <= score <= 100

    def _reliability(self, kind: str, data: dict[str, Any]) -> str:
        """The instance's Source Reliability, or the most trusted matched collection's when the override is ignored."""
        if self._settings.reputation_reliability:
            return self._settings.reputation_reliability
        matched = [
            spec.reputation_reliability
            for name, spec in COLLECTIONS.items()
            if kind in spec.reputation_kinds and spec.reputation_reliability and data.get(name)
        ]
        if DBotScoreReliability.A in matched:
            return DBotScoreReliability.A
        if DBotScoreReliability.B in matched:
            return DBotScoreReliability.B
        return self._settings.source_reliability

    def _context(
        self, kind: str, data: dict[str, Any], score: int, risk_score: Any, floored: bool
    ) -> tuple[list[str], list[str], list[str], str | None]:
        """Tags, malware, actors and TLP of a Suspicious or Bad result that is not floored."""
        return self._collect(self._context_records(kind, data, score, risk_score, floored))

    def _context_records(self, kind: str, data: dict[str, Any], score: int, risk_score: Any, floored: bool) -> dict[str, Any]:
        """The context records of a Suspicious or Bad result: none when a floor raised it, ioc/primary's when it decided."""
        if floored or score < self.MIN_SCORE_FOR_CONTEXT:
            return {}
        number = as_number(risk_score)
        if kind in ("ip", "domain") and not (self._scored(number) and number >= self.SUSPICIOUS_FROM):
            return {TICollections.IOC_PRIMARY: data.get(TICollections.IOC_PRIMARY) or []}
        return data

    @classmethod
    def _publications(cls, data: dict[str, Any]) -> list[Common.Publications]:
        """The Group-IB threat reports and the public posts among the records, newest first."""
        found: list[tuple[str, str, str | None, str | None]] = []
        for record in cls._flatten(data.get(TICollections.APT_THREAT)):
            title = record.get("title")
            if isinstance(title, str) and title.strip():
                published = known_date(record.get("datePublished")) or known_date(record.get("createdAt"))
                found.append(("Group-IB Threat Intelligence", title.strip(), None, published))
        for record in cls._flatten(data.get(TICollections.HI_OPEN_THREATS)):
            link = record.get("link") if isinstance(record.get("link"), str) else None
            title = record.get("title") if isinstance(record.get("title"), str) else None
            if title or link:
                source = record.get("source") if isinstance(record.get("source"), str) else None
                found.append((source or "Open threat", title or str(link), link, known_date(record.get("createdAt"))))
        # ISO dates sort as text; an undated publication goes last.
        found.sort(key=lambda item: item[3] if isinstance(item[3], str) else "", reverse=True)
        return [Common.Publications(source=source, title=title, link=link, timestamp=when) for source, title, link, when in found]

    @classmethod
    def _collect(cls, data: dict[str, Any]) -> tuple[list[str], list[str], list[str], str | None]:
        """Tags, malware, actors and the most restrictive TLP of the matched records; a defacement adds its collection and TLP."""
        tags: list[str] = []
        malware: list[str] = []
        actors: list[str] = []
        tlp: str | None = None
        for collection, records in data.items():
            if collection in ("scoring", "whois") or not isinstance(records, list) or not records:
                continue
            if collection not in tags:
                tags.append(collection)
            spec = CollectionSpec.of(collection)
            if collection == TICollections.IOC_COMMON:
                # An ioc/common record carries no evaluation block; it counts as AMBER.
                tlp = IndicatorBuilder.most_restrictive_tlp(tlp, "AMBER")
            for record in cls._flatten(records):
                for key, path in (spec.reputation_context_keys or REPUTATION_CONTEXT_KEYS).items():
                    if key != "tlp" and spec.victim_site:
                        continue
                    raw = record[key] if key in record else ParserHelper.find_element_by_key(record, path)
                    if key == "tlp":
                        tlp = IndicatorBuilder.most_restrictive_tlp(tlp, raw)
                        continue
                    for name in texts(raw):
                        target = malware if key == "malware_names" else tags
                        if name not in target:
                            target.append(name)
                        if key == "threat_actor_name" and name not in actors:
                            actors.append(name)
        return tags, malware, actors, tlp

    def _normalized_input(self, kind: str, value: str) -> str:
        """The value as Group-IB is asked about it: trimmed, refanged unless a hash; a domain lowercased without a final dot."""
        if kind == "file":
            return str(value).strip()
        text = str(IndicatorBuilder.refang(value) or "").strip()
        if kind == "domain":
            text = text.lower().rstrip(".")
        return text

    def _not_looked_up(self, kind: str, value: str) -> str | None:
        """Why the value is answered without asking Group-IB, or None."""
        if kind != "ip":
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return f"`{value}` is not an IP address; no lookup was made."
        if not self._settings.lookup_internal_addresses and not address.is_global:
            return (
                f"`{value}` is a private, shared or reserved address; Group-IB was not asked about it "
                "(instance setting 'Look up internal and reserved IP addresses')."
            )
        return None

    @staticmethod
    def _ceiling(source: str) -> int:
        """The lowest verdict that stands while this source is missing: Bad for a risk score or ioc/common, else Suspicious."""
        if source.endswith(" scoring") or source == f"reading {TICollections.IOC_COMMON}":
            return Common.DBotScore.BAD
        return Common.DBotScore.SUSPICIOUS

    def _decides(self, source: str) -> bool:
        """Whether a missing answer of this source, failed or late, could have changed the verdict."""
        if source in ("ip scoring", "domain scoring"):
            return True
        floors = {path for path in self._settings.floor_collections if path.startswith("suspicious_ip/")}
        deciding = {TICollections.IOC_COMMON, *floors, *(path for path, _quoted in self.URL_SOURCES)}
        return source.removeprefix("reading ") in deciding

    @staticmethod
    def _malicious_description(score: int, collections: list[str], risk_score: Any) -> str | None:
        """The risk score and the collections of a Bad value, for the indicator's Malicious.Description."""
        if score != Common.DBotScore.BAD:
            return None
        reasons = [f"Group-IB risk score {risk_score}"] if risk_score is not None else []
        if collections:
            reasons.append(f"listed in Group-IB {', '.join(collections)}")
        text = "; ".join(reasons)
        return text[:1].upper() + text[1:] if text else None

    @staticmethod
    def _note(value: str, score: int, risk_score: Any, collections: list[str], floor_hits: list[str]) -> str:
        """The note above the table when the table does not say where the verdict comes from."""
        if not collections and risk_score is not None:
            return f"No Group-IB collection lists `{value}`; the verdict comes from the Group-IB risk score ({risk_score}).\n\n"
        if not collections:
            return f"No Group-IB Threat Intelligence data was found for `{value}`.\n\n"
        if floor_hits:
            score_text = f" ({risk_score})" if risk_score is not None else ""
            return (
                f"`{value}` is listed in {', '.join(floor_hits)}: the verdict is at least Suspicious, "
                f"whatever its Group-IB risk score{score_text}. The malware, threat and actor names of the "
                f"other records are not attached to it.\n\n"
            )
        if score >= ReputationCommand.MIN_SCORE_FOR_CONTEXT:
            return ""
        reason = (
            f"Group-IB rates `{value}` as low risk (risk score {risk_score})"
            if score == Common.DBotScore.GOOD
            else f"Group-IB has no risk score for `{value}` and no listing that sets its verdict"
        )
        return (
            f"{reason}: the records that mention it ({', '.join(collections)}) do not decide the verdict, "
            "and their malware, threat and actor names are not attached to it.\n\n"
        )

    def _indicator(
        self, value: str, data: dict[str, Any], d_bot_score: Common.DBotScore, enrichment: dict[str, Any]
    ) -> Common.Indicator | None:
        whois = data.get("whois")
        if self.kind == "ip":
            ip_whois = whois if isinstance(whois, IPWhois) else IPWhois(ip=value)
            # The registry's country is where the holder registered the range, not where the address is.
            return Common.IP(
                ip=value,
                ip_type=FeedIndicatorType.IPv6 if IndicatorBuilder.is_ipv6(value) else FeedIndicatorType.IP,
                dbot_score=d_bot_score,
                asn=ip_whois.asn,
                as_owner=ip_whois.as_owner,
                organization_name=ip_whois.organization,
                registrar_abuse_email=", ".join(ip_whois.abuse_emails) or None,
                registrar_abuse_phone=", ".join(ip_whois.abuse_phones) or None,
                **enrichment,
            )
        if self.kind == "domain":
            domain_whois = whois if isinstance(whois, DomainWhois) else DomainWhois(domain=value)
            personal = self._settings.whois_personal_data
            return DomainIndicator(
                domain=value,
                dbot_score=d_bot_score,
                organization=domain_whois.registrant_organization,
                creation_date=domain_whois.creation_date,
                updated_date=domain_whois.updated_date,
                expiration_date=domain_whois.expiration_date,
                domain_status=", ".join(domain_whois.statuses) or None,
                name_servers=list(domain_whois.name_servers) or None,
                registrar_name=domain_whois.registrar,
                registrar_abuse_email=domain_whois.registrar_abuse_email,
                registrar_abuse_phone=domain_whois.registrar_abuse_phone,
                registrant_name=domain_whois.registrant_name if personal else None,
                registrant_email=domain_whois.registrant_email if personal else None,
                registrant_country=domain_whois.registrant_country,
                **enrichment,
            )
        if self.kind == "file":
            return Common.File(dbot_score=d_bot_score, **self._file_hashes(value, data), **enrichment)
        if self.kind == "url":
            return Common.URL(url=value, dbot_score=d_bot_score, **enrichment)
        return None

    @classmethod
    def _file_hashes(cls, value: str, data: dict[str, Any]) -> dict[str, str]:
        """The hash asked about under its own kind, and the other hashes of the ioc/primary and ioc/common records of it."""
        hashes = IndicatorBuilder.file_hashes([value])
        for record in data.get(TICollections.IOC_PRIMARY) or []:
            for kind, item in IndicatorBuilder.file_hashes(sorted(cls._hashes_of(record))).items():
                hashes.setdefault(kind, item)
        for record in cls._flatten(data.get(TICollections.IOC_COMMON)):
            for kind, item in IndicatorBuilder.file_hashes(texts(record.get("hash"))).items():
                hashes.setdefault(kind, item)
        return hashes

    @staticmethod
    def _flatten(records: Any) -> list[dict]:
        """The records of a read; a raw page is the API envelope {"count", "items": [...]}."""
        flat: list[dict] = []
        for record in records if isinstance(records, list) else []:
            if isinstance(record, dict) and isinstance(record.get("items"), list):
                flat.extend(item for item in record["items"] if isinstance(item, dict))
            elif isinstance(record, dict):
                flat.append(record)
        return flat

    @classmethod
    def _ioc_values(cls, record: dict) -> set[str]:
        """The normalized ip and domain values of an ioc/primary record."""
        values: set[str] = set()

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for key in ("ip", "domain"):
                    walk(value.get(key))
            elif isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, str) and value.strip():
                values.add(cls._normalized(value))

        for key in ("ip", "domain"):
            walk(record.get(key))
        return values

    @classmethod
    def _defaces(cls, record: dict, value: str) -> bool:
        """Whether an attacks/deface record defaced the IP or domain itself rather than a page that mentions it."""
        target_ip = record.get("targetIp")
        if isinstance(target_ip, dict):
            target_ip = target_ip.get("ip")
        return any(
            cls._same(candidate, value) for candidate in (record.get("targetDomain"), cls._host_of(record.get("url")), target_ip)
        )

    @staticmethod
    def _host_of(value: Any) -> str | None:
        """The host of a defaced page's URL: a URL's host, or the value without a port; a bare IP address is its own host."""
        text = IndicatorBuilder.refang(value) if isinstance(value, str) else None
        if not text or not text.strip():
            return None
        text = text.strip()
        try:
            ipaddress.ip_address(text)
            return text
        except ValueError:
            pass
        try:
            return urllib.parse.urlsplit(text if "://" in text else f"//{text}").hostname
        except ValueError:
            return None

    @staticmethod
    def _normalized(value: str) -> str:
        """An IP in its canonical notation, or a domain stripped, lowercase and without a trailing dot."""
        text = value.strip().rstrip(".").lower()
        try:
            return ipaddress.ip_address(text).compressed
        except ValueError:
            return text

    @classmethod
    def _same(cls, value: Any, indicator_value: str) -> bool:
        """Whether a record's value is the looked-up IP or domain, whatever its case, trailing dot or IPv6 notation."""
        if not isinstance(value, str):
            return False
        candidate = cls._normalized(value)
        wanted = cls._normalized(indicator_value)
        if candidate == wanted:
            return True
        try:
            return ipaddress.ip_address(candidate) == ipaddress.ip_address(wanted)
        except ValueError:
            return False


class ScoringCommand:
    """gibti-ip-scoring and gibti-domain-scoring: the risk score of each scorable value; gibti-cve-scoring: a CVE's DBotScore."""

    # The keys a CVE's osi/vulnerability record is read with.
    CVE_KEYS = {
        "id": "id",
        "title": "title",
        "description": "description",
        "cvss_score": "cvss.score",
        "cvss_vector": "cvss.vector",
        "merged_cvss": "mergedCvss",
        "merged_cvss_vector": "mergedCvssVector",
        "epss": "epss.epss",
        "epss_percentile": "epss.percentile",
        "has_exploit": "hasExploit",
        "exploit_count": "exploitCount",
        "seen_in_the_wild": "seenInTheWild",
        "severity": "evaluation.severity",
        "tlp": "evaluation.tlp",
        "date_published": "datePublished",
        "date_modified": "dateModified",
    }

    def __init__(self, kind: str, client: Client, settings: Settings) -> None:
        # "ip", "domain" or "cve".
        self.kind = kind
        self._client = client
        self._reliability = settings.source_reliability
        self._lookup_internal_addresses = settings.lookup_internal_addresses
        # The risk scores the batched scoring requests returned for the values of the command.
        self._scores: dict[str, Any] = {}

    def run(self, args: dict) -> list[CommandResults]:
        if self.kind == "cve":
            return [self._cve(cve_id) for cve_id in argument_values(args, ["cve"], "cve")]
        values = argument_values(args, [self.kind], self.kind)
        scorable = list(dict.fromkeys(value for value in values if not self._skipped(value)))
        if len(scorable) > 1:
            try:
                self._scores = self._client.risk_scores(self.kind, scorable)
            except Exception as exc:
                # Each value then asks for its own score, and a failure names the value.
                demisto.debug(f"[scoring] {self.kind} scoring of {len(scorable)} values together failed: {exc}")
        return [value_result(self._risk, value) for value in values]

    def _skipped(self, value: str) -> str | None:
        """Why the value gets a note instead of a request, or None."""
        reason = self._unscorable(self.kind, value)
        if reason or self.kind != "ip" or self._lookup_internal_addresses or ipaddress.ip_address(value).is_global:
            return reason
        return (
            f"`{value}` is a private, shared or reserved address; Group-IB was not asked about it "
            "(instance setting 'Look up internal and reserved IP addresses')."
        )

    def _risk(self, value: str) -> CommandResults:
        """Group-IB's risk score of an IP or domain and the verdict it maps to; only the reputation commands set an indicator."""
        reason = self._skipped(value)
        if reason:
            return CommandResults(
                readable_output=reason,
                raw_response={"indicator": value, "score": Common.DBotScore.NONE, "riskScore": None},
            )
        try:
            risk_score = self._scores[value] if value in self._scores else self._client.risk_score(self.kind, value)
        except ConnectionException as exc:
            refused = http_status(exc) in ("401", "403")
            hint = " Check the instance credentials." if refused else ""
            failure = CredentialsRefused if refused else DemistoException
            raise failure(
                f"The Group-IB scoring request for {value!r} failed: {ReputationCommand._failure_label(exc)}.{hint}"
            ) from None
        verdict = IndicatorBuilder.risk_score_verdict(risk_score)
        readable_output = score_table(
            title=f"Group-IB scoring for {value}",
            value=value,
            score=verdict,
            reliability=self._reliability,
            numerical_score=risk_score,
        )
        if risk_score is None:
            readable_output = f"Group-IB has no risk score for `{value}`.\n\n" + readable_output
        return CommandResults(
            outputs_prefix="GIBTI.Scoring",
            outputs_key_field="indicator",
            outputs={"indicator": value, "type": self.kind, "riskScore": risk_score, "score": verdict},
            readable_output=readable_output,
            raw_response={"indicator": value, "score": verdict, "riskScore": risk_score},
        )

    @staticmethod
    def _unscorable(kind: str, value: str) -> str | None:
        """Why the scoring route of ``kind`` cannot score the value, or None: scoring/ip takes IPv4 only, scoring/domain no IP."""
        try:
            address: Any = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if kind == "ip" and not isinstance(address, ipaddress.IPv4Address):
            return f"`{value}` is not an IPv4 address: Group-IB scores IPv4 addresses only. No request was made."
        if kind == "domain" and address is not None:
            return (
                f"`{value}` is an IP address, which scoring/domain does not score: score an IPv4 address with gibti-ip-scoring."
                " No request was made."
            )
        return None

    def _cve(self, cve_id: str) -> CommandResults:
        """A CVE scored from its osi/vulnerability record: CVSS, EPSS, exploit evidence and Group-IB's severity."""
        record = self._cve_record(cve_id) or {}
        published, modified = known_date(record.get("date_published")), known_date(record.get("date_modified"))
        score = self._cve_verdict(record) if record else Common.DBotScore.NONE
        cvss_score, cvss_vector = IndicatorBuilder.cvss(
            record.get("merged_cvss"), record.get("merged_cvss_vector"), record.get("cvss_score"), record.get("cvss_vector")
        )
        tlp = IndicatorBuilder.tlp(record.get("tlp"))
        indicator = Common.CVE(
            id=cve_id,
            cvss=cvss_score,
            published=published,
            modified=modified,
            description=record.get("description"),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            tags=[TICollections.OSI_VULNERABILITY] if record else None,
            traffic_light_protocol=tlp,
            dbot_score=Common.DBotScore(
                indicator=cve_id,
                indicator_type=DBotScoreType.CVE,
                integration_name=DBOT_VENDOR_NAME,
                score=score,
                reliability=self._reliability,
            ),
        )
        outputs = {
            "id": cve_id,
            "found": bool(record),
            "title": record.get("title"),
            "cvssScore": cvss_score,
            "cvssVector": cvss_vector,
            "mergedCvss": as_number(record.get("merged_cvss")),
            "epss": as_number(record.get("epss")),
            "epssPercentile": as_number(record.get("epss_percentile")),
            "hasExploit": bool(record.get("has_exploit")) if record else None,
            "exploitCount": as_number(record.get("exploit_count")),
            "seenInTheWild": bool(record.get("seen_in_the_wild")) if record else None,
            "severity": record.get("severity"),
            "tlp": tlp,
            "datePublished": published,
            "dateModified": modified,
            "score": score,
        }
        readable_output = score_table(
            title=f"Group-IB CVE scoring for {cve_id}",
            value=cve_id,
            score=score,
            reliability=self._reliability,
            numerical_score=cvss_score,
            extra={
                "CVSS vector": cvss_vector,
                "EPSS": outputs["epss"],
                "EPSS percentile": outputs["epssPercentile"],
                "Exploit available": outputs["hasExploit"],
                "Seen in the wild": outputs["seenInTheWild"],
                "Group-IB severity": record.get("severity"),
                "TLP": tlp,
            },
        )
        if not record:
            readable_output = (
                f"No Group-IB Threat Intelligence data was found for `{cve_id}` in {TICollections.OSI_VULNERABILITY}.\n\n"
                + readable_output
            )
        return CommandResults(
            outputs_prefix="GIBTI.CVEScoring",
            outputs_key_field="id",
            outputs=outputs,
            readable_output=readable_output,
            indicator=indicator,
            raw_response=record or {"id": cve_id},
        )

    def _cve_record(self, cve_id: str) -> dict[str, Any] | None:
        """The osi/vulnerability record of a CVE id, None when Group-IB has none; a failed request is an error."""
        try:
            portion = self._client.record_by_id(TICollections.OSI_VULNERABILITY, cve_id)
            if portion is None:
                return None
            parsed = portion.parse_portion(keys=self.CVE_KEYS)
        except NotFoundException:
            return None
        except ConnectionException as exc:
            hint = "Check the instance credentials." if http_status(exc) in ("401", "403") else "Run the command again later."
            raise DemistoException(
                f"The Group-IB scoring request for {cve_id!r} failed: {ReputationCommand._failure_label(exc)}. {hint}"
            ) from None
        except Exception as exc:
            demisto.debug(f"[cve-scoring] lookup failed for {cve_id!r}: {exc}")
            return None
        record = parsed[0] if isinstance(parsed, list) and parsed else parsed
        if not isinstance(record, dict) or not record.get("id"):
            return None
        return record

    @staticmethod
    def _cve_verdict(fields: dict) -> int:
        """Bad for exploit evidence, EPSS >= 0.5 or percentile >= 0.95, CVSS >= 9.0 or red severity, else Suspicious."""
        exploit_count = as_number(fields.get("exploit_count")) or 0
        has_exploit = bool(fields.get("has_exploit")) or bool(fields.get("seen_in_the_wild")) or exploit_count > 0
        epss = as_number(fields.get("epss"))
        percentile = as_number(fields.get("epss_percentile"))
        scores = (as_number(fields.get(key)) for key in ("merged_cvss", "cvss_score"))
        cvss = next((score for score in scores if score is not None and score > 0), None)
        severity = first_value(fields.get("severity"))
        if (
            has_exploit
            or (epss is not None and epss >= 0.5)
            or (percentile is not None and percentile >= 0.95)
            or (cvss is not None and cvss >= 9.0)
            or severity == "red"
        ):
            return Common.DBotScore.BAD
        return Common.DBotScore.SUSPICIOUS


class SearchCommand:
    """gibti-global-search and gibti-local-search."""

    EMPTY_SEARCH_NOTE = (
        "\nThis command reads the collection's feed for your account. gibti-global-search counts a wider index and can "
        "report records this command does not return; gibti-get-threat-actor-info and gibti-get-threat-info read a profile "
        "or a report by its id."
    )

    def __init__(self, scope: str, client: Client, settings: Settings) -> None:
        # "global" or "local".
        self.scope = scope
        self._client = client
        self._masking = settings.masking

    def run(self, args: dict) -> CommandResults:
        return self._global(args) if self.scope == "global" else self._local(args)

    def _global(self, args: dict) -> CommandResults:
        """The collections with records that mention the query, the ones this pack has no lookup command for included."""
        query = str(args.get("query"))
        # Null or an empty list when Group-IB has no data on the query; both mean "no results".
        raw_response = self._client.global_search(query)
        found: list[dict[str, Any]] = [
            {
                "apiPath": result.get("apiPath"),
                "label": result.get("label"),
                "count": result.get("count"),
                "GIBLink": result.get("link"),
                "query": f"{result.get('apiPath')}?q={query}",
                "supportedByPack": bool(CollectionSpec.of(result["apiPath"]).mapping),
            }
            for result in raw_response or []
            if isinstance(result, dict) and result.get("apiPath")
        ]
        if not found:
            return CommandResults(
                outputs_prefix="GIBTI.search.global",
                raw_response=raw_response,
                ignore_auto_extract=True,
                outputs=[],
                readable_output="No results found for your query.",
            )
        return CommandResults(
            outputs_prefix="GIBTI.search.global",
            outputs_key_field="query",
            outputs=found,
            readable_output=tableToMarkdown(
                "Search results",
                t=found,
                headers=["apiPath", "label", "count", "supportedByPack", "GIBLink"],
                url_keys=["GIBLink"],
            ),
            raw_response=raw_response,
            ignore_auto_extract=True,
        )

    def _local(self, args: dict) -> CommandResults:
        """The records of one collection's update feed that match the query, up to ``requests_limit`` pages."""
        query = args.get("query")
        collection_name = str(args.get("collection_name"))
        include_raw_feed = argToBoolean(args.get("include_raw_feed", False))
        CollectionSpec.validate(collection_name)
        mapping = CollectionSpec.of(collection_name).mapping
        if not mapping:
            # The API grants more collections than the pack reads; a record of an unmapped one cannot be parsed.
            raise DemistoException(
                f"The {collection_name} collection is not supported by gibti-local-search: "
                "the collection_name argument lists the supported collections."
            )
        requests_limit = self._optional_int(args.get("requests_limit"), "requests_limit") or 1
        if CollectionSpec.of(collection_name).cursor_from_items:
            # The feed answers the lowest cursor of a page, so a second page would repeat the first; seq_update set to
            # the highest seqUpdate of the rows reads on.
            requests_limit = 1
        page_size_limit = self._optional_int(args.get("page_size_limit"), "page_size_limit")
        date_from = self._date(args["date_from"], "date_from") if args.get("date_from") else None
        date_to = self._date(args["date_to"], "date_to") if args.get("date_to") else None
        if date_to and not date_from:
            raise DemistoException("date_to needs date_from: the end of a date window is sent only with its start.")
        sequpdate = self._optional_int(args.get("seq_update"), "seq_update")
        if sequpdate is not None:
            date_from = date_to = None
        demisto.debug(
            f"[local_search] collection={collection_name}, query={query!r}, date_from={date_from}, date_to={date_to}, "
            f"seq_update={sequpdate!r}, requests_limit={requests_limit}, page_size_limit={page_size_limit}"
        )
        pages = self._client.search_collection(
            collection_name, query=query, limit=page_size_limit, date_from=date_from, date_to=date_to, sequpdate=sequpdate
        )

        # The API answers HTTP 400 to a date window beyond what the license serves, and forums HTTP 500 to a query it
        # cannot parse.
        def refusal(exc: Exception) -> str:
            status = http_status(exc)
            in_window = status == "400" and (date_from or date_to)
            hint = " On a trial or POC account, some collections serve only the last 30 days." if in_window else ""
            if status == "500" and query and CollectionSpec.of(collection_name).cursor_from_items:
                hint += " The collection answers HTTP 500 to a query it cannot parse; check the query argument."
            return (
                f"The search in {collection_name} failed (query {query!r}, date_from={date_from}, "
                f"date_to={date_to}): {exc}.{hint}"
            )

        results: list[dict[str, Any]] = []
        requests_count = 0
        # Lazily: without a cursor the update feed walks the whole collection, page after page.
        for page in Client.refusals_as_messages(pages, refusal):
            if page is None:
                continue
            raw_items = (getattr(page, "raw_dict", None) or {}).get("items") or []
            for index, record in enumerate(page.parse_portion(keys=mapping, as_json=False) or []):
                if isinstance(record, dict):
                    raw_item = raw_items[index] if index < len(raw_items) and isinstance(raw_items[index], dict) else {}
                    results.append(self._entry(collection_name, record, raw_item, include_raw_feed))
            requests_count += 1
            if requests_count >= requests_limit:
                break
        return CommandResults(
            outputs_prefix="GIBTI.search.local",
            outputs_key_field="id",
            outputs=results,
            readable_output=(
                tableToMarkdown("Search results", t=results, headers=["id", "additional_info", "seqUpdate", "raw_feed"])
                + (self.EMPTY_SEARCH_NOTE if query and not results else "")
            ),
            ignore_auto_extract=True,
        )

    def _entry(self, collection_name: str, record: dict, raw_item: dict, include_raw_feed: bool) -> dict[str, Any]:
        record = IncidentBuilder.shape(collection_name, self._masking.apply(collection_name, record))
        record = IncidentBuilder.portal_link(collection_name, record)
        name = record.get("name")
        entry: dict[str, Any] = {
            "id": record.get("id"),
            "additional_info": f"Name: {name}" if name else None,
            "seqUpdate": raw_item.get("seqUpdate"),
        }
        if include_raw_feed:
            entry["raw_feed"] = json_text(record)
        return entry

    @staticmethod
    def _optional_int(value: Any, arg_name: str) -> int | None:
        """A whole-number argument; None when it is missing or blank."""
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
                raise DemistoException(f"Invalid '{arg_name}' value: expected a whole number, got {value!r}.") from e
        raise DemistoException(f"Invalid '{arg_name}' value: expected a whole number, got {value!r}.")

    @staticmethod
    def _date(value: str, arg_name: str) -> str:
        """A date argument as the update feed's df/dt take it."""
        parsed = dateparser_parse(value)
        if parsed is None:
            raise DemistoException(
                f"Invalid '{arg_name}' value {value!r}: use a date such as 2020-01-01, January 1 2020 or 30 days."
            )
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(UTC)
        return parsed.strftime(DATE_FORMAT)


class AvailableCollectionsCommand:
    """gibti-get-available-collections: the granted collections that ciaops knows, sorted."""

    def __init__(self, client: Client) -> None:
        self._client = client

    def run(self, args: dict | None = None) -> CommandResults:
        collections = sorted(self._client.available_collections())
        return CommandResults(
            outputs_prefix="GIBTI.OtherInfo",
            outputs_key_field="collections",
            outputs={"collections": collections},
            readable_output=tableToMarkdown(name="Available collections", t={"collections": collections}, headers="collections"),
            ignore_auto_extract=True,
            raw_response=collections,
        )


class PreProcessRuleScripts:
    """Fills in the script id the pack's pre-processing rules ship without; a rule without it never runs."""

    RULE_SCRIPTS = {"GIB Rule All Types": "GIBTIIncidentUpdateAllTypes", "GIB Rule": "GIBTIIncidentUpdate"}

    def __init__(self, request: Callable[..., Any] | None = None) -> None:
        self._request = request or demisto.internalHttpRequest

    def fill(self) -> list[str]:
        """The names of the rules whose script id was filled in."""
        rules = self._call("GET", "/preprocess/rules")
        filled = []
        for rule in rules if isinstance(rules, list) else []:
            script = self.RULE_SCRIPTS.get(str(rule.get("name")))
            if not script or rule.get("action") != "script" or rule.get("scriptName") != script or rule.get("scriptID"):
                continue
            script_id = self._script_id(script)
            if not script_id:
                demisto.error(f"[pre-processing rules] {rule.get('name')!r} has no script and {script} is not installed.")
                continue
            # POST /preprocess/rule saves the whole rule; only its script id changes.
            if self._call("POST", "/preprocess/rule", {**rule, "scriptID": script_id}) is not None:
                filled.append(str(rule.get("name")))
            else:
                # The test still passes: the administrator finds the step in the README and this log line.
                demisto.error(
                    f"[pre-processing rules] {rule.get('name')!r} has no script and saving {script} in it was "
                    f"refused: select {script} in the rule, or the rule does not run."
                )
        return filled

    def _script_id(self, script: str) -> str | None:
        found = self._call("POST", "/automation/search", {"page": 0, "size": 1, "query": f'id:"{script}"'})
        scripts = found.get("scripts") if isinstance(found, dict) else None
        return next((item.get("id") for item in scripts or [] if isinstance(item, dict) and item.get("id")), None)

    def _call(self, method: str, uri: str, body: dict | None = None) -> Any:
        """The parsed answer of a 2xx response; None, with the status in the debug log, otherwise."""
        response = self._request(method, uri, json.dumps(body) if body is not None else None) or {}
        status = response.get("statusCode")
        demisto.debug(f"[pre-processing rules] {method} {uri} -> {status}")
        if not isinstance(status, int) or not 200 <= status < 300:
            return None
        text = response.get("body") or ""
        try:
            return json.loads(text) if text else {}
        except ValueError:
            return {}


class TestModuleCommand:
    """The instance test: one uncached grants request, then the script ids of the pack's pre-processing rules."""

    def __init__(self, client: Client) -> None:
        self._client = client

    def run(self) -> str:
        # The credentials or the URL may have just changed: the cache would hide a 401.
        self._client.granted_collections(refresh=True)
        if not self._client.available_collections():
            return "No collections are available; ask Group-IB support to grant them."
        try:
            filled = PreProcessRuleScripts().fill()
            if filled:
                demisto.info(f"[pre-processing rules] script id filled in: {', '.join(filled)}")
        except Exception as exc:
            # The rules are a convenience of the pack; the instance works without them.
            demisto.error(f"[pre-processing rules] not checked: {exc}")
        return "ok"


# The gibti-get-*-info command of each collection, by name: xsoar-lint finds a command only as a dict key or in an if.
LOOKUP_COMMANDS = {
    "gibti-get-compromised-account-info": TICollections.COMPROMISED_ACCOUNT_GROUP,
    "gibti-get-compromised-card-group-info": TICollections.COMPROMISED_BANK_CARD_GROUP,
    "gibti-get-compromised-masked-card-info": TICollections.COMPROMISED_MASKED_CARD,
    "gibti-get-compromised-breached-info": TICollections.COMPROMISED_BREACHEDDB,
    "gibti-get-compromised-spd-info": TICollections.COMPROMISED_SPD,
    "gibti-get-osi-git-leak-info": TICollections.OSI_GIT_REPOSITORY,
    "gibti-get-osi-public-leak-info": TICollections.OSI_PUBLIC_LEAK,
    "gibti-get-osi-vulnerability-info": TICollections.OSI_VULNERABILITY,
    "gibti-get-attacks-ddos-info": TICollections.ATTACKS_DDOS,
    "gibti-get-attacks-deface-info": TICollections.ATTACKS_DEFACE,
    "gibti-get-phishing-group-info": TICollections.ATTACKS_PHISHING_GROUP,
    "gibti-get-phishing-kit-info": TICollections.ATTACKS_PHISHING_KIT,
    "gibti-get-suspicious-ip-tor-node-info": TICollections.SUSPICIOUS_IP_TOR_NODE,
    "gibti-get-suspicious-ip-open-proxy-info": TICollections.SUSPICIOUS_IP_OPEN_PROXY,
    "gibti-get-suspicious-ip-socks-proxy-info": TICollections.SUSPICIOUS_IP_SOCKS_PROXY,
    "gibti-get-suspicious-ip-vpn-info": TICollections.SUSPICIOUS_IP_VPN,
    "gibti-get-suspicious-ip-scanner-info": TICollections.SUSPICIOUS_IP_SCANNER,
    "gibti-get-malware-cnc-info": TICollections.MALWARE_CNC,
    "gibti-get-malware-malware-info": TICollections.MALWARE_MALWARE,
    "gibti-get-compromised-access-info": TICollections.COMPROMISED_ACCESS,
    "gibti-get-darkweb-telegram-info": TICollections.COMPROMISED_MESSENGER,
    "gibti-get-darkweb-discord-info": TICollections.COMPROMISED_DISCORD,
    "gibti-get-darkweb-forum-info": TICollections.DARKWEB_FORUMS,
    "gibti-get-open-threat-info": TICollections.HI_OPEN_THREATS,
}
# Commands of a retired collection, declared in the YAML as deprecated: the error names the replacement.
REMOVED_COMMANDS = {
    "gibtia-get-compromised-mule-info": "gibti-get-compromised-spd-info",
    "gibti-get-compromised-mule-info": "gibti-get-compromised-spd-info",
}
# The legacy gibtia-* names: each runs its gibti-* command and warns in the War Room.
LEGACY_ALIASES = {
    "gibtia-get-compromised-account-info": "gibti-get-compromised-account-info",
    "gibtia-get-compromised-card-group-info": "gibti-get-compromised-card-group-info",
    "gibtia-get-compromised-spd-info": "gibti-get-compromised-spd-info",
    "gibtia-get-compromised-breached-info": "gibti-get-compromised-breached-info",
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


def main() -> None:
    """Parses the instance settings, builds the client and runs the command."""
    # The reputation commands write their logs from several threads.
    support_multithreading()
    # Besides the error, a failed command names the incident collections of a fetch or an instance test and the
    # collection of a one-collection lookup.
    incident_collections = None
    endpoint = None
    try:
        params, raw_command, args = demisto.params(), demisto.command(), demisto.args()
        if raw_command in ("test-module", "fetch-incidents"):
            incident_collections = params.get("incident_collections") or []
        settings = Settings.from_params(params)
        demisto.debug(f"Command being called is {raw_command}")
        client = Client(
            base_url=settings.base_url,
            verify=settings.verify,
            auth=(settings.username, settings.password),
            proxy=settings.proxy,
            headers={"Accept": "*/*"},
            limit=settings.limit,
            rate_limit_delay=settings.rate_limit_delay,
        )
        if raw_command in REMOVED_COMMANDS:
            raise DemistoException(f"Command {raw_command} is no longer available. Use {REMOVED_COMMANDS[raw_command]} instead.")
        command = LEGACY_ALIASES.get(raw_command, raw_command)
        if command != raw_command:
            return_warning(
                f"Command '{raw_command}' is deprecated. Use '{command}' in your playbooks and scripts instead.", exit=False
            )

        def lookup(target: str) -> Callable[[dict], list[CommandResults]]:
            return lambda args: LookupCommand(target, client, settings).run(args)

        commands: dict[str, Callable[[dict], Any]] = {
            "test-module": lambda args: TestModuleCommand(client).run(),
            "fetch-incidents": lambda args: FetchIncidentsCommand(client, settings).run(demisto.getLastRun()),
            "gibti-get-available-collections": lambda args: AvailableCollectionsCommand(client).run(args),
            "gibti-global-search": lambda args: SearchCommand("global", client, settings).run(args),
            "gibti-local-search": lambda args: SearchCommand("local", client, settings).run(args),
            "gibti-ip-scoring": lambda args: ScoringCommand("ip", client, settings).run(args),
            "gibti-domain-scoring": lambda args: ScoringCommand("domain", client, settings).run(args),
            "gibti-ip-whois": lambda args: WhoisCommand("ip", client, settings).run(args),
            "gibti-domain-whois": lambda args: WhoisCommand("domain", client, settings).run(args),
            "gibti-cve-scoring": lambda args: ScoringCommand("cve", client, settings).run(args),
            # isAPT sets whether apt/* or hi/* is read first; an id missing there is read from the other one.
            "gibti-get-threat-info": lookup("threat"),
            "gibti-get-threat-actor-info": lookup("threat_actor"),
            **{lookup_command: lookup(collection_name) for lookup_command, collection_name in LOOKUP_COMMANDS.items()},
            "ip": lambda args: ReputationCommand("ip", client, settings).run(args),
            "domain": lambda args: ReputationCommand("domain", client, settings).run(args),
            "file": lambda args: ReputationCommand("file", client, settings).run(args),
            "url": lambda args: ReputationCommand("url", client, settings).run(args),
        }
        handler = commands.get(command)
        if handler is None:
            raise NotImplementedError(f"Command {command} is not implemented")
        endpoint = LOOKUP_COMMANDS.get(command)
        result = handler(args)
        if command == "fetch-incidents":
            next_run, incidents = result
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == "test-module":
            demisto.results(result)
        else:
            return_results(result)
    except Exception as exc:
        # An expected failure (unknown id, a failed Group-IB request, a retired command, a setting or an argument the
        # integration or ciaops rejects): the message is the error, a traceback would only bury it. Anything else keeps
        # its traceback.
        expected = isinstance(exc, DemistoException | ConnectionException | InputException)
        return_error(
            f"Failed to execute {demisto.command()} command.\n"
            f"Incident collections: {incident_collections}.\n"
            f"Command endpoint: {endpoint}.\nError: {exc if expected else format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
