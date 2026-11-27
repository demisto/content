"""Enrich the indicators of a Group-IB incident."""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import ipaddress
from typing import Any


OUTPUT_PREFIX = "GIBTI.IncidentEnrichment"
INTEGRATION_BRAND = "Group-IB Threat Intelligence & Attribution"
CREATE_INDICATOR_COMMAND = "createNewIndicator"
FIND_INDICATORS_COMMAND = "findIndicators"
# TLP colors from the least to the most restrictive, as the integration writes them.
TLP_ORDER = ("WHITE", "GREEN", "AMBER", "RED")
TLP_ALIASES = {"CLEAR": "WHITE", "AMBER+STRICT": "AMBER"}
MALWARE = "Malware"
THREAT_ACTOR = "Threat Actor"
# The verdict Cortex XSOAR's own threat-intel feeds give these objects (ThreatIntel.ObjectsScore).
OBJECT_VERDICT = "Malicious"
# Collections whose incident names are not attributions: the GIB Threat Actor Name of a breached record
# holds the leak's publishers and that of a defacement the defacer's handle, so they make no Threat Actor object.
NAMES_WITHOUT_ATTRIBUTION = frozenset({"compromised/breacheddb", "attacks/deface"})
# Quality flags with which Group-IB withdraws a record (a phishing group marked false positive or
# allow-listed): the lookup returns no indicator for it, and its names make no object.
WITHDRAWAL_FLAGS = ("falsePositive", "whitelist")

# collection -> (lookup command, extra command arguments)
COLLECTION_COMMANDS: dict[str, tuple[str, dict[str, str]]] = {
    "compromised/account_group": ("gibti-get-compromised-account-info", {}),
    "compromised/bank_card_group": ("gibti-get-compromised-card-group-info", {}),
    "compromised/masked_card": ("gibti-get-compromised-masked-card-info", {}),
    "compromised/spd": ("gibti-get-compromised-spd-info", {}),
    "compromised/breacheddb": ("gibti-get-compromised-breached-info", {}),
    "attacks/phishing_kit": ("gibti-get-phishing-kit-info", {}),
    "attacks/phishing_group": ("gibti-get-phishing-group-info", {}),
    "attacks/ddos": ("gibti-get-attacks-ddos-info", {}),
    "attacks/deface": ("gibti-get-attacks-deface-info", {}),
    "osi/git_repository": ("gibti-get-osi-git-leak-info", {}),
    "osi/public_leak": ("gibti-get-osi-public-leak-info", {}),
    "osi/vulnerability": ("gibti-get-osi-vulnerability-info", {}),
    "suspicious_ip/tor_node": ("gibti-get-suspicious-ip-tor-node-info", {}),
    "suspicious_ip/open_proxy": ("gibti-get-suspicious-ip-open-proxy-info", {}),
    "suspicious_ip/socks_proxy": ("gibti-get-suspicious-ip-socks-proxy-info", {}),
    "suspicious_ip/vpn": ("gibti-get-suspicious-ip-vpn-info", {}),
    "suspicious_ip/scanner": ("gibti-get-suspicious-ip-scanner-info", {}),
    "malware/cnc": ("gibti-get-malware-cnc-info", {}),
    "malware/malware": ("gibti-get-malware-malware-info", {}),
    "hi/threat": ("gibti-get-threat-info", {"isAPT": "false"}),
    "apt/threat": ("gibti-get-threat-info", {"isAPT": "true"}),
    "hi/threat_actor": ("gibti-get-threat-actor-info", {"isAPT": "false"}),
    "apt/threat_actor": ("gibti-get-threat-actor-info", {"isAPT": "true"}),
    "compromised/access": ("gibti-get-compromised-access-info", {}),
    "compromised/messenger": ("gibti-get-darkweb-telegram-info", {}),
    "compromised/discord": ("gibti-get-darkweb-discord-info", {}),
    "darkweb/forums": ("gibti-get-darkweb-forum-info", {}),
    "hi/open_threats": ("gibti-get-open-threat-info", {}),
}
# Incident types of collections Group-IB renamed or removed: no lookup reads their records again.
LEGACY_INCIDENT_TYPES = frozenset(
    {
        "GIB APT Threat",
        "GIB Brand Protection Phishing",
        "GIB Brand Protection Phishing Kit",
        "GIB Compromised Account",
        "GIB Compromised Card",
        "GIB Compromised Mule",
        "GIB Targeted Malware",
    }
)
# Incident type (the pack's classifier) -> collection.
COLLECTION_BY_INCIDENT_TYPE = {
    "GIB Compromised Account Group": "compromised/account_group",
    "GIB Compromised Card Group": "compromised/bank_card_group",
    "GIB Compromised Masked Card": "compromised/masked_card",
    "GIB SPD": "compromised/spd",
    "GIB Data Breach": "compromised/breacheddb",
    "GIB Attacks Phishing Kit": "attacks/phishing_kit",
    "GIB Attacks Phishing Group": "attacks/phishing_group",
    "GIB Attacks DDOS": "attacks/ddos",
    "GIB Attacks Deface": "attacks/deface",
    "GIB OSI Git Leak": "osi/git_repository",
    "GIB OSI Public Leak": "osi/public_leak",
    "GIB OSI Vulnerability": "osi/vulnerability",
    "GIB Suspicious IP TOR Node": "suspicious_ip/tor_node",
    "GIB Suspicious IP Open Proxy": "suspicious_ip/open_proxy",
    "GIB Suspicious IP Socks Proxy": "suspicious_ip/socks_proxy",
    "GIB Suspicious IP VPN": "suspicious_ip/vpn",
    "GIB Suspicious IP Scanner": "suspicious_ip/scanner",
    "GIB Malware CNC": "malware/cnc",
    "GIB Malware": "malware/malware",
    "GIB Cybercriminal Threat": "hi/threat",
    "GIB Nation-State Cybercriminals Threat": "apt/threat",
    "GIB Cybercriminal Threat Actor": "hi/threat_actor",
    "GIB Nation-State Cybercriminals Threat Actor": "apt/threat_actor",
    "GIB Compromised Access": "compromised/access",
    "GIB Darkweb Telegram": "compromised/messenger",
    "GIB Darkweb Discord": "compromised/discord",
    "GIB Darkweb Forum": "darkweb/forums",
    "GIB Open Threat": "hi/open_threats",
}
# DBotScore type of an indicator entry -> indicator type of the relationship entity
ENTITY_TYPES = {
    "ip": "IP",
    "domain": "Domain",
    "url": "URL",
    "file": "File",
    "cve": "CVE",
    "email": "Email",
    "cryptocurrency": "Cryptocurrency Address",
}
# DBotScore -> the verdict createNewIndicator takes
VERDICTS = {0: "Unknown", 1: "Benign", 2: "Suspicious", 3: "Malicious"}
# context key of a standard indicator (before the "(val..." filter) -> the attributes that hold its value,
# a nested one by its dotted path (an Email indicator's context is an Account with the address in Email.Address)
VALUE_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "IP": ("Address",),
    "IPv6": ("Address",),
    "Domain": ("Name",),
    "URL": ("Data",),
    "File": ("SHA256", "SHA1", "MD5", "SHA512"),
    "CVE": ("ID",),
    "Account": ("Email.Address",),
    "Cryptocurrency": ("Address",),
}


def _names(value: Any) -> list[str]:
    """The names of a field: a list, or a comma-joined string, without blanks or duplicates."""
    items = value if isinstance(value, list) else str(value or "").split(",")
    names: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in names:
            names.append(text)
    return names


def resolve_collection(args: dict[str, Any], incident: dict[str, Any] | None) -> str:
    explicit = str(args.get("collection") or "").strip()
    if explicit:
        if explicit not in COLLECTION_COMMANDS:
            raise DemistoException(f"Unsupported collection {explicit!r}; supported: {', '.join(COLLECTION_COMMANDS)}")
        return explicit
    incident_type = str((incident or {}).get("type") or "")
    collection = COLLECTION_BY_INCIDENT_TYPE.get(incident_type)
    if not collection:
        raise DemistoException(
            "Cannot derive the collection: pass 'collection' or run the script on a Group-IB incident "
            f"(got type {incident_type or 'none'})."
        )
    return collection


def resolve_instance(args: dict[str, Any], incident: dict[str, Any] | None) -> str | None:
    """The instance the lookup runs on: the instance argument, the active instance that fetched the incident, the only
    active instance, else every instance."""
    explicit = str(args.get("instance") or "").strip()
    if explicit:
        return explicit
    modules = demisto.getModules() or {}
    active = {
        name
        for name, module in modules.items()
        if isinstance(module, dict) and module.get("brand") == INTEGRATION_BRAND and module.get("state") == "active"
    }
    source = str((incident or {}).get("sourceInstance") or "").strip()
    if source and source in active:
        return source
    if len(active) == 1:
        return next(iter(active))
    return None


def resolve_gib_id(args: dict[str, Any], incident: dict[str, Any] | None) -> str:
    """The record ID to look up. A breached record's GIB ID joins its IDs with ", ", and the lookup takes
    the first, as its portal link does."""
    gib_id = str(args.get("gib_id") or "").strip()
    if not gib_id:
        custom_fields = (incident or {}).get("CustomFields") or {}
        gib_id = str(custom_fields.get("gibid") or "").strip() if isinstance(custom_fields, dict) else ""
    if not gib_id:
        raise DemistoException("Argument 'gib_id' is required outside a Group-IB incident.")
    return gib_id.split(",")[0].strip()


def dbot_key(entry: dict[str, Any]) -> str | None:
    context = entry.get("EntryContext") or {}
    return next((key for key in context if str(key).startswith("DBotScore")), None) if isinstance(context, dict) else None


def indicator_type_of(score: dict[str, Any]) -> str:
    """The indicator type of a DBotScore: an IPv6 address scores as an ip and is an IPv6 indicator."""
    raw_type = str(score.get("Type") or "")
    indicator_type = ENTITY_TYPES.get(raw_type.lower(), raw_type)
    if indicator_type == "IP":
        try:
            if isinstance(ipaddress.ip_address(str(score.get("Indicator") or "").strip()), ipaddress.IPv6Address):
                return "IPv6"
        except ValueError:
            pass
    return indicator_type


def observables_of(entry: dict[str, Any]) -> list[tuple[str, str]]:
    """(value, indicator type) of every DBotScore the entry carries."""
    key = dbot_key(entry)
    if not key:
        return []
    scores = entry["EntryContext"][key]
    found: list[tuple[str, str]] = []
    for score in scores if isinstance(scores, list) else [scores]:
        if not isinstance(score, dict) or not score.get("Indicator"):
            continue
        found.append((str(score["Indicator"]), indicator_type_of(score)))
    return found


def withdrawn(entries: list[dict[str, Any]]) -> bool:
    """Whether the lookup's record entry carries a WITHDRAWAL_FLAGS flag."""
    for entry in entries:
        context = entry.get("EntryContext") or {}
        for key, records in context.items() if isinstance(context, dict) else []:
            if not str(key).startswith("GIBTI."):
                continue
            for record in records if isinstance(records, list) else [records]:
                if isinstance(record, dict) and any(record.get(flag) is True for flag in WITHDRAWAL_FLAGS):
                    return True
    return False


def objects_of(entries: list[dict[str, Any]], incident: dict[str, Any] | None) -> list[tuple[str, str]]:
    """The (type, name) of every Malware / Threat Actor object the command related its indicators to;
    when the entries carry no relationships, the names the incident itself holds."""
    objects: list[tuple[str, str]] = []
    for entry in entries:
        for relationship in entry.get("Relationships") or []:
            if not isinstance(relationship, dict):
                continue
            key = (str(relationship.get("entityBType") or ""), str(relationship.get("entityB") or ""))
            if key[0] in (MALWARE, THREAT_ACTOR) and key[1] and key not in objects:
                objects.append(key)
    if objects:
        return objects
    custom_fields = (incident or {}).get("CustomFields") or {}
    if isinstance(custom_fields, dict):
        objects += [(MALWARE, name) for name in _names(custom_fields.get("gibmalwarename"))]
        objects += [(THREAT_ACTOR, name) for name in _names(custom_fields.get("gibthreatactorname"))]
    return objects


def relationships_for(observables: list[tuple[str, str]], objects: list[tuple[str, str]]) -> list[EntityRelationship]:
    relationships: list[EntityRelationship] = []
    for value, indicator_type in observables:
        for object_type, name in objects:
            malware = object_type == MALWARE
            relationships.append(
                EntityRelationship(
                    name=EntityRelationship.Relationships.INDICATOR_OF
                    if malware
                    else EntityRelationship.Relationships.RELATED_TO,
                    reverse_name=EntityRelationship.Relationships.INDICATED_BY
                    if malware
                    else EntityRelationship.Relationships.RELATED_TO,
                    entity_a=value,
                    entity_a_type=indicator_type,
                    entity_b=name,
                    entity_b_type=object_type,
                )
            )
    return relationships


def reissue(entry: dict[str, Any]) -> dict[str, Any]:
    """The indicator entry of the command as a War Room entry of this script: its table, and the
    relationships the platform stores from it."""
    readable = entry.get("HumanReadable") or ""
    contents = entry.get("Contents")
    # A dict without Contents is not an entry to the server: it is rendered as a JSON note and
    # nothing is extracted from it. The readable stands in when the command sent no contents.
    reissued = {
        "Type": entry.get("Type") or EntryType.NOTE,
        "ContentsFormat": entry.get("ContentsFormat") if contents not in (None, "") else EntryFormat.MARKDOWN,
        "Contents": contents if contents not in (None, "") else readable,
        "HumanReadable": readable,
        "EntryContext": entry.get("EntryContext") or {},
        "Relationships": entry.get("Relationships"),
        # A defacement's entries are not extracted: the site's host would become a Domain indicator.
        "IgnoreAutoExtract": entry.get("IgnoreAutoExtract"),
    }
    return {key: value for key, value in reissued.items() if value is not None}


def scored_observables(entries: list[dict[str, Any]]) -> dict[tuple[str, str], tuple[int, dict[str, Any]]]:
    """Every observable the entries score, once: (value, indicator type) -> (DBotScore, its context object).

    The same observable comes once per instance when the lookup ran on several instances; the
    highest score wins.
    """
    scored: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}
    for entry in entries:
        key = dbot_key(entry)
        if not key:
            continue
        scores = entry["EntryContext"][key]
        for score in scores if isinstance(scores, list) else [scores]:
            if not isinstance(score, dict) or not score.get("Indicator"):
                continue
            value = str(score["Indicator"])
            indicator_type = indicator_type_of(score)
            raw_score = score.get("Score")
            number = raw_score if isinstance(raw_score, int) and not isinstance(raw_score, bool) else 0
            previous = scored.get((value, indicator_type))
            if previous is None or number > previous[0]:
                scored[(value, indicator_type)] = (number, indicator_context(entry, value))
    return scored


def indicator_context(entry: dict[str, Any], value: str) -> dict[str, Any]:
    """The standard indicator context object (IP, IPv6, Domain, URL, File, CVE, Email, Cryptocurrency) of ``value``
    in the entry."""
    for key, objects in (entry.get("EntryContext") or {}).items():
        attributes = VALUE_ATTRIBUTES.get(str(key).split("(", 1)[0])
        if not attributes:
            continue
        for obj in objects if isinstance(objects, list) else [objects]:
            if isinstance(obj, dict) and any(str(_attribute(obj, attribute) or "") == value for attribute in attributes):
                return obj
    return {}


def _attribute(obj: dict[str, Any], path: str) -> Any:
    """The value at a dotted path of a context object."""
    found: Any = obj
    for part in path.split("."):
        found = found.get(part) if isinstance(found, dict) else None
    return found


def observable_arguments(value: str, indicator_type: str, score: int, context: dict[str, Any], collection: str) -> dict[str, Any]:
    """Arguments of ``createNewIndicator`` for one observable of the record: the verdict of its DBotScore
    and the attributes of its context, by CLI name."""
    geo_value, cvss_value = context.get("Geo"), context.get("CVSS")
    geo: dict[str, Any] = geo_value if isinstance(geo_value, dict) else {}
    cvss: dict[str, Any] = cvss_value if isinstance(cvss_value, dict) else {}
    attributes: dict[str, Any] = {
        "tags": ",".join(_names(context.get("Tags"))),
        "malwarefamily": ",".join(_names(context.get("MalwareFamily"))),
        "trafficlightprotocol": context.get("TrafficLightProtocol"),
        "asn": context.get("ASN"),
        "geocountry": geo.get("Country"),
        "geolocation": geo.get("Description"),
        "md5": context.get("MD5"),
        "sha1": context.get("SHA1"),
        "sha256": context.get("SHA256"),
        "sha512": context.get("SHA512"),
        "size": context.get("Size"),
        "cvss": cvss.get("Score"),
        "cvssvector": cvss.get("Vector"),
        "published": context.get("Published"),
        "cvemodified": context.get("Modified"),
        "cvedescription": context.get("Description") if indicator_type == "CVE" else None,
    }
    arguments: dict[str, Any] = {
        "value": value,
        "type": indicator_type,
        "verdict": VERDICTS.get(score, "Unknown"),
        "source": INTEGRATION_BRAND,
        "gibcollection": collection,
    }
    arguments.update({name: value for name, value in attributes.items() if value not in (None, "", [], {})})
    return arguments


def create_indicators(
    scored: dict[tuple[str, str], tuple[int, dict[str, Any]]], collection: str
) -> tuple[list[dict[str, str]], list[str]]:
    """Create every observable with ``createNewIndicator``, whatever the task's indicator extraction mode."""
    created: list[dict[str, str]] = []
    errors: list[str] = []
    for (value, indicator_type), (score, context) in scored.items():
        try:
            execute_command(
                CREATE_INDICATOR_COMMAND,
                observable_arguments(value, indicator_type, score, context, collection),
                extract_contents=False,
            )
            created.append({"value": value, "type": indicator_type})
        except Exception as exc:  # one failed indicator must not lose the others
            errors.append(f"{indicator_type} {value!r}: {exc}")
    return created, errors


def object_arguments(object_type: str, name: str, collection: str, incident: dict[str, Any] | None) -> dict[str, Any]:
    """Arguments of ``createNewIndicator`` for one object: the built-in command accepts custom fields by
    their CLI name, so the object carries the collection it comes from and, for the threat actor
    the incident names, its Group-IB ID and APT flag."""
    arguments: dict[str, Any] = {
        "value": name,
        "type": object_type,
        "verdict": OBJECT_VERDICT,
        "tags": collection,
        "gibcollection": collection,
    }
    custom_fields = (incident or {}).get("CustomFields") or {}
    if (
        object_type == THREAT_ACTOR
        and isinstance(custom_fields, dict)
        and _names(custom_fields.get("gibthreatactorname")) == [name]
    ):
        if custom_fields.get("gibthreatactorid") not in (None, ""):
            arguments["gibthreatactorid"] = str(custom_fields["gibthreatactorid"])
        if custom_fields.get("gibthreatactorisapt") not in (None, ""):
            arguments["gibthreatactorisapt"] = "true" if argToBoolean(custom_fields["gibthreatactorisapt"]) else "false"
    return arguments


def _tlp(value: Any) -> str | None:
    color = str(value or "").strip().upper().removeprefix("TLP:")
    color = TLP_ALIASES.get(color, color)
    return color if color in TLP_ORDER else None


def strictest_tlp(scored: dict[tuple[str, str], tuple[int, dict[str, Any]]], incident: dict[str, Any] | None) -> str | None:
    """The most restrictive TLP of the record: of its observables and of the incident's *GIB TLP*."""
    custom_fields = (incident or {}).get("CustomFields")
    colors = [_tlp(context.get("TrafficLightProtocol")) for _, context in scored.values()]
    colors.append(_tlp((custom_fields if isinstance(custom_fields, dict) else {}).get("gibtlp")))
    return max((color for color in colors if color), key=TLP_ORDER.index, default=None)


def object_tlp(object_type: str, name: str, record_tlp: str | None) -> str | None:
    """The TLP to create a new object with: the record's. An object that exists keeps its own, whatever
    created it: createNewIndicator replaces the field, and an object is shared by every record and feed
    that names it."""
    if not record_tlp:
        return None
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    try:
        found = execute_command(FIND_INDICATORS_COMMAND, {"query": f'value:"{escaped}" and type:"{object_type}"', "size": 1})
    except Exception as exc:
        demisto.debug(f"[GIBTIEnrichIncidentIndicators] findIndicators failed for {object_type} {name!r}; no TLP is set: {exc}")
        return None
    existing = [item for item in (found if isinstance(found, list) else [found]) if isinstance(item, dict)]
    return None if existing else record_tlp


def create_objects(
    objects: list[tuple[str, str]], collection: str, incident: dict[str, Any] | None, record_tlp: str | None = None
) -> tuple[list[dict[str, str]], list[str]]:
    created: list[dict[str, str]] = []
    errors: list[str] = []
    for object_type, name in objects:
        try:
            arguments = object_arguments(object_type, name, collection, incident)
            if tlp := object_tlp(object_type, name, record_tlp):
                arguments["trafficlightprotocol"] = tlp
            execute_command(CREATE_INDICATOR_COMMAND, arguments, extract_contents=False)
            created.append({"type": object_type, "name": name})
        except Exception as exc:  # one failed object must not lose the others
            errors.append(f"{object_type} {name!r}: {exc}")
    return created, errors


def enrich(
    collection: str, gib_id: str, with_objects: bool, incident: dict[str, Any] | None, instance: str | None = None
) -> list:
    command, extra = COLLECTION_COMMANDS[collection]
    arguments = {"id": gib_id, **extra, **({"using": instance} if instance else {})}
    raw = execute_command(command, arguments, extract_contents=False)
    entries = [entry for entry in (raw if isinstance(raw, list) else [raw]) if isinstance(entry, dict)]
    indicator_entries = [entry for entry in entries if dbot_key(entry)]
    scored = scored_observables(indicator_entries)
    observables = list(scored)
    attributed = collection not in NAMES_WITHOUT_ATTRIBUTION and not withdrawn(entries)
    objects = objects_of(indicator_entries, incident if attributed else None)
    # The entries stay in the War Room for their tables and relationships; the indicators themselves
    # are created explicitly (see create_indicators).
    results: list = [reissue(entry) for entry in indicator_entries]
    # The command's entries carry the relationships when the integration built them; otherwise
    # (an instance with "Create relationships" off) they are built here from the incident's names.
    relationships = (
        [] if any(entry.get("Relationships") for entry in indicator_entries) else relationships_for(observables, objects)
    )
    enriched, indicator_errors = create_indicators(scored, collection)
    created, object_errors = (
        create_objects(objects, collection, incident, strictest_tlp(scored, incident)) if with_objects and objects else ([], [])
    )
    errors = indicator_errors + object_errors
    output = {
        "gibId": gib_id,
        "collection": collection,
        "command": command,
        "instance": instance,
        "indicators": enriched,
        "objects": [{"type": object_type, "name": name} for object_type, name in objects],
        "objectsCreated": created,
        "errors": errors,
    }
    origin = f" (instance {instance})" if instance else ""
    summary = (
        f"Group-IB {collection} record {gib_id}{origin}: {len(enriched)} indicator(s) enriched, "
        f"{len(created)} Malware / Threat Actor object(s) created or updated"
        + (f", {len(errors)} failed: " + "; ".join(errors) if errors else "")
        + "."
    )
    results.append(
        CommandResults(
            outputs_prefix=OUTPUT_PREFIX,
            outputs_key_field="gibId",
            outputs=output,
            readable_output=summary,
            relationships=relationships or None,
            ignore_auto_extract=True,
        )
    )
    return results


def main():
    args = demisto.args()
    try:
        incident = demisto.incident() or {}
        incident_type = str(incident.get("type") or "")
        if incident_type in LEGACY_INCIDENT_TYPES and not args.get("collection"):
            return_results(
                CommandResults(
                    readable_output=f"Nothing to enrich: {incident_type} comes from a collection the integration no longer "
                    "reads. Pass collection and gib_id to read a record of a current collection."
                )
            )
            return
        collection = resolve_collection(args, incident)
        gib_id = resolve_gib_id(args, incident)
        with_objects = argToBoolean(args.get("create_objects", True))
        return_results(enrich(collection, gib_id, with_objects, incident, resolve_instance(args, incident)))
    except Exception as exc:
        return_error(f"GIBTIEnrichIncidentIndicators failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
