"""Create a Cortex XSOAR Threat Intel Report from a Group-IB record."""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any


SOURCE_NAME = "Group-IB Threat Intelligence"
INTEGRATION_BRAND = "Group-IB Threat Intelligence & Attribution"
CREATE_COMMAND = "createThreatIntelReport"
SET_COMMAND = "setThreatIntelReport"
OUTPUT_PREFIX = "GIBTI.ThreatIntelReport"

# collection -> (report type, lookup command, extra command arguments)
COLLECTION_PROFILES: dict[str, tuple[str, str, dict[str, str]]] = {
    "hi/threat": ("Campaign", "gibti-get-threat-info", {"isAPT": "false"}),
    "apt/threat": ("Campaign", "gibti-get-threat-info", {"isAPT": "true"}),
    "hi/threat_actor": ("Threat Actor", "gibti-get-threat-actor-info", {"isAPT": "false"}),
    "apt/threat_actor": ("Threat Actor", "gibti-get-threat-actor-info", {"isAPT": "true"}),
    "malware/malware": ("Malware", "gibti-get-malware-malware-info", {}),
    "osi/vulnerability": ("Vulnerability", "gibti-get-osi-vulnerability-info", {}),
}
# incident type (classifier output) -> collection
COLLECTION_BY_INCIDENT_TYPE = {
    "GIB Cybercriminal Threat": "hi/threat",
    "GIB Nation-State Cybercriminals Threat": "apt/threat",
    "GIB Cybercriminal Threat Actor": "hi/threat_actor",
    "GIB Nation-State Cybercriminals Threat Actor": "apt/threat_actor",
    "GIB Malware": "malware/malware",
    "GIB OSI Vulnerability": "osi/vulnerability",
}
# There is no shared body field: every report type owns one.
BODY_FIELD_BY_TYPE = {
    "Campaign": "bodycampaign",
    "Malware": "bodymalware",
    "Threat Actor": "bodythreatactor",
    "Vulnerability": "bodyvulnerability",
    "Executive Brief": "bodyexecutivebrief",
}
# The report types whose out-of-the-box fields include threatactor (ThreatIntelReports pack).
ACTOR_FIELD_TYPES = {"Threat Actor", "Campaign"}


def _as_list(value: Any) -> list:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [item for item in value if item not in (None, "")]
    return [value]


def _join(value: Any) -> str:
    return ", ".join(str(item) for item in _as_list(value))


def _first(value: Any) -> Any:
    items = _as_list(value)
    return items[0] if items else None


# Defanged spellings a report writes instead of the real value; the lookup commands restore them too.
_DEFANGED_PARTS = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://"), ("[@]", "@"))
# One hash per file of a report: SHA-256, else SHA-1, else MD5.
_FILE_HASHES = (("SHA256", "hashes_sha256"), ("SHA1", "hashes_sha1"), ("MD5", "hashes_md5"))


def _flatten(value: Any) -> list:
    """Every value of a column of the indicators block: a network entry holds a list of IPs."""
    if isinstance(value, list):
        return [item for element in value for item in _flatten(element)]
    return [] if value in (None, "") else [value]


def _refang(value: str) -> str:
    text = value.strip()
    if text[:4].lower() == "hxxp":
        text = "http" + text[4:]
    for defanged, fanged in _DEFANGED_PARTS:
        text = text.replace(defanged, fanged)
    return text


def indicator_rows(indicators: dict[str, Any]) -> list[tuple[str, str]]:
    """(type, value) of the IPv4, domain, URL and file-hash observables of a report's indicators block:
    defanged values restored, placeholders (``/{machineId}/``) skipped, one hash per file."""
    rows: list[tuple[str, str]] = []
    for label, key in (("IP", "ipv4"), ("Domain", "domain"), ("URL", "url")):
        for value in _flatten(indicators.get(key)):
            text = _refang(str(value))
            if text and not any(char in text for char in "{}") and not any(char.isspace() for char in text):
                rows.append((label, text))
    columns = [indicators.get(key) for _, key in _FILE_HASHES]
    columns = [column if isinstance(column, list) else [column] for column in columns]
    for position in range(max(len(column) for column in columns)):
        for (label, _), column in zip(_FILE_HASHES, columns):
            value = column[position] if position < len(column) else None
            if value not in (None, ""):
                rows.append((label, str(value)))
                break
    return list(dict.fromkeys(rows))


def resolve_collection(args: dict[str, Any], incident: dict[str, Any] | None) -> str:
    """The collection from the ``collection`` argument, the ``is_apt`` flag, or the incident type."""
    explicit = str(args.get("collection") or "").strip()
    if explicit:
        if explicit not in COLLECTION_PROFILES:
            raise DemistoException(f"Unsupported collection {explicit!r}; supported: {', '.join(COLLECTION_PROFILES)}")
        return explicit
    if args.get("is_apt") not in (None, ""):
        return "apt/threat" if argToBoolean(args.get("is_apt")) else "hi/threat"
    incident_type = str((incident or {}).get("type") or "")
    collection = COLLECTION_BY_INCIDENT_TYPE.get(incident_type)
    if not collection:
        raise DemistoException(
            f"Cannot derive the collection: pass 'collection' or run the script on one of these incident types: "
            f"{', '.join(COLLECTION_BY_INCIDENT_TYPE)} (got {incident_type or 'none'})."
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
    gib_id = str(args.get("gib_id") or "").strip()
    if gib_id:
        return gib_id
    custom_fields = (incident or {}).get("CustomFields") or {}
    gib_id = str(custom_fields.get("gibid") or "").strip() if isinstance(custom_fields, dict) else ""
    if not gib_id:
        raise DemistoException("Argument 'gib_id' is required outside a Group-IB incident.")
    return gib_id


def fetch_record(collection: str, gib_id: str, instance: str | None = None) -> dict[str, Any]:
    """Read the record through the integration command and return its parsed context object."""
    _type, command, extra = COLLECTION_PROFILES[collection]
    arguments = {"id": gib_id, **extra, **({"using": instance} if instance else {})}
    entries = execute_command(command, arguments, extract_contents=False)
    for entry in entries if isinstance(entries, list) else [entries]:
        context = (entry or {}).get("EntryContext") or {}
        for key, value in context.items():
            if not str(key).startswith("GIBTI."):
                continue
            record = value[0] if isinstance(value, list) and value else value
            if isinstance(record, dict) and record.get("id"):
                return record
    raise DemistoException(f"{command} returned no record for id {gib_id!r} in {collection}; check gib_id and collection.")


def report_name(record: dict[str, Any], collection: str) -> str:
    if collection == "osi/vulnerability":
        title = record.get("title")
        return f"[Group-IB] {record.get('id')}" + (f": {title}" if title else "")
    title = (
        record.get("title")
        or record.get("name")
        or record.get("threat_actor_name")
        or record.get("malware_name")
        or record.get("id")
    )
    number = record.get("reportNumber")
    return f"[Group-IB] {title}" + (f" ({number})" if number and number != title else "")


def actor_name(record: dict[str, Any], collection: str) -> str | None:
    if collection.endswith("/threat_actor"):
        return _first(record.get("threat_actor_name") or record.get("name"))
    actor = record.get("threatActor")
    if isinstance(actor, dict):
        return _first(actor.get("name"))
    return None


def report_summary(record: dict[str, Any], collection: str) -> str:
    parts = [f"Group-IB {collection} record {record.get('id')}"]
    actor = actor_name(record, collection)
    if actor and not collection.endswith("/threat_actor"):
        parts.append(f"attributed to {actor}")
    evaluation = record.get("evaluation") or {}
    if isinstance(evaluation, dict) and evaluation.get("severity"):
        parts.append(f"severity {evaluation['severity']}")
    return ", ".join(parts) + "."


def _facts(record: dict[str, Any], collection: str) -> list[tuple[str, Any]]:
    evaluation = record.get("evaluation") or {}
    actor_raw = record.get("threatActor")
    actor: dict = actor_raw if isinstance(actor_raw, dict) else {}
    common = [
        ("Group-IB ID", record.get("id")),
        ("Collection", collection),
        ("Severity", evaluation.get("severity") if isinstance(evaluation, dict) else None),
        ("TLP", evaluation.get("tlp") if isinstance(evaluation, dict) else None),
        ("Admiralty code", evaluation.get("admiraltyCode") if isinstance(evaluation, dict) else None),
        ("Portal", record.get("portalLink")),
    ]
    if collection in ("hi/threat", "apt/threat"):
        specific = [
            ("Report number", record.get("reportNumber")),
            ("Threat actor", actor.get("name")),
            ("APT", actor.get("isAPT")),
            ("Created", record.get("createdAt")),
            ("Published", record.get("datePublished")),
            ("First seen", record.get("dateFirstSeen")),
            ("Last seen", record.get("dateLastSeen")),
        ]
    elif collection.endswith("/threat_actor"):
        specific = [
            ("Name", record.get("threat_actor_name") or record.get("name")),
            ("Aliases", _join(record.get("aliases"))),
            ("Country", record.get("country")),
            ("APT", record.get("isAPT")),
            ("Created", record.get("createdAt")),
            ("Updated", record.get("updatedAt")),
            ("First seen", record.get("dateFirstSeen")),
            ("Last seen", record.get("dateLastSeen")),
        ]
    elif collection == "malware/malware":
        specific = [
            ("Name", record.get("malware_name") or record.get("name")),
            ("Aliases", _join(record.get("aliases"))),
            ("Category", _join(record.get("category"))),
            ("Platforms", _join(record.get("platform"))),
            ("Threat level", record.get("threatLevel")),
            ("Updated", record.get("updatedAt")),
        ]
    else:  # osi/vulnerability
        cvss_raw = record.get("cvss")
        cvss: dict = cvss_raw if isinstance(cvss_raw, dict) else {}
        specific = [
            ("Title", record.get("title")),
            ("CVSS", cvss.get("score")),
            ("CVSS vector", cvss.get("vector")),
            ("Merged CVSS", record.get("mergedCvss")),
            ("EPSS", record.get("epssScore")),
            ("EPSS percentile", record.get("epssPercentile")),
            ("Exploit available", record.get("hasExploit")),
            ("Seen in the wild", record.get("seenInTheWild")),
            ("Published", record.get("datePublished")),
            ("Modified", record.get("dateModified")),
            ("Reporter", record.get("reporter")),
        ]
    return [(label, value) for label, value in common[:2] + specific + common[2:] if value not in (None, "", [])]


def build_body(record: dict[str, Any], collection: str) -> str:
    """Markdown body of the record's main fields, so nothing depends on tenant-specific fields."""
    lines = [f"# {report_name(record, collection)[len('[Group-IB] '):]}", "", "| Field | Value |", "| --- | --- |"]
    lines += [f"| {label} | {value} |" for label, value in _facts(record, collection)]
    for label, key in (
        ("Regions", "regions"),
        ("Countries", "countries"),
        ("Sectors", "sectors"),
        ("Expertise", "expertise"),
        (
            "Languages",
            "langs",
        ),
        ("Labels", "labels"),
        ("Goals", "goals"),
        ("Roles", "roles"),
        ("Malware", "malware"),
        ("CVE", "cve"),
        ("Source countries", "sourceCountry"),
    ):
        if _as_list(record.get(key)):
            lines += ["", f"**{label}:** {_join(record.get(key))}"]
    for label, key in (
        ("Description", "description"),
        ("Short description", "shortDescription"),
        ("Extended description", "extDescription"),
    ):
        if record.get(key):
            # The lookup returns each narrative as the incident shows it, an HTML one already as text with a line per
            # paragraph, list item and table cell. Markdown joins consecutive lines into one paragraph; a blank line parts them.
            paragraphs = [line.strip() for line in str(record[key]).splitlines() if line.strip()]
            lines += ["", f"## {label}", "", "\n\n".join(paragraphs)]
    indicators = record.get("indicators") or {}
    ioc_lines = [f"| {label} | {value} |" for label, value in indicator_rows(indicators)] if isinstance(indicators, dict) else []
    if ioc_lines:
        lines += ["", "## Indicators", "", "| Type | Value |", "| --- | --- |", *ioc_lines]
    reports_raw = record.get("reports")
    reports: dict = reports_raw if isinstance(reports_raw, dict) else {}
    names = _as_list(reports.get("name"))
    if names:
        lines += ["", "## Reports", ""]
        ids = _as_list(reports.get("id"))
        for index, name in enumerate(names):
            lines.append(f"- {name}" + (f" ({ids[index]})" if index < len(ids) else ""))
    forums_raw = record.get("forumsAccounts")
    forums: dict = forums_raw if isinstance(forums_raw, dict) else {}
    nicknames = _as_list(forums.get("nickname"))
    if nicknames:
        lines += ["", "## Forum accounts", ""]
        urls = _as_list(forums.get("url"))
        for index, nickname in enumerate(nicknames):
            lines.append(f"- {nickname}" + (f" ({urls[index]})" if index < len(urls) else ""))
    return "\n".join(lines)


def build_fields(record: dict[str, Any], collection: str, report_type: str) -> dict[str, Any]:
    """Arguments for setThreatIntelReport: the body field, description, source and threatactor (Campaign and Threat Actor)."""
    fields: dict[str, Any] = {"description": report_summary(record, collection), "source": SOURCE_NAME}
    body_field = BODY_FIELD_BY_TYPE.get(report_type)
    if body_field:
        fields[body_field] = build_body(record, collection)
    actor = actor_name(record, collection)
    if actor and report_type in ACTOR_FIELD_TYPES:
        fields["threatactor"] = actor
    return assign_params(**fields)


def extract_report_id(result: Any) -> str | None:
    entries = result if isinstance(result, list) else [result]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key, value in (entry.get("EntryContext") or {}).items():
            if "ThreatIntelReport" in str(key):
                obj = value[0] if isinstance(value, list) and value else value
                if isinstance(obj, dict) and obj.get("id"):
                    return str(obj["id"])
        contents = entry.get("Contents")
        if isinstance(contents, dict) and contents.get("id"):
            return str(contents["id"])
        if isinstance(contents, str) and contents.strip():
            return contents.strip()
    return None


def create_report(
    collection: str, gib_id: str, report_type: str | None, dry_run: bool, instance: str | None = None
) -> CommandResults:
    default_type = COLLECTION_PROFILES[collection][0]
    report_type = report_type or default_type
    record = fetch_record(collection, gib_id, instance)
    name = report_name(record, collection)
    fields = build_fields(record, collection, report_type)
    output: dict[str, Any] = {
        "gibId": record.get("id"),
        "collection": collection,
        "name": name,
        "type": report_type,
        "created": False,
        "dryRun": dry_run,
    }
    if dry_run:
        output["payload"] = {"name": name, "type": report_type, **fields}
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX,
            outputs_key_field="gibId",
            outputs=output,
            readable_output=tableToMarkdown(
                f"Threat Intel Report payload for {gib_id} (dry run)",
                output["payload"],
                removeNull=True,
            ),
            ignore_auto_extract=True,
        )
    created = execute_command(CREATE_COMMAND, {"name": name, "type": report_type}, extract_contents=False)
    report_id = extract_report_id(created)
    if not report_id:
        raise DemistoException(f"{CREATE_COMMAND} did not return a report id for {name!r}: {created!r}")
    execute_command(SET_COMMAND, {"id": report_id, **fields})
    output.update({"id": report_id, "created": True})
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field="gibId",
        outputs=output,
        readable_output=(
            f"Threat Intel Report **{name}** (type {report_type}, id {report_id}) "
            f"created from Group-IB {collection} record {gib_id}."
        ),
        ignore_auto_extract=True,
    )


def main():
    args = demisto.args()
    try:
        incident = demisto.incident() or {}
        collection = resolve_collection(args, incident)
        gib_id = resolve_gib_id(args, incident)
        report_type = str(args.get("report_type") or "").strip() or None
        dry_run = argToBoolean(args.get("dry_run", False))
        return_results(create_report(collection, gib_id, report_type, dry_run, resolve_instance(args, incident)))
    except Exception as exc:
        return_error(f"GIBTICreateThreatIntelReport failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
