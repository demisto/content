import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ALLOWED_TYPES = ["Domain", "URL", "IP", "CIDR"]
DEFAULT_MAX_INDICATORS = 500
DEFAULT_CHUNK_SIZE = 10


def format_value(indicator_type: str, value: str) -> str:
    # Matches the Netskope destination profile "Definition" field's expected syntax: plain values
    # for domains/URLs/IPs, but CIDR blocks need an explicit "CIDR:" prefix.
    if indicator_type == "CIDR":
        return f"CIDR:{value}"
    return value


def chunk_list(items: list, size: int) -> list:
    return [items[i : i + size] for i in range(0, len(items), size)]


def build_query(types: list, tags: list, skip_tags: list) -> str:
    query = f"type:({' '.join(types)})"
    if tags:
        query += f" and tags:({' '.join(tags)})"
    if skip_tags:
        query += f" and -tags:({' '.join(skip_tags)})"
    return query


def find_new_values(types: list, tags: list, skip_tags: list, existing: set, max_indicators: int, chunk_size: int) -> tuple:
    query = build_query(types, tags, skip_tags)
    # .get("iocs", []) only falls back when the key is absent - searchIndicators can return
    # {"iocs": None, ...} when nothing matches, so the "or []" is needed too.
    iocs = (demisto.searchIndicators(query=query, size=max_indicators) or {}).get("iocs") or []

    seen: set = set()
    new_values: list = []
    skipped_existing = 0
    skipped_no_value = 0
    for ioc in iocs:
        value = ioc.get("value")
        if not value:
            skipped_no_value += 1
            continue
        formatted = format_value(ioc.get("indicator_type", ""), value)
        if formatted in existing or formatted in seen:
            skipped_existing += 1
            continue
        seen.add(formatted)
        new_values.append(formatted)

    chunks = chunk_list(new_values, chunk_size)
    stats = {
        "query": query,
        "total_found": len(iocs),
        "skipped_existing": skipped_existing,
        "skipped_no_value": skipped_no_value,
        "new_count": len(new_values),
    }
    return new_values, chunks, stats


def append_chunk(profile_id: str, chunk: list) -> None:
    res = demisto.executeCommand(
        "netskopev2-update-destination-profile-values",
        {
            "id": profile_id,
            "operation": "append",
            "values": chunk,
        },
    )
    if is_error(res):
        raise DemistoException(f"Failed to append batch {chunk} to profile {profile_id}: {get_error(res)}")


def deploy_profile(profile_id: str, change_note: str) -> None:
    args: dict = {"ids": profile_id}
    if change_note:
        args["change_note"] = change_note
    res = demisto.executeCommand("netskopev2-deploy-destination-profiles", args)
    if is_error(res):
        raise DemistoException(f"Failed to deploy profile {profile_id}: {get_error(res)}")


def main():
    args = demisto.args()

    types = [t.strip() for t in argToList(args.get("indicator_types")) if t.strip()]
    invalid = [t for t in types if t not in ALLOWED_TYPES]
    if invalid:
        raise DemistoException(f"indicator_types must be one of {ALLOWED_TYPES}, got: {invalid}")
    if not types:
        raise DemistoException("indicator_types must not be empty")

    tags = [t.strip() for t in argToList(args.get("tags")) if t.strip()]
    skip_tags = [t.strip() for t in argToList(args.get("skip_tags")) if t.strip()]
    profile_id = args.get("profile_id")
    existing = {v.strip() for v in argToList(args.get("existing_values")) if v.strip()}
    max_indicators = int(args.get("max_indicators") or DEFAULT_MAX_INDICATORS)
    chunk_size = int(args.get("chunk_size") or DEFAULT_CHUNK_SIZE)

    new_values, chunks, stats = find_new_values(types, tags, skip_tags, existing, max_indicators, chunk_size)

    added_count = 0
    deployed = False
    if profile_id:
        # Appending to an existing profile - batched, since the API caps appends at chunk_size
        # values per call. Each batch is its own executeCommand call rather than a playbook-level
        # loop task, since there's no verified pattern in this codebase for looping a command task
        # over sub-array batches - doing it here in Python is simpler and directly testable.
        for chunk in chunks:
            append_chunk(profile_id, chunk)
            added_count += len(chunk)
        if added_count and argToBoolean(args.get("deploy", True)):
            deploy_profile(profile_id, args.get("change_note", ""))
            deployed = True

    outputs = {
        "profile_id": profile_id,
        "added_count": added_count,
        "deployed": deployed,
        "batches": len(chunks),
        "all_new_values": new_values,
        **stats,
    }

    if profile_id:
        readable_output = (
            f"Query: {stats['query']}\n"
            f"Found {stats['total_found']} indicator(s) (capped at {max_indicators} per run). "
            f"Appended {added_count} new value(s) to profile {profile_id} in {len(chunks)} batch(es)"
            f"{' and deployed' if deployed else ''}. "
            f"{stats['skipped_existing']} were already present or duplicated."
        )
    else:
        readable_output = (
            f"Query: {stats['query']}\n"
            f"Found {stats['total_found']} indicator(s) (capped at {max_indicators} per run). "
            f"{stats['new_count']} new value(s) prepared for a new profile. "
            f"{stats['skipped_existing']} were duplicated within this run."
        )

    return_results(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="NetskopeSync",
            outputs=outputs,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
