import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Same patterns as NetskopeV2.py's update_file_hash_list validation - only these two formats are
# accepted by the Netskope v1 file hash list API.
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
DEFAULT_MAX_INDICATORS = 500


def is_valid_hash(value) -> bool:
    return bool(value) and bool(MD5_PATTERN.match(value) or SHA256_PATTERN.match(value))


def extract_hashes(ioc: dict) -> list:
    # An indicator's primary "value" is usually the hash itself for File indicators, but some
    # feeds populate MD5/SHA256 as separate CustomFields instead (or as well) - check both so
    # either shape is picked up.
    candidates = [ioc.get("value")]
    custom_fields = ioc.get("CustomFields") or {}
    candidates.append(custom_fields.get("md5"))
    candidates.append(custom_fields.get("sha256"))
    return [c for c in candidates if is_valid_hash(c)]


FILE_INDICATOR_TYPES = 'File "File MD5" "File SHA-256"'


def build_query(tags: list) -> str:
    # The hash-specific types ("File MD5"/"File SHA-256") may be disabled as selectable indicator
    # types on a given tenant, in which case new hash indicators land under the generic "File"
    # type instead - search both so it works either way. is_valid_hash still does the real
    # filtering for which values are actually MD5/SHA256, regardless of which type matched.
    query = f"type:({FILE_INDICATOR_TYPES})"
    if tags:
        query += f' and tags:({" ".join(tags)})'
    return query


def main():
    args = demisto.args()

    tags = [t.strip() for t in argToList(args.get("tags")) if t.strip()]
    existing = {h.strip() for h in argToList(args.get("existing_hashes")) if h.strip()}
    max_indicators = int(args.get("max_indicators") or DEFAULT_MAX_INDICATORS)

    query = build_query(tags)
    # .get("iocs", []) only falls back when the key is absent - searchIndicators can return
    # {"iocs": None, ...} when nothing matches, so the "or []" is needed too.
    iocs = (demisto.searchIndicators(query=query, size=max_indicators) or {}).get("iocs") or []

    found: set = set()
    skipped_no_valid_hash = 0
    for ioc in iocs:
        hashes = extract_hashes(ioc)
        if not hashes:
            skipped_no_valid_hash += 1
            continue
        found.update(hashes)

    new_hashes = sorted(found - existing)
    merged_hashes = sorted(existing | found)

    outputs = {
        "query": query,
        "total_found_indicators": len(iocs),
        "skipped_no_valid_hash": skipped_no_valid_hash,
        "new_count": len(new_hashes),
        "new_hashes": new_hashes,
        "merged_hashes": merged_hashes,
    }

    readable_output = (
        f"Query: {query}\n"
        f"Found {len(iocs)} File indicator(s) (capped at {max_indicators} per run), "
        f"{skipped_no_valid_hash} without a valid MD5/SHA256 hash. "
        f"{len(new_hashes)} new hash(es) not already tracked "
        f"(currently tracking {len(existing)}, {len(merged_hashes)} total after merge)."
    )

    return_results(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="NetskopeHashSync",
            outputs=outputs,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
