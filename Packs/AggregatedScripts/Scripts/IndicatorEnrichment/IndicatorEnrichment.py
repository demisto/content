import demistomock as demisto
from CommonServerPython import *

from AggregatedCommandApiModule import *

# =========================
# Constants & Configuration
# =========================

MAX_INDICATORS = 100

NO_VALID_INDICATORS_MESSAGE = (
    "No valid indicators provided. You must provide at least one valid indicator " "in arguments: indicators_list or text."
)

ERR_INDICATOR_LIMIT_EXCEEDED_TEMPLATE = (
    "Error: Indicator limit exceeded. Found {found} indicators, but the limit is {limit}. "
    "To process all indicators, set the ignore_indicator_limit argument to true. "
    "Note: This should be avoided if possible."
)


class FatalArgException(Exception):
    """
    Raised when the command arguments are invalid in a way that must stop the command execution.

    These are surfaced to the user via `return_error` in `main()`.
    """


# Unified configuration for all supported indicator types
INDICATOR_TYPE_CONFIG: dict[str, dict[str, str]] = {
    "ip": {
        "display": "IP",
        "command": "ip-enrichment",
        "arg_name": "ip_list",
        "enrichment_prefix": "IPEnrichment",
    },
    "url": {
        "display": "URL",
        "command": "url-enrichment",
        "arg_name": "url_list",
        "enrichment_prefix": "URLEnrichment",
    },
    "domain": {
        "display": "Domain",
        "command": "domain-enrichment",
        "arg_name": "domain_list",
        "enrichment_prefix": "DomainEnrichment",
    },
    "cve": {
        "display": "CVE",
        "command": "cve-enrichment",
        "arg_name": "cve_list",
        "enrichment_prefix": "CVEEnrichment",
    },
    "file": {
        "display": "File",
        "command": "file-enrichment",
        "arg_name": "file_hash",
        "enrichment_prefix": "FileEnrichment",
    },
}

SUPPORTED_INDICATOR_TYPES: set[str] = set(INDICATOR_TYPE_CONFIG.keys())


# ===============
# Helper Functions
# ===============


def normalize_indicator_type(raw_type: str) -> str:
    """
    Normalize raw indicator type names into our internal bucket names.

    Examples:
        - "ip", "IPv4" -> "ip"
        - "Url" -> "url"
        - "domain" -> "domain"
        - "cve" -> "cve"
        - "md5", "sha1", "sha256" -> "file"
        - Anything unknown -> returned as-is for unsupported classification.

    Args:
        raw_type: The raw type string from extractIndicators / auto_detect_indicator_type.

    Returns:
        Normalized internal type name ("ip", "url", "domain", "cve", "file")
        or the original string if not recognized (treated as unsupported).
    """
    if not raw_type:
        return "Unknown"

    t = raw_type.lower()

    if t in {"ip", "ipv4"}:
        return "ip"
    if t == "url":
        return "url"
    if t == "domain":
        return "domain"
    if t == "cve":
        return "cve"
    if t in {"file", "md5", "sha1", "sha256", "sha512"}:
        return "file"

    return raw_type


def run_extract_indicators(text: str) -> dict[str, Any]:
    """
    Run the `extractIndicators` command in the same way the working helper does.

    This:
        - Uses execute_command instead of Command.execute()
        - Forces extract_contents=False so we get a full entry structure
        - Always reads ExtractedIndicators from EntryContext ONLY
        - Never crashes on unexpected structure
        - Returns {} if no indicators are found or if command fails

    Args:
        text: Free text from which to extract indicators.

    Returns:
        dict[str, Any]: The ExtractedIndicators mapping,
                        e.g. {"IP": ["1.1.1.1"], "URL": ["https://..."]}
                        or {} if nothing is found.
    """
    if not text:
        return {}

    demisto.debug("IndicatorEnrichment: validating input using extractIndicators (execute_command)")

    # Use the same approach as your working version
    results = execute_command("extractIndicators", {"text": text}, extract_contents=False)

    # Defensive check: results should be a list of entries
    if not isinstance(results, list) or not results:
        demisto.debug("IndicatorEnrichment: extractIndicators returned no results or invalid structure.")
        return {}

    first = results[0]
    if not isinstance(first, dict):
        demisto.debug(f"IndicatorEnrichment: malformed extractIndicators result: {first!r}")
        return {}

    # Always extract ONLY from EntryContext.ExtractedIndicators (your working pattern)
    entry_context = first.get("EntryContext", {})
    if not isinstance(entry_context, dict):
        demisto.debug("IndicatorEnrichment: EntryContext missing or invalid.")
        return {}

    extracted = entry_context.get("ExtractedIndicators", {})
    if not isinstance(extracted, dict):
        demisto.debug("IndicatorEnrichment: ExtractedIndicators missing or invalid.")
        return {}

    demisto.debug(f"IndicatorEnrichment: extracted indicators = {extracted}")
    return extracted


def normalize_args(args: dict[str, Any]) -> tuple[str, list[str], bool, bool, bool]:
    """
    Normalize raw demisto args into typed values.

    Args:
        args: Raw demisto.args() dict.

    Returns:
        text: str
        indicators_list: list[str]
        indicators_list_provided: bool (argument key present, even if empty)
        ignore_indicator_limit: bool
        raw_context: bool

    Example:
        args = {
            "text": "The IOC is 192.168.1.0",
            "indicators_list": "192.168.1.0,example.com",
            "ignore_indicator_limit": "false",
            "raw_context": "true",
        }
        -> ("The IOC is 192.168.1.0", ["192.168.1.0", "example.com"], True, False, True)
    """
    text = args.get("text", "") or ""

    # Keep the raw value so we know if the user passed the argument at all
    indicators_list_raw = args.get("indicators_list")
    indicators_list = argToList(indicators_list_raw or "")
    indicators_list_provided = "indicators_list" in args

    ignore_indicator_limit = argToBoolean(args.get("ignore_indicator_limit", False))
    raw_context = argToBoolean(args.get("raw_context", False))

    return text, indicators_list, indicators_list_provided, ignore_indicator_limit, raw_context


def validate_initial_args(text: str, indicators_list: list[str], indicators_list_provided: bool) -> None:
    """
    Validate that at least one of text or indicators_list is provided.

    Raises:
        FatalArgException: If arguments are fundamentally missing or malformed.

    Rules:
        - If neither text nor indicators_list are provided -> fatal.
        - If indicators_list is provided but ends up empty AND no text -> fatal.
        - If text is provided, even if indicators_list is empty, we allow text-only mode
          and will handle "no indicators found" later.

    This uses the unified NO_VALID_INDICATORS_MESSAGE for all invalid-input cases.
    """
    text_provided = bool(text.strip())
    list_has_values = bool(indicators_list)

    # Case 1: both missing or effectively empty AND list was not explicitly provided
    if not text_provided and not list_has_values and not indicators_list_provided:
        demisto.debug("IndicatorEnrichment: validation failed - neither text nor indicators_list were provided.")
        raise FatalArgException(NO_VALID_INDICATORS_MESSAGE)

    # Case 2: indicators_list was provided but ended up empty after normalization (spaces, commas, etc.)
    if indicators_list_provided and not list_has_values and not text_provided:
        demisto.debug("IndicatorEnrichment: validation failed - indicators_list was provided but contains no indicators.")
        raise FatalArgException(NO_VALID_INDICATORS_MESSAGE)


def extract_from_text(
    text: str,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    """
    Extract indicators from free text using extractIndicators and classify them.

    Args:
        text: Free text to parse.

    Returns:
        supported:   list of (internal_type, value) where internal_type is in SUPPORTED_INDICATOR_TYPES
        unsupported: list of (original_type, value) for known but unsupported types
        unknown:     list of values for indicators classified as Unknown / invalid

    Example:
        text = "Check IP 192.168.1.0 and IPv6 ::1 and not-an-ioc"
        -> supported:   [("ip", "192.168.1.0")]
           unsupported: [("IPv6", "::1")]
           unknown:     ["not-an-ioc"]
    """
    if not text:
        return [], [], []

    extracted = run_extract_indicators(text)
    demisto.debug(f"IndicatorEnrichment: extract_from_text ExtractedIndicators: {extracted}")

    supported: list[tuple[str, str]] = []
    unsupported: list[tuple[str, str]] = []
    unknown: list[str] = []

    for indicator_type, values in extracted.items():
        if not values:
            continue

        if isinstance(values, str):
            values = [values]

        for value in values:
            if not value:
                continue

            internal_type = normalize_indicator_type(indicator_type)

            if internal_type in SUPPORTED_INDICATOR_TYPES:
                supported.append((internal_type, value))
            elif internal_type == "Unknown":
                unknown.append(value)
            else:
                # Concrete but unsupported type (e.g., IPv6, CIDR, etc.)
                unsupported.append((indicator_type, value))

    return supported, unsupported, unknown


def extract_from_indicator_list(
    indicators_list: list[str],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    """
    Extract indicator types from indicators_list values using auto_detect_indicator_type
    and classify them.

    Args:
        indicators_list: Values provided via the `indicators_list` argument.

    Returns:
        supported:   list of (internal_type, value) where internal_type is in SUPPORTED_INDICATOR_TYPES
        unsupported: list of (original_type, value) for known but unsupported types
        unknown:     list of values for indicators classified as Unknown / invalid

    Example:
        indicators_list = ["192.168.1.0", "10.0.0.0/8", "not-an-ioc"]
        -> supported:   [("ip", "192.168.1.0")]
           unsupported: [("CIDR", "10.0.0.0/8")]
           unknown:     ["not-an-ioc"]
    """
    if not indicators_list:
        return [], [], []

    supported: list[tuple[str, str]] = []
    unsupported: list[tuple[str, str]] = []
    unknown: list[str] = []

    for raw_value in indicators_list:
        if not raw_value:
            continue

        detected_type = auto_detect_indicator_type(raw_value)  # type: ignore
        demisto.debug(f"IndicatorEnrichment: auto_detect_indicator_type('{raw_value}') -> {detected_type}")

        internal_type = normalize_indicator_type(detected_type or "")

        if internal_type in SUPPORTED_INDICATOR_TYPES:
            supported.append((internal_type, raw_value))
        elif internal_type == "Unknown" or not detected_type:
            unknown.append(raw_value)
        else:
            # Known but unsupported type (e.g. IPv6, CIDR)
            unsupported.append((detected_type, raw_value))

    return supported, unsupported, unknown


def collect_indicators(
    text: str,
    indicators_list: list[str],
) -> tuple[
    dict[str, set[str]],
    set[tuple[str, str]],
    set[str],
    int,
    int,
]:
    """
    Extract indicators from both text and indicators_list, then merge and deduplicate.

    Args:
        text: Free text to parse for indicators.
        indicators_list: list of explicit indicator values.

    Returns:
        supported_buckets:   {internal_type -> {values}}
        unsupported_entries: {(original_type, value), ...}
        unknown_entries:     {"value", ...}
        duplicates_count:    total number of duplicate occurrences skipped
        total_supported:     total number of unique supported indicators

    Example:
        text = "IP 192.168.1.0 and URL https://example.com"
        indicators_list = ["192.168.1.0", "not-an-ioc"]

        -> supported_buckets = {
               "ip": {"192.168.1.0"},
               "url": {"https://example.com"}
           }
           unsupported_entries = set()
           unknown_entries = {"not-an-ioc"}
           duplicates_count >= 1 (because 192.168.1.0 appears twice)
           total_supported = 2
    """
    supported_buckets: dict[str, set[str]] = {}
    unsupported_entries: set[tuple[str, str]] = set()
    unknown_entries: set[str] = set()

    duplicates_count = 0
    seen_supported: set[tuple[str, str]] = set()
    seen_unsupported: set[tuple[str, str]] = set()
    seen_unknown: set[str] = set()

    # 1) Extract from text
    supported_from_text, unsupported_from_text, unknown_from_text = extract_from_text(text)

    # 2) Extract from indicators_list
    supported_from_list, unsupported_from_list, unknown_from_list = extract_from_indicator_list(indicators_list)

    # 3) Merge + dedup (text first, then list)

    # Supported
    for internal_type, value in supported_from_text + supported_from_list:
        key = (internal_type, value)
        if key in seen_supported:
            duplicates_count += 1
            continue
        seen_supported.add(key)
        supported_buckets.setdefault(internal_type, set()).add(value)

    # Unsupported
    for original_type, value in unsupported_from_text + unsupported_from_list:
        key = (original_type, value)
        if key in seen_unsupported:
            duplicates_count += 1
            continue
        seen_unsupported.add(key)
        unsupported_entries.add((original_type, value))

    # Unknown
    for value in unknown_from_text + unknown_from_list:
        if value in seen_unknown:
            duplicates_count += 1
            continue
        seen_unknown.add(value)
        unknown_entries.add(value)

    total_supported = sum(len(values) for values in supported_buckets.values())

    demisto.debug(
        "IndicatorEnrichment: collection summary (after merge): "
        f"supported={total_supported}, unsupported={len(unsupported_entries)}, "
        f"unknown={len(unknown_entries)}, duplicates={duplicates_count}"
    )

    return supported_buckets, unsupported_entries, unknown_entries, duplicates_count, total_supported


def validate_collected_indicators(
    text: str,
    indicators_list: list[str],
    indicators_list_provided: bool,
    total_supported: int,
    unsupported_entries: set[tuple[str, str]],
    unknown_entries: set[str],
) -> Optional[CommandResults]:
    """
    Validate the collected indicators after extraction/merge.

    Behavior:
        - If indicators_list was provided AND there are zero supported indicators,
          we treat it as a fatal argument error (raise FatalArgException) because the user
          explicitly provided bad inputs.
        - If only text was provided (no indicators_list at all) AND there are zero supported
          indicators, we return a normal informational CommandResults with the unified
          "No valid indicators..." message.
        - Otherwise, we return None and execution continues.

    Args:
        text:             The text argument (possibly empty).
        indicators_list:  Normalized indicators_list values.
        indicators_list_provided: True if the indicators_list arg key was present in args.
        total_supported:  Number of unique supported indicators.
        unsupported_entries: set of (original_type, value) for unsupported indicators.
        unknown_entries:     set of values for indicators classified as unknown/invalid.

    Returns:
        CommandResults if a non-fatal informational message should be returned,
        or None if execution should continue.

    Raises:
        FatalArgException for list-related invalid input cases.
    """
    text_provided = bool(text.strip())
    list_has_values = bool(indicators_list)

    # If indicators_list was involved, and there are ZERO supported indicators:
    # treat this as a fatal argument error.
    if indicators_list_provided and list_has_values and total_supported == 0:
        only_unsupported = bool(unsupported_entries) and not unknown_entries
        only_unknown = bool(unknown_entries) and not unsupported_entries

        if only_unsupported:
            demisto.debug("IndicatorEnrichment: validation failed - indicators_list contains only unsupported indicator types.")
        elif only_unknown:
            demisto.debug("IndicatorEnrichment: validation failed - indicators_list contains only invalid/unknown indicators.")
        else:
            demisto.debug(
                "IndicatorEnrichment: validation failed - indicators_list contains only unsupported and/or invalid indicators."
            )

        # In all of these list-related cases, we use the single unified message.
        raise FatalArgException(NO_VALID_INDICATORS_MESSAGE)

    # Text-only mode: no list, no supported → NOT an error, just a message
    if text_provided and not indicators_list_provided and total_supported == 0:
        demisto.debug("IndicatorEnrichment: text-only input and no indicators were extracted - returning informational message.")
        return CommandResults(
            readable_output=NO_VALID_INDICATORS_MESSAGE,
            outputs={},
        )

    # Otherwise: everything is fine
    return None


def enforce_indicator_limit(total_supported: int, ignore_indicator_limit: bool) -> None:
    """
    Enforce a hard cap on the total number of supported indicators to enrich.

    If `ignore_indicator_limit` is False and `total_supported` exceeds MAX_INDICATORS,
    this raises a FatalArgException which will be returned via `return_error` in main.

    Args:
        total_supported: Number of unique supported indicators.
        ignore_indicator_limit: Whether to bypass the limit.

    Raises:
        FatalArgException: If limit is exceeded and ignore_indicator_limit is False.
    """
    if ignore_indicator_limit:
        demisto.debug(
            f"IndicatorEnrichment: ignore_indicator_limit=true, skipping indicator count check "
            f"(total_supported={total_supported}, limit={MAX_INDICATORS})."
        )
        return

    if total_supported > MAX_INDICATORS:
        message = ERR_INDICATOR_LIMIT_EXCEEDED_TEMPLATE.format(
            found=total_supported,
            limit=MAX_INDICATORS,
        )
        demisto.debug(f"IndicatorEnrichment: validation failed - {message}")
        raise FatalArgException(message)

    demisto.debug(
        f"IndicatorEnrichment: indicator count within limit " f"(total_supported={total_supported}, limit={MAX_INDICATORS})."
    )


def run_underlying_enrichment_scripts(
    supported_buckets: dict[str, set[str]],
    args: dict[str, Any],
) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    """
    Execute the underlying enrichment scripts for each supported bucket using BatchExecutor.

    Underlying scripts:
        - ip-enrichment
        - url-enrichment
        - domain-enrichment
        - cve-enrichment
        - file-enrichment

    Each is treated as a black box. This function:
        - Builds Command objects using INDICATOR_TYPE_CONFIG.
        - Executes them in a single batch.
        - Aggregates EntryContext from all commands into `merged_context`.
        - Collects HumanReadable sections along with their indicator bucket type.

    Args:
        supported_buckets: A mapping of internal_type -> set(values).
        args:              Raw command args (used for external_enrichment, brands, additional_fields).

    Returns:
        underlying_sections: list of (bucket_type, markdown HR block).
        merged_context:      Combined EntryContext from all child scripts.
    """
    external_enrichment = args.get("external_enrichment")
    enrichment_brands = args.get("brands")
    additional_fields = args.get("additional_fields")

    demisto.debug(
        "IndicatorEnrichment: running underlying scripts (BatchExecutor) with "
        f"external_enrichment={external_enrichment}, brands={enrichment_brands}, "
        f"additional_fields={additional_fields}"
    )

    sections: list[tuple[str, str]] = []
    merged_context: dict[str, Any] = {}
    commands: list[tuple[str, Command]] = []

    # Build commands based on buckets and INDICATOR_TYPE_CONFIG
    for bucket_type, values in supported_buckets.items():
        if not values:
            continue

        type_cfg = INDICATOR_TYPE_CONFIG.get(bucket_type)
        if not type_cfg:
            demisto.debug(f"IndicatorEnrichment: no type config found for bucket '{bucket_type}', skipping.")
            continue

        cmd_args: dict[str, Any] = {
            type_cfg["arg_name"]: list(values),
        }
        if external_enrichment is not None:
            cmd_args["external_enrichment"] = external_enrichment
        if enrichment_brands is not None:
            cmd_args["brands"] = enrichment_brands
        if additional_fields is not None:
            cmd_args["additional_fields"] = additional_fields

        cmd = Command(
            name=type_cfg["command"],
            args=cmd_args,
            command_type=CommandType.INTERNAL,
            ignore_using_brand=True,
            is_multi_input=True,
            is_aggregated_output=True,
        )
        commands.append((bucket_type, cmd))

    if not commands:
        return [], {}

    executor = BatchExecutor()
    # execute_batch expects a list of Command objects
    batches_results = executor.execute_batch(
        commands=[c for _t, c in commands],
        brands_to_run=None,
        verbose=False,
    )

    demisto.debug(f"The raw batch results are: {batches_results}")

    for (bucket_type, command), command_results in zip(commands, batches_results):
        demisto.debug(
            f"IndicatorEnrichment: processing results for command {command.name} "
            f"({len(command_results)} result entries) in bucket '{bucket_type}'"
        )
        for result, _hr_output, error_message in command_results:
            # Merge EntryContext into local merged_context (for building IndicatorEnrichment)
            context = result.get("EntryContext") or result.get("Contents") or {}
            if isinstance(context, dict):
                merged_context.update(context)

            # Collect underlying HR
            hr = result.get("HumanReadable")
            if hr:
                sections.append((bucket_type, hr))
            elif error_message:
                sections.append((bucket_type, f"### Error from {command.name}\n{error_message}"))

    return sections, merged_context


def build_error_table(
    unsupported_entries: set[tuple[str, str]],
    unknown_entries: set[str],
) -> list[dict[str, str]]:
    """
    Build the error table rows for unsupported and unknown indicators.

    Args:
        unsupported_entries: set of (original_type, value) for unsupported indicators.
        unknown_entries:     set of values for unknown/invalid indicators.

    Returns:
        A list of dicts suitable for tableToMarkdown.
    """
    rows: list[dict[str, str]] = []

    # Sort by type, then value (case-insensitive) so same types are grouped together
    for indicator_type, value in sorted(
        unsupported_entries,
        key=lambda x: (x[0].lower(), x[1].lower()),
    ):
        rows.append(
            {
                "Type": indicator_type,
                "Value": value,
                "Status": "Error",
                "Message": "No script supports this indicator type.",
            }
        )

    for value in sorted(unknown_entries, key=lambda v: v.lower()):
        rows.append(
            {
                "Type": "Unknown",
                "Value": value,
                "Status": "Error",
                "Message": "Not a valid indicator.",
            }
        )

    return rows


def build_indicator_enrichment_list(
    merged_context: dict[str, Any],
    unsupported_entries: set[tuple[str, str]],
    unknown_entries: set[str],
) -> list[dict[str, Any]]:
    """
    Build the unified IndicatorEnrichment list.

    - For successful enrichments, we:
        * Read *Enrichment(...) keys in merged_context.
        * Detect type by matching key prefix from INDICATOR_TYPE_CONFIG.
        * Unpack each object.
        * Add a "Type" field (e.g. "IP", "URL", "File").
        * Keep all other fields exactly as returned by the underlying scripts.

    - For invalid/unsupported indicators, we add error objects with:
        * Type
        * Value
        * Message
        * Status

    Args:
        merged_context: EntryContext as produced by underlying enrichment scripts.
        unsupported_entries: Unsupported indicators collected from input parsing.
        unknown_entries: Unknown/invalid indicators collected from input parsing.

    Returns:
        A list of IndicatorEnrichment objects.
    """
    indicator_enrichment: list[dict[str, Any]] = []

    # Success objects from underlying *Enrichment(...) keys
    for ctx_key, value in merged_context.items():
        type_label: Optional[str] = None

        for _internal_type, type_cfg in INDICATOR_TYPE_CONFIG.items():
            prefix = type_cfg.get("enrichment_prefix")
            if prefix and ctx_key.startswith(prefix):
                type_label = type_cfg["display"]
                break

        if not type_label or value is None:
            continue

        items = value if isinstance(value, list) else [value]

        for item in items:
            if not isinstance(item, dict):
                continue
            obj = dict(item)
            obj["Type"] = type_label
            indicator_enrichment.append(obj)

    # Error objects for unsupported entries
    for indicator_type, value in sorted(
        unsupported_entries,
        key=lambda x: (x[0].lower(), x[1].lower()),
    ):
        indicator_enrichment.append(
            {
                "Type": indicator_type,
                "Value": value,
                "Message": "No script supports this indicator type.",
                "Status": "Error",
            }
        )

    # Error objects for unknown entries
    for value in sorted(unknown_entries, key=lambda v: v.lower()):
        indicator_enrichment.append(
            {
                "Type": "Unknown",
                "Value": value,
                "Message": "Not a valid indicator.",
                "Status": "Error",
            }
        )

    return indicator_enrichment


def build_final_context(
    merged_context: dict[str, Any],
    unsupported_entries: set[tuple[str, str]],
    unknown_entries: set[str],
    raw_context: bool,
) -> dict[str, Any]:
    """
    Build the final context for this script.

    Behavior:
        - Start from the full merged_context returned by child scripts (Core, EndpointData, DBotScore, *Enrichment, etc.).
        - Always build IndicatorEnrichment from the *Enrichment(...) keys and errors.
        - If raw_context is False:
            * Drop the raw *Enrichment(...) keys from this script's output context.
          If raw_context is True:
            * Keep the raw *Enrichment(...) keys as-is.
        - The resulting context for this entry is:
            child context keys (+/- raw enrichment lists) + IndicatorEnrichment.

    Args:
        merged_context: EntryContext/Contents merged from all child scripts.
        unsupported_entries: Unsupported indicators collected from input parsing.
        unknown_entries: Unknown/invalid indicators collected from input parsing.
        raw_context: Whether to preserve the raw *Enrichment(...) lists.

    Returns:
        A dict suitable for CommandResults.outputs containing:
            - Core, EndpointData, DBotScore, etc.
            - IndicatorEnrichment
            - Optionally *Enrichment(...) keys when raw_context=True.
    """
    # Start from everything children gave us
    final_context: dict[str, Any] = dict(merged_context) if merged_context else {}

    # Always build the aggregated IndicatorEnrichment list
    indicator_enrichment_list = build_indicator_enrichment_list(
        merged_context=merged_context,
        unsupported_entries=unsupported_entries,
        unknown_entries=unknown_entries,
    )

    # If raw_context is False: drop raw *Enrichment(...) keys from THIS script's context
    if not raw_context and final_context:
        keys_to_drop: list[str] = []
        for key in list(final_context.keys()):
            for type_cfg in INDICATOR_TYPE_CONFIG.values():
                prefix = type_cfg.get("enrichment_prefix")
                if prefix and key.startswith(prefix):
                    keys_to_drop.append(key)
                    break

        for key in keys_to_drop:
            demisto.debug(
                f"IndicatorEnrichment: removing raw enrichment context key '{key}' "
                f"from this script's output (raw_context=false)."
            )
            final_context.pop(key, None)

    # Add our aggregated IndicatorEnrichment view
    if indicator_enrichment_list:
        final_context["IndicatorEnrichment"] = indicator_enrichment_list

    return final_context


def build_readable_output(
    duplicates_count: int,
    underlying_sections: list[tuple[str, str]],
    unsupported_entries: set[tuple[str, str]],
    unknown_entries: set[str],
) -> str:
    """
    Build the markdown HumanReadable output for the command.

    Layout:
        - Optional note about deduplicated indicators.
        - Per-type sections:
              "### {DISPLAY} Final Results"
          followed by the underlying script's HumanReadable unchanged.
        - A final "Invalid or unsupported indicators" table when relevant.

    Args:
        duplicates_count: Number of duplicate indicator occurrences skipped.
        underlying_sections: list of (bucket_type, markdown HR) from child scripts.
        unsupported_entries: Unsupported indicators.
        unknown_entries: Unknown/invalid indicators.

    Returns:
        A markdown string for the War Room.
    """
    hr_parts: list[str] = []

    if duplicates_count > 0:
        hr_parts.append(f"Note: Removed {duplicates_count} duplicate indicator occurrences before enrichment.")

    # Nicely label each underlying HR section by type, using INDICATOR_TYPE_CONFIG["display"]
    for bucket_type, section_md in underlying_sections:
        if not section_md:
            continue

        type_cfg = INDICATOR_TYPE_CONFIG.get(bucket_type)
        pretty = type_cfg["command"] if type_cfg else bucket_type.upper()

        header = f"### {pretty}\n"
        hr_parts.append(f"{header}\n{section_md}")

    # Error table is always last
    error_rows = build_error_table(unsupported_entries, unknown_entries)
    if error_rows:
        error_table_md = tableToMarkdown(
            "Invalid or unsupported indicators",
            error_rows,
            headers=["Type", "Value", "Status", "Message"],
        )
        hr_parts.append(error_table_md)

    return "\n\n".join(hr_parts) if hr_parts else "No enrichment was performed."


# ===========================
# Main Command Implementation
# ===========================


def indicator_enrichment_command(args: dict[str, Any]) -> CommandResults:
    """
    Aggregated indicator enrichment over IP, URL, Domain, CVE and File.

    High-level flow:
        1. normalize_args:
            - Parse text, indicators_list, ignore_indicator_limit, raw_context.
        2. validate_initial_args:
            - Ensure at least text or indicators_list is provided.
        3. collect_indicators:
            - Extract from text (extractIndicators) and indicators_list (auto_detect_indicator_type).
            - Merge and deduplicate, filling:
                * supported_buckets
                * unsupported_entries
                * unknown_entries
                * duplicates_count
                * total_supported
        4. validate_collected_indicators:
            - For indicators_list-based invalid input, raise FatalArgException.
            - For text-only with no indicators, return a friendly informational result.
        5. enforce_indicator_limit:
            - If total_supported > MAX_INDICATORS and ignore_indicator_limit=false, raise FatalArgException.
        6. run_underlying_enrichment_scripts:
            - Execute ip/url/domain/cve/file enrichment in a single batch.
            - Collect HR sections and merged EntryContext.
        7. build_final_context:
            - Build IndicatorEnrichment list and apply raw_context behavior.
        8. build_readable_output:
            - Build the final markdown, including per-type sections and error table.

    Returns:
        CommandResults for the final indicator-enrichment command.
    """
    demisto.debug(f"IndicatorEnrichment called with args: {args}")

    # 1) Normalize args
    (
        text,
        indicators_list,
        indicators_list_provided,
        ignore_indicator_limit,
        raw_context,
    ) = normalize_args(args)

    # 2) Initial validation (may raise FatalArgException)
    validate_initial_args(text, indicators_list, indicators_list_provided)

    # 3) Extract + merge + dedup
    (
        supported_buckets,
        unsupported_entries,
        unknown_entries,
        duplicates_count,
        total_supported,
    ) = collect_indicators(text, indicators_list)

    # 4) Validate collected indicators (may raise FatalArgException, or return non-fatal CommandResults)
    collection_error_result = validate_collected_indicators(
        text=text,
        indicators_list=indicators_list,
        indicators_list_provided=indicators_list_provided,
        total_supported=total_supported,
        unsupported_entries=unsupported_entries,
        unknown_entries=unknown_entries,
    )
    if collection_error_result is not None:
        return collection_error_result

    # 5) Enforce indicator limit (may raise FatalArgException)
    enforce_indicator_limit(total_supported, ignore_indicator_limit)

    # 6) Execute underlying enrichment scripts
    underlying_sections: list[tuple[str, str]] = []
    merged_context: dict[str, Any] = {}
    if total_supported > 0:
        underlying_sections, merged_context = run_underlying_enrichment_scripts(supported_buckets, args)

    # 7) Build final context (IndicatorEnrichment + raw_context behavior)
    demisto.debug(f"The merged context is: {merged_context}")
    final_context = build_final_context(
        merged_context=merged_context,
        unsupported_entries=unsupported_entries,
        unknown_entries=unknown_entries,
        raw_context=raw_context,
    )

    # 8) Render HumanReadable
    readable_output = build_readable_output(
        duplicates_count=duplicates_count,
        underlying_sections=underlying_sections,
        unsupported_entries=unsupported_entries,
        unknown_entries=unknown_entries,
    )

    demisto.debug(f"The final context is: {final_context}")

    return CommandResults(
        readable_output=readable_output,
        outputs=final_context,
    )


def main():  # pragma: no cover
    """
    XSOAR entry point.
    - Wraps `indicator_enrichment_command`.
    - Converts FatalArgException into `return_error` with the exact message.
    - Converts any other unexpected exception into a generic failure message and logs the details.
    """
    try:
        args = demisto.args()
        result = indicator_enrichment_command(args)
        return_results(result)
    except FatalArgException as ex:
        demisto.debug(f"IndicatorEnrichment: FatalArgException - {str(ex)}")
        return_error(str(ex))
    except Exception as ex:
        demisto.error(f"IndicatorEnrichment: failed to execute. Error: {str(ex)}")
        return_error(f"Failed to execute !indicator-enrichment. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
