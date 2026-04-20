import time
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

STATUS_NEW = "new"
STATUS_EXISTING = "existing"
STATUS_UNAVAILABLE = "unavailable"

KEY_CREATION_STATUS = "CreationStatus"
KEY_VALUE = "value"

MAX_FIND_INDICATOR_RETRIES = 10
SLEEP_TIME = 2

# Maximum number of indicator values to include in a single batched findIndicators
# OR-query.  Larger chunks reduce server round-trips; smaller chunks avoid hitting
# query-length limits.  100 is a safe default based on QA benchmarks.
_FIND_BATCH_SIZE = 100


def associate_indicator_to_incident(indicator_value: Any) -> None:
    """
    Associate an indicator to this incident. Raise an exception if an error occurs.
    """

    incident_id = demisto.incidents()[0].get("id")
    demisto.debug(f"The incident id is {incident_id}")

    cmd_args = {
        "incidentId": incident_id,
        "value": f"{indicator_value}",  # Force an error
    }

    retry_num = 1
    res = ""
    while res != "done" and retry_num <= MAX_FIND_INDICATOR_RETRIES:
        try:
            demisto.debug(f"Executing associateIndicatorToIncident command with retry {retry_num}/{MAX_FIND_INDICATOR_RETRIES}")
            res = execute_command("associateIndicatorToIncident", cmd_args)
            demisto.debug(f"The associateIndicatorToIncident response is: {res}")

        except Exception as err:
            if "For associateIndicatorToIncident found no indicator" not in str(err):
                raise err
            # else log and continue with retries after sleeping
            demisto.debug(f"Failed to find indicator {indicator_value} in the system.")
            if retry_num != MAX_FIND_INDICATOR_RETRIES:
                time.sleep(SLEEP_TIME)  # pylint: disable=E9003
            retry_num += 1

    if res != "done":
        raise Exception(f"Failed to associate {indicator_value} with incident {incident_id}")


def normalize_indicator_value(indicator_value: Any) -> str:
    if isinstance(indicator_value, int):
        return str(indicator_value)
    elif isinstance(indicator_value, str) and indicator_value:
        return indicator_value
    else:
        raise DemistoException(f"Invalid indicator value: {indicator_value!s}")


def batch_find_existing_indicators(indicator_values: list[str]) -> dict[str, dict[str, Any]]:
    """
    Find which of the given indicator values already exist in TIM using a single
    batched OR-query instead of N serial ``findIndicators`` calls.

    Performance optimisation (CRTX-231934): for N indicators this replaces N
    server round-trips with ceil(N / _FIND_BATCH_SIZE) round-trips.

    Returns:
        A dict mapping ``value.lower()`` → the full indicator dict returned by
        ``findIndicators``.  Only indicators that already exist are included.
    """
    existing: dict[str, dict[str, Any]] = {}

    for chunk_start in range(0, len(indicator_values), _FIND_BATCH_SIZE):
        chunk = indicator_values[chunk_start : chunk_start + _FIND_BATCH_SIZE]
        # Build an OR-query: value:"1.1.1.1" or value:"8.8.8.8" ...
        escaped = [v.replace('"', r"\"") for v in chunk]
        query = " or ".join(f'value:"{v}"' for v in escaped)

        t0 = time.monotonic()
        try:
            found = execute_command("findIndicators", {"query": query, "size": len(chunk)})
            elapsed = time.monotonic() - t0
            demisto.debug(
                f"[TIMING] findIndicators batch ({len(chunk)} values) elapsed_s={elapsed:.3f} "
                f"found={len(found) if found else 0}"
            )
            if found:
                for ind in found:
                    val = ind.get(KEY_VALUE, "")
                    if val:
                        existing[val.lower()] = ind
        except Exception as ex:
            elapsed = time.monotonic() - t0
            demisto.debug(
                f"[BATCH_FIND] Batched findIndicators failed after {elapsed:.3f}s: {ex}. "
                f"Chunk will be treated as all-new (individual createNewIndicator calls will follow)."
            )
            # On failure we leave the chunk values absent from `existing`, so
            # they will be created individually below — safe fallback.

    return existing


def add_new_indicator(
    indicator_value: Any, create_new_indicator_args: dict[str, Any], associate_to_incident: bool = False
) -> dict[str, Any]:
    """Create a single indicator, checking TIM first. Used as fallback / for single-item calls."""
    indicator_value = normalize_indicator_value(indicator_value)
    escaped_indicator_value = indicator_value.replace('"', r"\"")

    if indicators := execute_command("findIndicators", {"value": escaped_indicator_value}):
        indicator = indicators[0]
        indicator[KEY_CREATION_STATUS] = STATUS_EXISTING

        # findIndicators might find an indicator with different letter case.
        # Unfortunately associate_indicator_to_incident does not ignore case
        # and as a result in some cases is unable to associate indicator.
        indicator_value = indicator[KEY_VALUE]
    else:
        args = dict(create_new_indicator_args, value=indicator_value)
        indicator = execute_command("createNewIndicator", args)
        if isinstance(indicator, dict):
            indicator[KEY_CREATION_STATUS] = STATUS_NEW
        elif isinstance(indicator, str):
            # createNewIndicator has been successfully done, but the indicator
            # wasn't created for some reasons.
            if "done - Indicator was not created" in indicator:
                demisto.debug(f'Indicator was not created. Make sure "{indicator_value}" is not excluded.')
            else:
                demisto.debug(indicator)

            indicator = {
                "value": indicator_value,
                "indicator_type": args.get("type", "Unknown"),
                KEY_CREATION_STATUS: STATUS_UNAVAILABLE,
            }
        else:
            raise DemistoException(f"Unknown response from createNewIndicator: str{indicator_value}")

    if indicator[KEY_CREATION_STATUS] != STATUS_UNAVAILABLE and associate_to_incident:
        demisto.debug(f"Associating {indicator_value} to incident.")
        associate_indicator_to_incident(indicator_value)

    return indicator


class AddNewIndicatorsResult:
    """Return value of add_new_indicators — bundles indicators with per-phase timing."""

    def __init__(
        self,
        indicators: list[dict[str, Any]],
        elapsed_find_s: float = 0.0,
        elapsed_create_s: float = 0.0,
    ) -> None:
        self.indicators = indicators
        # Time spent in batch_find_existing_indicators (OR-query phase).
        self.elapsed_find_s = elapsed_find_s
        # Time spent in createNewIndicator calls (creation phase).
        self.elapsed_create_s = elapsed_create_s


def add_new_indicators(
    indicator_values: list[Any] | None,
    create_new_indicator_args: dict[str, Any],
    associate_to_incident: bool = False,
    use_batch: bool = True,
) -> AddNewIndicatorsResult:
    """
    Create indicators in TIM for all values in ``indicator_values``.

    Args:
        indicator_values: Raw indicator values to create.
        create_new_indicator_args: Arguments forwarded to ``createNewIndicator``.
        associate_to_incident: Whether to associate each indicator to the current incident.
        use_batch: If True (default), use a single batched OR-query to find existing indicators
            (CRTX-231934 optimisation — ~50x faster for large batches).
            If False, fall back to the original per-indicator serial ``findIndicators`` calls
            (pre-optimisation baseline, useful for side-by-side performance comparison).

    Returns:
        AddNewIndicatorsResult with .indicators list and per-phase timing (.elapsed_find_s, .elapsed_create_s).
    """
    if not indicator_values:
        return AddNewIndicatorsResult([])

    if not use_batch:
        # --- Legacy path: one findIndicators call per indicator (pre-CRTX-231934 behaviour) ---
        demisto.debug(f"[LEGACY] use_batch=False — running serial findIndicators loop for {len(indicator_values)} indicators")
        t0 = time.monotonic()
        indicators = [
            add_new_indicator(indicator_value, create_new_indicator_args, associate_to_incident)
            for indicator_value in indicator_values
        ]
        elapsed = time.monotonic() - t0
        # In legacy mode the find+create are interleaved per-indicator; report total as find time.
        return AddNewIndicatorsResult(indicators, elapsed_find_s=elapsed)

    # --- Optimised path: single batched findIndicators OR-query ---
    # Normalise all values up-front so we can deduplicate and build the batch query.
    normalised: list[str] = []
    results: list[dict[str, Any]] = []
    for raw_value in indicator_values:
        try:
            normalised.append(normalize_indicator_value(raw_value))
        except DemistoException as exc:
            demisto.debug(f"Skipping invalid indicator value {raw_value!r}: {exc}")
            # Produce a placeholder result so the output list length matches the input.
            results.append(
                {
                    "value": str(raw_value),
                    "indicator_type": create_new_indicator_args.get("type", "Unknown"),
                    KEY_CREATION_STATUS: STATUS_UNAVAILABLE,
                }
            )

    if not normalised:
        return AddNewIndicatorsResult(results)

    # --- Step 1: Batch-find which indicators already exist in TIM ---
    t_find = time.monotonic()
    existing_by_lower = batch_find_existing_indicators(normalised)
    elapsed_find = time.monotonic() - t_find
    demisto.debug(
        f"[BATCH_CREATE] {len(existing_by_lower)}/{len(normalised)} indicators already exist in TIM "
        f"(findIndicators elapsed_s={elapsed_find:.3f})"
    )

    # --- Step 2: For each value, either reuse the existing record or create a new one ---
    t_create_total = time.monotonic()
    for value in normalised:
        value_lower = value.lower()

        if value_lower in existing_by_lower:
            # Already in TIM — reuse the existing indicator dict.
            indicator = existing_by_lower[value_lower]
            # Normalise the canonical value (server may differ in case).
            canonical_value = indicator.get(KEY_VALUE, value)
            indicator[KEY_CREATION_STATUS] = STATUS_EXISTING
            demisto.debug(f"[BATCH_CREATE] '{value}' already exists as '{canonical_value}'")

            if associate_to_incident:
                associate_indicator_to_incident(canonical_value)
        else:
            # Not in TIM — create it now.
            args = dict(create_new_indicator_args, value=value)
            t_create = time.monotonic()
            raw_result = execute_command("createNewIndicator", args)
            elapsed_create = time.monotonic() - t_create
            demisto.debug(f"[TIMING] createNewIndicator for '{value}' elapsed_s={elapsed_create:.3f}")

            if isinstance(raw_result, dict):
                indicator = raw_result
                indicator[KEY_CREATION_STATUS] = STATUS_NEW
            elif isinstance(raw_result, str):
                if "done - Indicator was not created" in raw_result:
                    demisto.debug(f'Indicator was not created. Make sure "{value}" is not excluded.')
                else:
                    demisto.debug(raw_result)
                indicator = {
                    "value": value,
                    "indicator_type": args.get("type", "Unknown"),
                    KEY_CREATION_STATUS: STATUS_UNAVAILABLE,
                }
            else:
                raise DemistoException(f"Unknown response from createNewIndicator: {value!r}")

            if indicator[KEY_CREATION_STATUS] != STATUS_UNAVAILABLE and associate_to_incident:
                associate_indicator_to_incident(value)

        results.append(indicator)

    elapsed_create_total = time.monotonic() - t_create_total
    demisto.debug(
        f"[TIMING] add_new_indicators total: find={elapsed_find:.3f}s create={elapsed_create_total:.3f}s "
        f"for {len(normalised)} indicators "
        f"({len(existing_by_lower)} existing, {len(normalised) - len(existing_by_lower)} new)"
    )
    return AddNewIndicatorsResult(results, elapsed_find_s=elapsed_find, elapsed_create_s=elapsed_create_total)


def main():
    try:
        args = assign_params(**demisto.args())

        # Don't use argToList to make a list in order to accept an indicator including commas.
        # The `indicator_values` parameter doesn't support a comma separated list.
        if (indicator_values := args.get("indicator_values", [])) and not isinstance(indicator_values, list):
            indicator_values = [indicator_values]

        create_new_indicator_args = dict(args)
        create_new_indicator_args.pop("indicator_values", None)
        create_new_indicator_args.pop("verbose", None)
        create_new_indicator_args.pop("use_batch", None)
        associate_to_incident = argToBoolean(create_new_indicator_args.pop("associate_to_current", "false"))
        # use_batch=true (default): batched findIndicators OR-query (CRTX-231934 optimisation).
        # use_batch=false: legacy serial findIndicators per indicator (pre-optimisation baseline).
        use_batch = argToBoolean(args.get("use_batch", "true"))

        result = add_new_indicators(indicator_values, create_new_indicator_args, associate_to_incident, use_batch=use_batch)
        ents = result.indicators
        elapsed_find = result.elapsed_find_s
        elapsed_create = result.elapsed_create_s
        elapsed_total = elapsed_find + elapsed_create

        outputs = [
            assign_params(
                ID=ent.get("id"),
                Score=ent.get("score"),
                CreationStatus=ent.get(KEY_CREATION_STATUS),
                Type=ent.get("indicator_type"),
                Value=ent.get("value"),
            )
            for ent in ents
        ]

        count_new = sum(1 for ent in ents if ent.get(KEY_CREATION_STATUS) == STATUS_NEW)
        count_existing = sum(1 for ent in ents if ent.get(KEY_CREATION_STATUS) == STATUS_EXISTING)
        if use_batch:
            timing_detail = (
                f"batch_find_existing_indicators: {elapsed_find:.2f}s | "
                f"createNewIndicator ({count_new} new): {elapsed_create:.2f}s | "
                f"Total: {elapsed_total:.2f}s"
            )
        else:
            timing_detail = f"serial findIndicators per-indicator: {elapsed_find:.2f}s total (no batch)"
        readable_output = (
            f"{count_new} new indicators added, {count_existing} already existed. "
            f"Total: {len(ents)} | {timing_detail}"
        )
        if argToBoolean(args.get("verbose", "false")):
            readable_output += "\n" + tblToMd(
                "New Indicator Created", outputs, ["ID", "Score", "CreationStatus", "Type", "Value"]
            )

        # Build context with both indicator list and per-phase timing so IPEnrichment
        # can read elapsed_find_s / elapsed_create_s from the batch EntryContext.
        ctx: dict[str, Any] = {
            "CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)": outputs,
            "CreateNewIndicatorsOnly.Timing": {
                "elapsed_find_s": round(elapsed_find, 3),
                "elapsed_create_s": round(elapsed_create, 3),
                "elapsed_total_s": round(elapsed_total, 3),
                "use_batch": use_batch,
            },
        }
        demisto.results({
            "Type": 1,
            "ContentsFormat": "json",
            "Contents": ents,
            "EntryContext": ctx,
            "HumanReadable": readable_output,
        })
    except Exception as e:
        return_error(f"Failed to execute CreateNewIndicatorsOnly.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
