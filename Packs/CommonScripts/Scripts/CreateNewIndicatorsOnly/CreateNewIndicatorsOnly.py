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


def add_new_indicators(
    indicator_values: list[Any] | None, create_new_indicator_args: dict[str, Any], associate_to_incident: bool = False
) -> list[dict[str, Any]]:
    """
    Create indicators in TIM for all values in ``indicator_values``.

    **Performance optimisation (CRTX-231934)**: Instead of calling
    ``findIndicators`` once per value (N serial round-trips), we issue a single
    batched OR-query to discover which values already exist, then only call
    ``createNewIndicator`` for the genuinely new ones.

    For N=100 indicators this reduces ~200 serial server calls to
    ~2 calls (1 batch find + 1 batch create for new ones).
    """
    if not indicator_values:
        return []

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
        return results

    t_total = time.monotonic()

    # --- Step 1: Batch-find which indicators already exist in TIM ---
    existing_by_lower = batch_find_existing_indicators(normalised)
    demisto.debug(
        f"[BATCH_CREATE] {len(existing_by_lower)}/{len(normalised)} indicators already exist in TIM"
    )

    # --- Step 2: For each value, either reuse the existing record or create a new one ---
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

    elapsed_total = time.monotonic() - t_total
    demisto.debug(
        f"[TIMING] add_new_indicators total elapsed_s={elapsed_total:.3f} "
        f"for {len(normalised)} indicators "
        f"({len(existing_by_lower)} existing, {len(normalised) - len(existing_by_lower)} new)"
    )
    return results


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
        associate_to_incident = argToBoolean(create_new_indicator_args.pop("associate_to_current", "false"))
        ents = add_new_indicators(indicator_values, create_new_indicator_args, associate_to_incident)

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
        readable_output = f"{count_new} new indicators have been added."
        if argToBoolean(args.get("verbose", "false")):
            readable_output += "\n" + tblToMd(
                "New Indicator Created", outputs, ["ID", "Score", "CreationStatus", "Type", "Value"]
            )

        return_results(
            CommandResults(
                outputs_prefix="CreateNewIndicatorsOnly",
                outputs_key_field=["Value", "Type"],
                outputs=outputs,
                raw_response=ents,
                readable_output=readable_output,
            )
        )
    except Exception as e:
        return_error(f"Failed to execute CreateNewIndicatorsOnly.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
