import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *

# Context key used for Core endpoint data passthrough
ENDPOINT_PATH = (
    "EndpointData(val.Brand && val.Brand == obj.Brand && "
    "val.ID && val.ID == obj.ID && "
    "val.Hostname && val.Hostname == obj.Hostname)"
)


# Sub-timing keys that are breakdowns of the pipeline batch; shown as indented detail rows,
# NOT added to the total (they are already included in the pipeline elapsed time).
_SUB_TIMING_KEYS = {
    "CreateNewIndicatorsOnly (batch_find_existing_indicators + createNewIndicator)",
    "enrichIndicators + internal commands",
}


def _build_timing_hr(timings: dict[str, float], use_batch: bool) -> str:
    """
    Build a markdown timing summary table to prepend to the final HR output.

    Top-level keys (extractIndicators, enrichment pipeline) are summed for the total.
    Sub-timing keys (CreateNewIndicatorsOnly, enrichIndicators) are shown as breakdown
    rows indented with └ and are NOT added to the total (they are already included in
    the pipeline elapsed time).

    Args:
        timings: Dict of stage_name → elapsed_seconds.
        use_batch: Whether the optimised batch path was used.

    Returns:
        Markdown string with a timing table.
    """
    mode_label = "✅ Optimised (use_batch=true)" if use_batch else "⚠️ Legacy (use_batch=false)"
    rows: list[dict[str, str]] = []
    total = 0.0
    for stage, elapsed in timings.items():
        if stage in _SUB_TIMING_KEYS:
            rows.append({"Stage": f"  └ {stage}", "Time (s)": f"{elapsed:.2f}"})
        else:
            rows.append({"Stage": stage, "Time (s)": f"{elapsed:.2f}"})
            total += elapsed
    rows.append({"Stage": "**Total**", "Time (s)": f"**{total:.2f}**"})
    table = tableToMarkdown(
        f"⏱️ Enrichment Timing — {mode_label}",
        rows,
        headers=["Stage", "Time (s)"],
    )
    return table


def ip_enrichment_script(
    ip_list: list[str],
    external_enrichment: bool = False,
    verbose: bool = False,
    enrichment_brands: list[str] | None = None,
    additional_fields: bool = False,
    use_batch: bool = True,
    args: dict[str, Any] = {},
) -> CommandResults:
    """
    Enrich IP indicators.

    Args:
        ip_list: IPs to enrich.
        external_enrichment: If True, run external enrichment (or whenever brands are provided).
        verbose: If True, include human-readable outputs from executed commands.
        enrichment_brands: Specific brands to use (overrides external_enrichment routing).
        additional_fields: If True, keep unmapped fields from indicator contexts under "AdditionalFields".
        use_batch: If True (default), use the CRTX-231934 batch optimisations for extractIndicators
            and CreateNewIndicatorsOnly. If False, run the legacy serial path for comparison.

    Returns:
        CommandResults with aggregated context:
          - IPEnrichment(val.Value && val.Value == obj.Value): [...]
          - DBotScore: [...]
          - passthrough results (e.g., Core endpoint data, prevalence)
    """
    timings: dict[str, float] = {}

    demisto.debug(f"Extracting indicators from ip_list (count={len(ip_list)}): {ip_list}")
    demisto.debug(f"[MODE] use_batch={use_batch}")

    # --- Phase 1: Extract and validate indicators ---
    t0 = time.monotonic()
    # mark_mismatched_type_as_invalid=False: accept IPs that extractIndicators also classifies
    # as another type (e.g. Domain). Some valid public IPs are incorrectly rejected when True
    # because the server regex engine matches them as both IP and Domain simultaneously.
    # Since the caller explicitly requests IP enrichment, we accept any input that extracts
    # as IP regardless of co-extracted types. (CRTX-231934)
    ip_instances, extract_verbose = create_and_extract_indicators(
        ip_list, "ip", mark_mismatched_type_as_invalid=False, use_batch=use_batch
    )
    timings["extractIndicators"] = time.monotonic() - t0

    valid_inputs = [ip_instance.extracted_value for ip_instance in ip_instances if ip_instance.extracted_value]
    indicator_mapping = {
        "Address": "Address",
        "Source": "Source",
        "ASOwner": "ASOwner",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
    }

    ip_indicator_schema = IndicatorSchema(
        type="ip",
        value_field="Address",
        context_path_prefix="IP",
        context_output_mapping=indicator_mapping,
    )

    # --- Command Batch 1: create indicators (BUILTIN) ---
    demisto.debug("Command Batch 1: Creating new indicators")
    command_batch1: list[Command] = [
        Command(
            name="CreateNewIndicatorsOnly",
            # Pass use_batch through so CreateNewIndicatorsOnly uses the same mode.
            args={"indicator_values": valid_inputs, "type": "IP", "use_batch": str(use_batch).lower()},
            command_type=CommandType.BUILTIN,
            context_output_mapping=None,
            ignore_using_brand=True,
        )
    ]

    # --- Command Batch 2: external enrichment + internal commands ---
    private_ip_addresses = [
        private_ip_address for private_ip_address in valid_inputs if is_ip_address_internal(private_ip_address)
    ]
    demisto.debug(
        f"[IP_ROUTING] valid_inputs={len(valid_inputs)} "
        f"private={len(private_ip_addresses)} public={len(valid_inputs) - len(private_ip_addresses)} "
        f"external_enrichment={external_enrichment} "
        f"private_ips={private_ip_addresses} "
        f"public_ips={[ip for ip in valid_inputs if ip not in private_ip_addresses]}"
    )
    command_batch2: list[Command] = []
    demisto.debug("Command Batch 2: Internal commands")
    if private_ip_addresses:
        command_batch2.append(
            Command(
                name="get-endpoint-data",
                args={"endpoint_ip": private_ip_addresses},
                command_type=CommandType.INTERNAL,
                brand="Core",
                context_output_mapping={ENDPOINT_PATH: ENDPOINT_PATH},
            )
        )

    if is_xsiam():
        demisto.debug("Command Batch 2: Internal commands (for XSIAM)")
        command_batch2.append(
            Command(
                name="core-get-IP-analytics-prevalence",
                args={"ip_address": valid_inputs},
                command_type=CommandType.INTERNAL,
                brand="Cortex Core - IR",
                context_output_mapping={"Core.AnalyticsPrevalence.Ip": "Core.AnalyticsPrevalence.Ip"},
            )
        )

    demisto.debug("Command Batch 2: Enriching indicators")
    command_batch2.append(
        Command(
            name="enrichIndicators",
            args={"indicatorsValues": valid_inputs},
            command_type=CommandType.EXTERNAL,
        )
    )

    commands: list[list[Command]] = [
        command_batch1,
        command_batch2,
    ]
    demisto.debug("Commands: ")
    for i, batch in enumerate(commands):
        demisto.debug(f"Batch {i}")
        for j, cmd in enumerate(batch):
            demisto.debug(f"Command {j}: {cmd}")

    # --- Phase 2: Run enrichment pipeline (batches + TIM search + context build) ---
    t1 = time.monotonic()
    ip_enrichment = ReputationAggregatedCommand(
        brands=enrichment_brands or [],
        verbose=verbose,
        commands=commands,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="IPEnrichment",
        args=args,
        indicator_instances=ip_instances,
        indicator_schema=ip_indicator_schema,
        verbose_outputs=[extract_verbose],
    )
    result = ip_enrichment.run()
    timings["enrichment pipeline (batches + TIM + context)"] = time.monotonic() - t1

    # Pull per-batch timings exposed by ReputationAggregatedCommand.batch_timings.
    # batch 0 = CreateNewIndicatorsOnly; batch 1 = enrichIndicators + internal commands.
    # Only show sub-timing breakdown when use_batch=True (optimised path); in legacy mode
    # the labels are not meaningful (no batch_find_existing_indicators call).
    if use_batch:
        create_new_elapsed = ip_enrichment.batch_timings.get("CreateNewIndicatorsOnly", 0.0)
        enrich_elapsed = ip_enrichment.batch_timings.get(
            # batch 1 key is the first command in command_batch2; fall back to enrichIndicators
            next(
                (cmd.name for cmd in command_batch2),
                "enrichIndicators",
            ),
            0.0,
        )
        if create_new_elapsed:
            timings["CreateNewIndicatorsOnly (batch_find_existing_indicators + createNewIndicator)"] = create_new_elapsed
        if enrich_elapsed:
            timings["enrichIndicators + internal commands"] = enrich_elapsed

    # --- Prepend timing HR table to the result ---
    timing_hr = _build_timing_hr(timings, use_batch)
    existing_hr = result.readable_output or ""
    result.readable_output = timing_hr + "\n\n" + existing_hr if existing_hr else timing_hr
    return result


""" MAIN FUNCTION """


def main():
    args = demisto.args()
    ip_list = argToList(args.get("ip_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    # use_batch=true (default): CRTX-231934 batch optimisations active.
    # use_batch=false: legacy serial path — use for side-by-side performance comparison.
    use_batch = argToBoolean(args.get("use_batch", "true"))
    demisto.debug(f"Data list: {ip_list}")
    demisto.debug(f"Brands: {brands}")
    demisto.debug(f"use_batch: {use_batch}")

    try:
        return_results(ip_enrichment_script(ip_list, external_enrichment, verbose, brands, additional_fields, use_batch, args))
    except ValueError as ve:
        # Graceful response for validation failures (e.g. private IPs, unsupported types, no valid IPs).
        # Return HTTP 200 with structured error context instead of HTTP 500 so callers (e.g. AgentiX)
        # can distinguish a validation failure from a real server error and avoid futile retries.
        # (CRTX-231934)
        reason = str(ve)
        demisto.debug(f"!ip-enrichment validation failure (no valid indicators): {reason}")
        return_results(
            CommandResults(
                readable_output=f"No valid IP indicators found. {reason}",
                outputs={
                    "IPEnrichment(val.Value && val.Value == obj.Value)": [
                        {"Value": ip, "Status": "Error", "Message": reason} for ip in ip_list
                    ]
                },
            )
        )
    except Exception as ex:
        return_error(f"Failed to execute !ip-enrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
