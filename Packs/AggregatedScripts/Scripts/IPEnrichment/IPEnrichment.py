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


def ip_enrichment_script(
    ip_list: list[str],
    external_enrichment: bool = False,
    verbose: bool = False,
    enrichment_brands: list[str] | None = None,
    additional_fields: bool = False,
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

    Returns:
        CommandResults with aggregated context:
          - IPEnrichment(val.Value && val.Value == obj.Value): [...]
          - DBotScore: [...]
          - passthrough results (e.g., Core endpoint data, prevalence)
    """
    demisto.debug(f"Extracting indicators from ip_list (count={len(ip_list)}): {ip_list}")
    # mark_mismatched_type_as_invalid=False: accept IPs that extractIndicators also classifies
    # as another type (e.g. Domain). Some valid public IPs are incorrectly rejected when True
    # because the server regex engine matches them as both IP and Domain simultaneously.
    # Since the caller explicitly requests IP enrichment, we accept any input that extracts
    # as IP regardless of co-extracted types. (CRTX-231934)
    ip_instances, extract_verbose = create_and_extract_indicators(ip_list, "ip", mark_mismatched_type_as_invalid=False)
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
            args={"indicator_values": valid_inputs, "type": "IP"},
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
    return ip_enrichment.run()


""" MAIN FUNCTION """


def main():
    args = demisto.args()
    ip_list = argToList(args.get("ip_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    demisto.debug(f"Data list: {ip_list}")
    demisto.debug(f"Brands: {brands}")

    try:
        return_results(ip_enrichment_script(ip_list, external_enrichment, verbose, brands, additional_fields, args))
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
