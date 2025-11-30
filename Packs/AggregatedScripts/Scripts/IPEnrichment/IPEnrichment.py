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
    demisto.debug("Extracting indicators")
    ip_list = extract_indicators(ip_list, "ip")

    indicator_mapping = {
        "Address": "Address",
        "Source": "Source",
        "ASOwner": "ASOwner",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
    }

    ip_indicator = Indicator(
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
            args={"indicator_values": ip_list, "type": "IP"},
            command_type=CommandType.BUILTIN,
            context_output_mapping=None,
            ignore_using_brand=True,
        )
    ]

    # --- Command Batch 2: external enrichment + internal commands ---
    command_batch2: list[Command] = []
    demisto.debug("Command Batch 2: Internal commands")
    command_batch2.append(
        Command(
            name="get-endpoint-data",
            args={"endpoint_ip": ip_list},
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
                args={"ip_address": ip_list},
                command_type=CommandType.INTERNAL,
                brand="Cortex Core - IR",
                context_output_mapping={"Core.AnalyticsPrevalence.Ip": "Core.AnalyticsPrevalence.Ip"},
            )
        )

    demisto.debug("Command Batch 2: Enriching indicators")
    command_batch2.append(
        Command(
            name="enrichIndicators",
            args={"indicatorsValues": ip_list},
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
        data=ip_list,
        indicator=ip_indicator,
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
    except Exception as ex:
        return_error(f"Failed to execute !ip-enrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
