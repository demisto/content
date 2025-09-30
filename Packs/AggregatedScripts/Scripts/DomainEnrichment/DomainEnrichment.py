import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def domain_enrichment_script(
    domain_list,
    external_enrichment: bool = False,
    verbose: bool = False,
    enrichment_brands: list[str] | None = None,
    additional_fields: bool = False,
) -> CommandResults:
    """
    Enriches Domain data with information from various integrations.

    Args:
        domain_list (list[str]): List of domains to enrich.
        external_enrichment (bool): Whether to perform external enrichment.
        verbose (bool): Whether to print verbose output.
        enrichment_brands (list[str]): List of brands to enrich.
        additional_fields (bool): Whether to include additional fields in the output.

    Returns:
        CommandResults: The results of the command.
    """
    demisto.debug("Extracting indicators")
    domain_list = extract_indicators(domain_list, "domain")
    demisto.debug(f"Data list after extract_indicators: {domain_list}")
    # Mapping for the final indicator objects (what you want to surface on each result)
    indicator_mapping = {
        "Name": "Name",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
        "Brand": "Brand",
    }

    domain_indicator = Indicator(
        type="domain",
        value_field="Name",
        context_path_prefix="Domain",
        context_output_mapping=indicator_mapping,
    )

    # --- Command Batch 1: create indicators (BUILTIN) ---
    demisto.debug("Command Batch 1: Creating new indicators")
    command_batch1: list[Command] = [
        Command(
            name="CreateNewIndicatorsOnly",
            args={"indicator_values": domain_list, "type": "Domain"},
            command_type=CommandType.BUILTIN,
            context_output_mapping=None,
            ignore_using_brand=True,
        )
    ]

    # --- Command Batch 2: internal analytics + external enrichment ---
    command_batch2: list[Command] = []
    if is_xsiam():
        demisto.debug("Command Batch 2: Internal commands (for XSIAM)")
        command_batch2.append(
            Command(
                name="core-get-domain-analytics-prevalence",
                args={"domain_name": domain_list},
                command_type=CommandType.INTERNAL,
                brand="Cortex Core - IR",  # keep the brand you use elsewhere
                context_output_mapping={"Core.AnalyticsPrevalence.Domain": "Core.AnalyticsPrevalence.Domain"},
            )
        )
    demisto.debug("Command Batch 2: Enriching indicators")
    command_batch2.append(
        Command(
            name="enrichIndicators",
            args={"indicatorsValues": domain_list},
            command_type=CommandType.EXTERNAL,
        )
    )

    # Important: commands are a list of *batches* (each batch is a list[Command])
    commands = [
        command_batch1,
        command_batch2,
    ]
    demisto.debug("Commands:")
    for i, batch in enumerate(commands):
        demisto.debug(f"Batch {i}")
        for j, cmd in enumerate(batch):
            demisto.debug(f"Command {j}: {cmd}")

    demisto.debug("Running ReputationAggregatedCommand")
    domain_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands or [],
        verbose=verbose,
        commands=commands,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="DomainEnrichment",
        args=demisto.args(),
        data=domain_list,
        indicator=domain_indicator,
    )
    return domain_reputation.run()


""" MAIN FUNCTION """


def main():  # pragma: no cover
    args = demisto.args()
    domain_list = argToList(args.get("domain_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    demisto.debug(f"Data list: {domain_list}")
    demisto.debug(f"Brands: {brands}")

    try:
        return_results(
            domain_enrichment_script(
                domain_list=domain_list,
                external_enrichment=external_enrichment,
                verbose=verbose,
                enrichment_brands=brands,
                additional_fields=additional_fields,
            )
        )
    except Exception as ex:
        return_error(f"Failed to execute !domain-enrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
