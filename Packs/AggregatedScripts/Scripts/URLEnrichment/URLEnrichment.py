import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def url_enrichment_script(
    url_list: list[str],
    external_enrichment: bool = False,
    verbose: bool = False,
    enrichment_brands: list[str] = [],
    additional_fields: bool = False,
    args: dict[str, Any] = {},
) -> CommandResults:
    """
    Enriches URL data with information from various integrations
    Args:
        url_list (list[str]): List of URLs to enrich.
        external_enrichment (bool): Whether to call external integrations for enrichment.
        verbose (bool): Whether to print verbose output.
        enrichment_brands (list[str]): List of brands to enrich with.
        additional_fields (bool): Whether to include additional fields in the output.
    Returns:
        CommandResult: The result of the command.
    """
    demisto.debug("Extracting indicators")
    url_list = extract_indicators(url_list, "url")

    indicator_mapping = {
        "Data": "Data",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
        "Brand": "Brand",
    }
    url_indicator = Indicator(
        type="url",
        value_field="Data",
        context_path_prefix="URL(",  # add ( to prefix to distinct from URLhaus integration context path
        context_output_mapping=indicator_mapping,
    )

    # --- Command Batch 1: create indicators (BUILTIN) ---
    demisto.debug("Creating commands - Batch 1: Creating new indicators")
    command_batch1: list[Command] = [
        Command(
            name="CreateNewIndicatorsOnly",
            args={"indicator_values": url_list, "type": "URL"},
            command_type=CommandType.BUILTIN,
            context_output_mapping=None,
            ignore_using_brand=True,
        )
    ]

    # --- Command Batch 2: external enrichment ---
    demisto.debug("Creating commands - Batch 2: Enriching indicators")
    command_batch2: list[Command] = [
        Command(
            name="enrichIndicators",
            args={"indicatorsValues": url_list},
            command_type=CommandType.EXTERNAL,
        )
    ]

    commands = [command_batch1, command_batch2]
    demisto.debug("Commands: ")
    for i, batch in enumerate(commands):
        demisto.debug(f"Batch {i}")
        for j, cmd in enumerate(batch):
            demisto.debug(f"Command {j}: {cmd}")

    url_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands,
        verbose=verbose,
        commands=commands,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="URLEnrichment",
        args=args,
        data=url_list,
        indicator=url_indicator,
    )
    return url_reputation.run()


""" MAIN FUNCTION """


def main():  # pragma: no cover
    args = demisto.args()
    url_list = argToList(args.get("url_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands", []))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    demisto.debug(f"Data list: {url_list}")
    demisto.debug(f"Brands: {brands}")
    try:
        return_results(url_enrichment_script(url_list, external_enrichment, verbose, brands, additional_fields, args))
    except Exception as ex:
        return_error(f"Failed to execute !url-enrichment. Error: {str(ex)}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
