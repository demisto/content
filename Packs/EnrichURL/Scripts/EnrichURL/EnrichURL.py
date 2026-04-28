import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def url_enrichment_script(
    url_list: list[str],
    external_enrichment: bool = False,
    verbose: bool = False,
    enrichment_brands: list[str] | None = None,
    additional_fields: bool = False,
    args: dict[str, Any] = {},
) -> CommandResults | None:
    """
    Enrich URL indicators using batch validation.

    Args:
        url_list: URLs to enrich.
        external_enrichment: If True, run external enrichment (or whenever brands are provided).
        verbose: If True, include human-readable outputs from executed commands.
        enrichment_brands: Specific brands to use (overrides external_enrichment routing).
        additional_fields: If True, keep unmapped fields from indicator contexts under "AdditionalFields".
        args: The original demisto.args() dict.

    Returns:
        CommandResults with aggregated context, or None if no valid indicators were found
        (a human-readable message is returned via return_results in that case):
          - URLEnrichment(val.Value && val.Value == obj.Value): [...]
          - DBotScore: [...]
          - passthrough results from external enrichment
    """
    demisto.debug("Extracting indicators using batch validation")
    valid_inputs = create_and_extract_indicators_batch(url_list, "URL")

    if not valid_inputs:
        demisto.debug("No valid URL indicators found in the provided input.")
        return_results(CommandResults(readable_output="No valid URL indicators were found in the provided input."))
        return None

    demisto.debug(f"Found {len(valid_inputs)} valid URL indicator(s): {valid_inputs}")

    # Build IndicatorInstance objects from the validated inputs
    url_instances = [IndicatorInstance(raw_input=url, extracted_value=url) for url in valid_inputs]

    indicator_mapping = {
        "Data": "Data",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
        "Brand": "Brand",
    }

    url_indicator_schema = IndicatorSchema(
        type="url",
        value_field="Data",
        context_path_prefix="URL(",  # add ( to prefix to distinct from URLhaus integration context path
        context_output_mapping=indicator_mapping,
    )

    # --- Command Batch 1: create indicators (BUILTIN) ---
    demisto.debug("Command Batch 1: Creating new indicators")
    command_batch1: list[Command] = [
        Command(
            name="CreateNewIndicatorsOnly",
            args={"indicator_values": valid_inputs, "type": "URL"},
            command_type=CommandType.BUILTIN,
            context_output_mapping=None,
            ignore_using_brand=True,
        )
    ]

    # --- Command Batch 2: external enrichment ---
    demisto.debug("Command Batch 2: Enriching indicators")
    command_batch2: list[Command] = [
        Command(
            name="enrichIndicators",
            args={"indicatorsValues": valid_inputs},
            command_type=CommandType.EXTERNAL,
        )
    ]

    commands: list[list[Command]] = [
        command_batch1,
        command_batch2,
    ]
    demisto.debug("Commands: ")
    for i, batch in enumerate(commands):
        demisto.debug(f"Batch {i}")
        for j, cmd in enumerate(batch):
            demisto.debug(f"Command {j}: {cmd}")

    url_enrichment = ReputationAggregatedCommand(
        brands=enrichment_brands or [],
        verbose=verbose,
        commands=commands,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="URLEnrichment",
        args=args,
        indicator_instances=url_instances,
        indicator_schema=url_indicator_schema,
    )
    return url_enrichment.run()


""" MAIN FUNCTION """


def main():
    args = demisto.args()
    url_list = argToList(args.get("url_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    demisto.debug(f"Data list: {url_list}")
    demisto.debug(f"Brands: {brands}")

    try:
        result = url_enrichment_script(url_list, external_enrichment, verbose, brands, additional_fields, args)
        if result is not None:
            return_results(result)
    except Exception as ex:
        return_error(f"Failed to execute !url-enrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
