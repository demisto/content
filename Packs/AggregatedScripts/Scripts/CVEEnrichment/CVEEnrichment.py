import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def cve_enrichment_script(
    cve_list,
    external_enrichment: bool = False,
    verbose: bool = False,
    enrichment_brands: list[str] | None = None,
    additional_fields: bool = False,
) -> CommandResults:
    """
    Enriches CVE data with information from various integrations.

    Args:
        cve_list (list[str]): A list of CVEs to enrich.
        external_enrichment (bool, optional): Whether to call external integrations for enrichment. Defaults to False.
        verbose (bool, optional): Whether to retrieve a human-readable entry for every command.
        When set to false, human-readable will only summarize the final result and suppress error entries from commands.
        enrichment_brands (list[str], optional): A list of integration brands to run enrichment against. Defaults to None.
        additional_fields (bool, optional): When set to true, the output will also include an
        `AdditionalFields` object for each of the indicator result.

    Returns:
        CommandResults: The enriched CVE data.
    """
    cve_list = extract_indicators(cve_list, "cve")

    indicator_mapping = {
        "ID": "ID",
        "Brand": "Brand",
        "CVSS": "CVSS",
        "Description": "Description",
        "Published": "Published",
    }

    cve_indicator = Indicator(
        type="cve",
        value_field="ID",
        context_path_prefix="CVE(",  # add ( to prefix to distinct from CVESearch v2 integration context path
        context_output_mapping=indicator_mapping,
    )

    # --- Batch 1: create indicators (BUILTIN) ---
    create_new_indicator_commands = [
        Command(
            name="CreateNewIndicatorsOnly",
            args={"indicator_values": cve_list, "type": "CVE"},
            command_type=CommandType.BUILTIN,
            context_output_mapping=None,
            ignore_using_brand=True,  # never inject using-brand for server builtins
        )
    ]

    # --- Batch 2: external enrichment per CVE ---
    enrich_indicator_commands = [
        Command(
            name="enrichIndicators",
            args={"indicatorsValues": cve_list},
            command_type=CommandType.EXTERNAL,
        )
    ]

    # commands is a list of *batches* (each batch is list[Command])
    commands: list[list[Command]] = [
        create_new_indicator_commands,
        enrich_indicator_commands,
    ]

    cve_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands or [],
        verbose=verbose,
        commands=commands,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="CVEEnrichment",
        args=demisto.args(),
        data=cve_list,
        indicator=cve_indicator,
    )
    return cve_reputation.run()


""" MAIN FUNCTION """


def main():  # pragma: no cover
    args = demisto.args()
    cve_list = argToList(args.get("cve_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    demisto.debug(f"Data list: {cve_list}")
    demisto.debug(f"Brands: {brands}")

    try:
        return_results(
            cve_enrichment_script(
                cve_list=cve_list,
                external_enrichment=external_enrichment,
                verbose=verbose,
                enrichment_brands=brands,
                additional_fields=additional_fields,
            )
        )
    except Exception as ex:
        return_error(f"Failed to execute !cve-enrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
