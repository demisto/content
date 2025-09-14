import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def url_enrichment_script(url_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False):
    """
    Enriches URL data with information from various integrations
    """
    url_list = extract_indicators(url_list, "url")

    indicator_mapping = {
        "Data": "Data",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
        "Brand": "Brand",
    }
    url_indicator = Indicator(
        type="url", value_field="Data", context_path_prefix="URL(", context_output_mapping=indicator_mapping
    )

    # wildfire_command = [
    #     Command(
    #         name="wildfire-get-verdict",
    #         args={"url": url_list},
    #         command_type=CommandType.INTERNAL,
    #         brand="WildFire-v2",
    #         context_output_mapping={
    #             "WildFire.Verdicts(val.url && val.url == obj.url)": "WildFire.Verdicts(val.url && val.url == obj.url)[]"
    #         },
    #         is_multi_input=True,
    #         is_aggregated_output=False,
    #     )
    # ]

    create_new_indicator_commands = [
        Command(
            name="CreateNewIndicatorsOnly",
            args={"indicator_values": url_list, "type": "URL"},
            command_type=CommandType.BUILTIN,
            context_output_mapping=None,
            ignore_using_brand=True,
        )
    ]
    enrich_indicator_commands = [
        Command(
            name="enrichIndicators",
            args={"indicatorsValues": url_list},
            command_type=CommandType.EXTERNAL,
        )
    ]

    commands = [create_new_indicator_commands, enrich_indicator_commands]

    url_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands,
        verbose=verbose,
        commands=commands,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="URLEnrichment",
        args=demisto.args(),
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
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    demisto.debug(f"Data list: {url_list}")
    demisto.debug(f"Brands: {brands}")

    try:
        return_results(url_enrichment_script(url_list, external_enrichment, verbose, brands, additional_fields))
    except Exception as ex:
        return_error(f"Failed to execute !url-enrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
