import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def validate_input_function(args):
    """
    Validate the input arguments.
    """
    domain_list = argToList(args.get("domain_list"))
    if not domain_list:
        raise ValueError("domain_list is required")

    for domain in domain_list:
        if auto_detect_indicator_type(domain) != FeedIndicatorType.Domain:
            raise ValueError("Invalid domain name")


def domain_enrichment_script(
    domain_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False
):
    """
    Enriches Domain data with information from various integrations
    """
    indicator_mapping = {
        "Name": "Name",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
        "Brand": "Brand",
    }

    domain_indicator = Indicator(
        type="domain", value_field="Name", context_path_prefix="Domain(", context_output_mapping=indicator_mapping
    )

    commands: list[Command] = [ReputationCommand(indicator=domain_indicator, data=data) for data in domain_list]
    commands.extend(
        [
            Command(
                name="core-get-domain-analytics-prevalence",
                args={"domain_name": domain_list},
                command_type=CommandType.INTERNAL,
                brand="Cortex Core - IR",
                context_output_mapping={"Core.AnalyticsPrevalence.Domain": "Core.AnalyticsPrevalence.Domain"},
            )
        ]
    )

    demisto.debug(f"Data list: {domain_list}")
    domain_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands,
        verbose=verbose,
        commands=commands,
        validate_input_function=validate_input_function,
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
        return_results(domain_enrichment_script(domain_list, external_enrichment, verbose, brands, additional_fields))
    except Exception as ex:
        return_error(f"Failed to execute !domain-enrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
