import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def validate_input_function(args):
    """
    Validates the input arguments.
    Args:
        args (dict[str, Any]): The arguments from `demisto.args()`.
    Raises:
        ValueError: If the input is invalid.
    """
    url_list = argToList(args.get("url_list"))
    if not url_list:
        raise ValueError("url_list is required")
    for url in url_list:
        if auto_detect_indicator_type(url) != FeedIndicatorType.URL:
            raise ValueError(f"URL '{url}' is invalid")


def url_enrichment_script(url_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False):
    """
    Enriches URL data with information from various integrations
    """
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

    commands: list[Command] = [ReputationCommand(indicator=url_indicator, data=url) for url in url_list]
    commands.append(
        Command(
            name="wildfire-get-verdict",
            args={"url": url_list},
            command_type=CommandType.INTERNAL,
            brand="WildFire-v2",
            context_output_mapping={
                "WildFire.Verdicts(val.url && val.url == obj.url)": "WildFire.Verdicts(val.url && val.url == obj.url)[]"
            },
        )
    )
    url_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands,
        verbose=verbose,
        commands=commands,
        validate_input_function=validate_input_function,
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
        return_error(f"Failed to execute URLEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
