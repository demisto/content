import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def validate_input_function(args):
    url_list = argToList(args.get("url_list"))
    if not url_list:
        raise DemistoException("url_list is required")
    for url in url_list:
        if auto_detect_indicator_type(url) != FeedIndicatorType.URL:
            raise DemistoException(f"URL '{url}' is invalid")
            


def url_enrichment_script(
    url_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False
):
    """
    Enriches URL data with information from various integrations
    """
    indicator_mapping = {"Data":"Data",
                        "DetectionEngines":"DetectionEngines",
                        "PositiveDetections":"PositiveDetections",
                        "Score":"Score",
                        "Brand":"Brand"}
    
    url_indicator = Indicator(type="url",
                              value_field="Data",
                              context_path_prefix="URL(",
                              mapping=indicator_mapping)
    
    commands = [ReputationCommand(indicator=url_indicator, data=url) for url in url_list]
    commands.append(
        Command(name="wildfire-get-verdict", args={"url": url_list}, command_type=CommandType.INTERNAL, brand="WildFire-v2", mapping={"WildFire.Verdicts(val.url && val.url == obj.url)":"WildFireVerdicts(val.url && val.url == obj.url)[]"})
    )
    urlreputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        validate_input_function=validate_input_function,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path=f"URLEnrichment(val.{url_indicator.value_field} && val.{url_indicator.value_field} == obj.{url_indicator.value_field})",
        args=demisto.args(),
        data=url_list,
        indicator=url_indicator,
    )
    return urlreputation.aggregated_command_main_loop()
    

""" MAIN FUNCTION """


def main(): # pragma: no cover
    args = demisto.args()
    url_list = argToList(args.get("url_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    try:
        return_results(url_enrichment_script(url_list, external_enrichment, verbose, brands, additional_fields))
    except Exception as ex:
        return_error(f"Failed to execute URLEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()