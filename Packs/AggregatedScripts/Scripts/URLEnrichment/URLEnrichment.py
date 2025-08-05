import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def validate_input_function(args):
    if not args.get("url_list"):
        raise DemistoException("url_list is required")
    for url in args.get("url_list"):
        if auto_detect_indicator_type(url) != FeedIndicatorType.URL:
            raise DemistoException("URL is invalid")
            


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
    
    url_indicator = Indicator(indicator_type="url",
                              indicator_value_field="Data",
                              indicator_context_path="URL(",
                              indicator_mapping=indicator_mapping)
    
    commands = [ReputationCommand(indicator=url_indicator, data=data) for data in url_list]
    commands.append(
        Command(name="wildfire-get-verdict", args={"url": url_list}, command_type=CommandType.internal, brand="WildFire-v2", mapping={"WildFire.Verdicts(val.url && val.url == obj.url)":"WildFireVerdicts(val.url && val.url == obj.url)[]"})
    )
    urlreputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        validate_input_function=validate_input_function,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="URLEnrichment",
        args=demisto.args(),
        data=url_list,
        indicator=url_indicator,
    )
    return urlreputation.aggregated_command_main_loop()
    

""" MAIN FUNCTION """


def main():
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