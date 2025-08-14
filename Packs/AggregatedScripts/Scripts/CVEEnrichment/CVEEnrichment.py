import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *

def validate_input_function(args):
    cve_list = argToList(args.get("cve_list"))
    if not cve_list:
        raise ValueError("cve_list is required")
    for cve in cve_list:
        if auto_detect_indicator_type(cve) != FeedIndicatorType.CVE:
            raise ValueError(f"Invalid CVE ID: {cve}")

def cve_enrichment_script(
    cve_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False
):
    """
    Enriches CVE data with information from various integrations
    """
    indicator_mapping = {"ID":"ID",
                         "Brand":"Brand",
                         "CVSS":"CVSS",
                         "Description":"Description",
                         "Published":"Published"}
    
    cve_indicator = Indicator(type="cve",
                              value_field="ID",
                              context_path_prefix="CVE(",
                              context_output_mapping=indicator_mapping)
    
    commands = [ReputationCommand(indicator=cve_indicator, data=data) for data in cve_list]
    cve_reputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        validate_input_function=validate_input_function,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="CVEEnrichment(val.ID && val.ID == obj.ID)",
        args=demisto.args(),
        data=cve_list,
        indicator=cve_indicator,
    )
    return cve_reputation.run()
    

""" MAIN FUNCTION """


def main(): # pragma: no cover
    args = demisto.args()
    cve_list = argToList(args.get("cve_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    demisto.debug(f"Data list: {cve_list}")
    demisto.debug(f"Brands: {brands}")
    
    try:
        return_results(cve_enrichment_script(cve_list, external_enrichment, verbose, brands, additional_fields))
    except Exception as ex:
        return_error(f"Failed to execute CVEEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()