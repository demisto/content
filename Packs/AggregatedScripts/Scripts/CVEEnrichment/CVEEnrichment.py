import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *

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
    
    cve_indicator = Indicator(indicator_type="cve",
                              indicator_value_field="ID",
                              indicator_context_path="CVE(",
                              indicator_mapping=indicator_mapping)
    
    commands = [ReputationCommand(indicator=cve_indicator, data=data) for data in cve_list]
    cve_reputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        validate_input_function=lambda args: True,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="CVEEnrichment",
        args=demisto.args(),
        data=cve_list,
        indicator=cve_indicator,
    )
    return cve_reputation.aggregated_command_main_loop()
    

""" MAIN FUNCTION """


def main():
    args = demisto.args()
    cve_list = argToList(args.get("cve_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    try:
        return_results(cve_enrichment_script(cve_list, external_enrichment, verbose, brands, additional_fields))
    except Exception as ex:
        return_error(f"Failed to execute CVEEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()