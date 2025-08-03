import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from enum import Enum
from AggregatedCommandApiModule import *




def ip_enrichment_script(
    ip_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False, indicator_type="url"
):
    """
    Enriches IP data with information from various integrations
    """
    indicator_mapping = {"Address":"Address",
                         "Source":"Source",
                         "ASOwner":"ASOwner",
                         "DetectionEngines":"DetectionEngines",
                         "PositiveDetections":"PositiveDetections",
    }
    commands = [ReputationCommand(name=indicator_type,args={indicator_type: data}, mapping=indicator_mapping, indicator_context_path="IP(") for data in ip_list]
    commands.extend([
        Command(name="get-endpoint-data", args={"endpoint_ip": ip_list}, command_type=CommandType.internal, brand="Scripts", mapping={"EndpointData":"EndpointData[]"}),
        Command(name="core-get-IP-analytics-prevalence", args={"ip_address": ip_list}, command_type=CommandType.internal, brand="Cortex Core - IR", mapping={"IPAnalyticsPrevalence":"IPAnalyticsPrevalence[]"})])
    ipreputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        indicator_type=indicator_type,
        indicator_value_field="Address",
        validate_input_function=lambda args: True,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="IPEnrichment",
        args=demisto.args(),
        data=ip_list,
        indicator_mapping=indicator_mapping,
        indicator_context_path="IP(",
    )
    return ipreputation.aggregated_command_main_loop()
    

""" MAIN FUNCTION """


def main():
    args = demisto.args()
    ip_list = argToList(args.get("ip_list"))
    indicator_type = "ip"
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    try:
        return_results(ip_enrichment_script(ip_list, external_enrichment, verbose, brands, additional_fields, indicator_type))
    except Exception as ex:
        return_error(f"Failed to execute IPEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()