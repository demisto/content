import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def validate_input_function(args):
    ip_list = argToList(args.get("ip_list"))
    if not ip_list:
        raise DemistoException("ip_list is required")
    for ip in ip_list:
        if not is_ip_valid(ip,accept_v6_ips=True):
            raise DemistoException("Invalid IP address")
            

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
    ip_indicator = Indicator(type="ip",
                             value_field="Address",
                             context_path="IP(",
                             mapping=indicator_mapping)
    
    commands = [ReputationCommand(indicator=ip_indicator, data=data) for data in ip_list]
    commands.extend([
        Command(name="get-endpoint-data", args={"endpoint_ip": ip_list}, command_type=CommandType.INTERNAL, brand="Scripts", mapping={"EndpointData(val.Brand && val.Brand == obj.Brand && val.ID && val.ID == obj.ID && val.Hostname && val.Hostname == obj.Hostname)":"EndpointData(val.Brand && val.Brand == obj.Brand && val.ID && val.ID == obj.ID && val.Hostname && val.Hostname == obj.Hostname)"}),
        Command(name="core-get-IP-analytics-prevalence", args={"ip_address": ip_list}, command_type=CommandType.INTERNAL, brand="Cortex Core - IR", mapping={"IPAnalyticsPrevalence":"IPAnalyticsPrevalence[]"})])
    ipreputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        validate_input_function=validate_input_function,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="IPEnrichment(val.Address && val.Address == obj.Address)",
        args=demisto.args(),
        data=ip_list,
        indicator=ip_indicator,
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