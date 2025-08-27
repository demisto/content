import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *

ENDPOINT_PATH = "EndpointData(val.Brand && val.Brand == obj.Brand && val.ID && val.ID == obj.ID && val.Hostname && val.Hostname == obj.Hostname)"  # noqa: E501


def validate_input_function(args):
    """
    Validates the input arguments.
    Args:
        args (dict[str, Any]): The arguments from `demisto.args()`.
    Raises:
        ValueError: If the input is invalid.
    """
    ip_list = argToList(args.get("ip_list"))
    if not ip_list:
        raise ValueError("ip_list is required")

    for ip in ip_list:
        if not is_ip_valid(ip, accept_v6_ips=True):
            raise ValueError(f"Invalid IP address: {ip}")


def ip_enrichment_script(
    ip_list,
    external_enrichment=False,
    verbose=False,
    enrichment_brands=None,
    additional_fields=False,
):
    """
    Enriches IP data with information from various integrations
    """
    indicator_mapping = {
        "Address": "Address",
        "Source": "Source",
        "ASOwner": "ASOwner",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
    }
    ip_indicator = Indicator(
        type="ip", value_field="Address", context_path_prefix="IP(", context_output_mapping=indicator_mapping
    )

    commands: list[Command] = [ReputationCommand(indicator=ip_indicator, data=data) for data in ip_list]
    commands.extend(
        [
            Command(
                name="get-endpoint-data",
                args={"endpoint_ip": ip_list},
                command_type=CommandType.INTERNAL,
                brand="Core",
                context_output_mapping={ENDPOINT_PATH: ENDPOINT_PATH},
            ),
            Command(
                name="core-get-IP-analytics-prevalence",
                args={"ip_address": ip_list},
                command_type=CommandType.INTERNAL,
                brand="Cortex Core - IR",
                context_output_mapping={"Core.AnalyticsPrevalence.Ip": "Core.AnalyticsPrevalence.Ip"},
            ),
        ]
    )

    ip_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands,
        verbose=verbose,
        commands=commands,
        validate_input_function=validate_input_function,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="IPEnrichment",
        args=demisto.args(),
        data=ip_list,
        indicator=ip_indicator,
    )
    return ip_reputation.run()


""" MAIN FUNCTION """


def main():
    args = demisto.args()
    ip_list = argToList(args.get("ip_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    demisto.debug(f"Data list: {ip_list}")
    demisto.debug(f"Brands: {brands}")

    try:
        return_results(ip_enrichment_script(ip_list, external_enrichment, verbose, brands, additional_fields))
    except Exception as ex:
        return_error(f"Failed to execute !ip-enrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
