import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import socket
from ipaddress import ip_network, ip_address
import traceback
import re

PRIVATE_SUBNETS = [
    '172.16.0.0/12',
    '10.0.0.0/8',
    '198.18.0.0/15',
    '192.168.0.0/16',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '192.0.0.0/24',
    '0.0.0.0/8',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '255.255.255.255/32'
]


def get_tim_indicator_hr(indicator: dict) -> str:
    # return specific information for found indicators
    # todo - handle a case of an empty indicator
    fields = ['id', 'indicator_type', 'value','score']  # todo: which fields to return? maybe another command should be used per Yarden

    styled_indicator = {}
    for field in fields:
        styled_indicator[field] = indicator.get(field, indicator.get("CustomFields", {}).get(field, "n/a"))
    styled_indicator["verdict"] = scoreToReputation(styled_indicator['score'])
    headers = fields + ["verdict"]
    hr = tableToMarkdown("IP Enrichment- indicator data from TIM", styled_indicator, headers)
    return hr


class ModuleManager:
    def __init__(self, modules: dict[str, Any]) -> None:
        """Initialize ModuleManager."""
        self.modules = modules
        self.enabled_brands = {
            module.get("brand")
            for module in self.modules.values()
            if module.get("state") == "active"
        }

    def is_brand_available(self, brand: str) -> bool:
        """Check if a brand is active and available."""
        return brand in self.enabled_brands


def get_private_ips() -> list[str]:
    """Retrieve the list of private IP subnets."""
    #todo: error handeling
    private_ips_list = demisto.executeCommand("getList", {"listName": "PrivateIPs"})[0]["Contents"]
    private_ips = re.findall(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b/\d{1,2})", private_ips_list)
    return private_ips if private_ips else PRIVATE_SUBNETS


def is_ip_internal(ip: str) -> bool:
    """Determine if an IP is internal based on private subnets."""

    def is_ip_in_subnet(ip: str, subnet: str) -> bool:
        try:
            return ip_address(ip) in ip_network(subnet, strict=False)
        except ValueError:
            return False

    ip_ranges = get_private_ips()
    return any(is_ip_in_subnet(ip, subnet.strip()) for subnet in ip_ranges)


def is_command_runnable(brand: str, args: dict[str, Any], module_manager: ModuleManager) -> bool:
    """Check if a command is runnable based on the brand and arguments."""
    if not module_manager.is_brand_available(brand):
        demisto.debug(f"Brand '{brand}' is not available.")
        return False

    if not args or not any(args.values()):
        demisto.debug(f"No valid arguments provided for the command associated with brand '{brand}'.")
        return False

    return True



def enrich_internal_ip_address(ip: str, tim_data: dict, verbose: bool) -> CommandResults:
    """Handle internal IP enrichment."""
    demisto.debug(f"Internal IP detected: {ip}")
    endpoint_data = demisto.executeCommand("get-endpoint-data", {"ip": ip})[0]["Contents"]
    readable_output = tableToMarkdown("Internal IP Data", endpoint_data)
    return CommandResults(
        outputs=endpoint_data,
        outputs_prefix="IPEnrichment.Internal",
        readable_output=readable_output
    )


def check_reputation(ip: str) -> str:
    """Check the reputation of an IP address."""
    reputation = demisto.executeCommand("ip", {"ip": ip})[0]["Contents"]
    print(reputation)
    return reputation

def get_analytics_prevalence(ip: str) -> dict:
    pass

def enrich_external_ip_address(ip: str, tim_data: dict, verbose: bool, outputs, command_results) -> CommandResults:
    """Handle external IP enrichment."""
    demisto.debug(f"External IP detected: {ip}")
    reputation = check_reputation(ip)
    if is_xsiam():
        get_analytics_prevalence(ip)

    # prevalence = demisto.executeCommand("core-IP-prevalence", {"ip": ip})[0]["Contents"]
    #
    # combined_data = {**prevalence, **reputation}
    # readable_output = tableToMarkdown("External IP Data", combined_data)



def ip_enrichment(ip: str, third_enrichment: bool, verbose: bool, module_manager: ModuleManager):
    """Perform IP enrichment with validation."""
    command_results = []
    outputs = []
    try:
        tim_indicator = demisto.executeCommand("findIndicators", {"query": ip, "size": 1})[0].get("Contents", [{}])[0]
        if not third_enrichment:
            return CommandResults(
                outputs=tim_indicator,
                # outputs_prefix="IPEnrichment.TIM", #todo handle prefix
                # readable_output=tableToMarkdown("IP Enrichment - TIM Data", tim_indicator)
            )
        if verbose:
            command_results.append(CommandResults())

        if is_ip_internal(ip):
            enrich_internal_ip_address(ip, tim_indicator, verbose)
        else:
            enrich_external_ip_address(ip, tim_indicator, verbose, outputs, command_results)

        return outputs, command_results

    except Exception as e:
        demisto.error(f"Failed to enrich IP {ip}: {e}")
        raise e


def main():
    try:
        args = demisto.args()
        ips = argToList(args.get("ip", ""))
        third_enrichment = argToBoolean(args.get("third_enrichment", False))
        verbose = argToBoolean(args.get("verbose", False))
        module_manager = ModuleManager(demisto.getModules())

        if not ips:
            raise ValueError("No IPs provided for enrichment.")

        ip_outputs_list: list[dict[str, Any]] = []
        ips_not_found_list: list[dict] = []
        command_results_list : list[CommandResults] = []

        for ip in ips:
            try:
                ip_outputs, command_results = ip_enrichment(ip, third_enrichment, verbose, module_manager)
                ip_outputs_list.extend(ip_outputs) if isinstance(ip_outputs, list) else ip_outputs_list.append(ip_outputs)
                command_results_list.extend(command_results) if isinstance(command_results, list) else command_results_list.append(command_results)

            except Exception as e:
                ips_not_found_list.append({"ip": ip, "error": str(e)})

        if ips_not_found_list:
            command_results_list.append(
                CommandResults(
                    readable_output=tableToMarkdown(
                        name="Endpoint(s) not found",
                        # headers=["Key"],
                        t=ips_not_found_list,
                    )
                )
            )
        if ip_outputs_list:
            command_results_list.append(
                CommandResults(
                    # outputs_prefix="Endpoint",
                    # outputs_key_field="Hostname.Value",
                    outputs=ip_outputs_list,
                    # readable_output=tableToMarkdown(
                    #     name="Endpoint(s) data",
                    #     t=ip_outputs_list,
                    #     headers=["ID", "IPAddress", "Hostname"],
                    #     removeNull=True,
                    # ),
                )
            )
        return_results(command_results_list)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute IPEnrichment. Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
