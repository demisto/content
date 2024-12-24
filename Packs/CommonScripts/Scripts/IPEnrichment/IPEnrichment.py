import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# import demistomock as demisto  # noqa: F401
# from CommonServerPython import *  # noqa: F401
import socket
from ipaddress import ip_network, ip_address

# values taken from IsIPInRanges script
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
    fields = ['id', 'indicator_type', 'value',
              'score']  # todo: which fields to return? maybe another command should be used per Yarden

    styled_indicator = {}
    for field in fields:
        styled_indicator[field] = indicator.get(field, indicator.get("CustomFields", {}).get(field, "n/a"))
    styled_indicator["verdict"] = scoreToReputation(styled_indicator['score'])

    headers = fields + ["verdict"]
    hr = tableToMarkdown("IP Enrichment- indicator data from TIM", styled_indicator, headers)
    return hr


def get_private_ips() -> list:
    private_ips_list = demisto.executeCommand("getList", {"listName": "PrivateIPs"})[0]["Contents"]
    private_ips = re.findall(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b/\d{1,2})", private_ips_list)
    return privte_ips if private_ips else PRIVATE_SUBNETS


def is_ip_internal(ip: str):
    def is_ip_in_subnet(ip, subnet):
        try:
            return ip_address(ip) in ip_network(subnet, strict=False)
        except ValueError:
            return False

    ip_ranges = get_private_ips()
    return any(is_ip_in_subnet(ip, re.sub(r'\\s', '', iprange)) for iprange in ip_ranges)


def internal_ip_flow():
    # get-endpoint-data
    print("internal_ip_flow")


def external_ip_flow():
    # Check prevalence only in xsiam
    # IP

    print("external_ip_flow")


def ip_enrichment(ip: str, third_enrichment: bool, verbose: bool) -> CommandResults:
    # Check if the indicator exist in TIM - searchIndicator script functionality
    tim_indicator = demisto.executeCommand("findIndicators", {"query": ip, "size": 1})[0][
        "Contents"][0]  #todo: always one entity for ip right?
    demisto.debug(f"IP Enrichment - tim indicator tim_indicator")
    if verbose:
        tim_indicator_hr = get_tim_indicator_hr(tim_indicator)
    if not third_enrichment:
        return CommandResults(
            outputs=tim_indicator,
            # outputs_prefix='Endpoint',
            # outputs_key_field='Hostname',
            # readable_output=
        )

    # Internal \ external
    if is_ip_internal(ip):
        internal_ip_flow()
    else:
        external_ip_flow()

    output = None
    md = tableToMarkdown('IP Enrichment', [output])

    return CommandResults(
        outputs=output,
        # outputs_prefix='Endpoint',
        # outputs_key_field='Hostname',
        # readable_output=md,
    )


def main():
    try:
        ips = argToList(demisto.args().get('ip', ''))
        third_enrichment = argToBoolean(demisto.args().get('third_enrichment', False))
        verbose = argToBoolean(demisto.args().get('verbose', False))
        print(ips, third_enrichment, verbose)
        return_results([ip_enrichment(ip, third_enrichment, verbose) for ip in ips])
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'IP Enrichment failed. Error information: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
