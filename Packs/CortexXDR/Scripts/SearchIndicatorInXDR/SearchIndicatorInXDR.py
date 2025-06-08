import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CoreXQLApiModule import *

urllib3.disable_warnings()
DEFAULT_TIMEOUT = 600
DEFAULT_INTERVAL = 30
uri_fallback = r"(?P<uri>\b[a-z][a-z0-9+.-]*:[^\s]+)"  # for covering all cases in addition to "urlRegex"


def shorten_text(text: str) -> str:
    parts = text.split()
    if len(parts) == 2:
        return f"{parts[0]}{parts[1][0].lower()}"
    return text  # Return original if not exactly two words


def generate_xdr_query(time_frame_for_query: str, indicator: str, data_set: str = "xdr_data") -> str:
    """
    This function generates a query for xdr by the indicator's type.
    """

    # Determine indicator type
    if re.match(ipv4Regex, indicator) or re.match(ipv6Regex, indicator):
        indicator_type = "ip"
    elif re.match(domainRegex, indicator):
        indicator_type = "domain"
    elif re.match(md5Regex, indicator):
        indicator_type = "md5"
    elif re.match(sha256Regex, indicator):
        indicator_type = "sha256"
    elif re.match(urlRegex, indicator) or re.match(uri_fallback, indicator):
        indicator_type = "uri"
    else:
        indicator_type = "unknown"

    # Field map
    field_map = {
        "ip": ["action_remote_ip", "action_local_ip"],
        "domain": ["dst_action_external_hostname", "dns_query_name", "action_external_hostname"],
        "uri": ["uri"],
        "md5": ["action_file_md5", "action_module_md5", "action_process_image_md5"],
        "sha256": ["action_file_sha256", "action_module_sha256", "action_process_image_sha256"],
    }

    # Build query
    if indicator_type in field_map:
        fields = field_map[indicator_type]
        filters = [f'{field} contains "{indicator}"' for field in fields]
        filter_clause = " or ".join(filters)
        return f"config timeframe = {time_frame_for_query} | dataset = {data_set} | filter {filter_clause}"
    else:
        raise DemistoException(
            f"Indicators supported by this script are IP, Domain, MD5, Sha256, and Uri.\n" f"This {indicator=} has unknown type"
        )


def execute_query_in_xdr(args: dict) -> CommandResults:
    """
    This function executes the xdr-xql-generic-query command by execute_polling_command (from CSP),
    and returns the results.
    execute_polling_command wraps the xdr-xql-generic-query polling command and manages the polling by itself.
    """
    demisto.debug("starting execute_query")
    time_frame: str = args.get("time_frame", "7 days")
    data_set: str = args.get("data_set", "xdr_data")
    indicator: str = args["indicator"]
    query_name: str = args["query_name"]

    time_frame_for_query: str = shorten_text(time_frame)
    query: str = generate_xdr_query(time_frame_for_query=time_frame_for_query, indicator=indicator, data_set=data_set)
    demisto.debug(f"This is the {query=}")
    entry_result = execute_polling_command(
        command_name="xdr-xql-generic-query", args={"query": query, "query_name": query_name, "max_fields": 1000}
    )
    return entry_result


def main():  # pragma: no cover
    try:
        return_results(execute_query_in_xdr(args=demisto.args()))
    except Exception as e:
        return_error("Error occurred while retrieving data from XDR. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
