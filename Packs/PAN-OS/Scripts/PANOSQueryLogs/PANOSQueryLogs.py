import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

URL_CATEGORY_LIST = [
    "Malware",
    "Phishing",
    "Command and Control",
    "Dynamic DNS",
    "Encrypted DNS",
    "Parked",
    "Unknown",
    "Newly Registered Domains",
    "Grayware",
    "Hacking",
    "Proxy Avoidance And Anonymizers",
    "Ransomware",
    "Scanning Activity",
    "Artificial Intelligence",
    "High Risk",
    "Compromised Website",
]


def main():
    args = demisto.args()
    try:
        args["log-type"] = args.pop("log_type", None)
        args["time-generated"] = args.pop("time_generated", None)
        args["time-generated-after"] = args.pop("time_generated_after", None)
        args["addr-src"] = args.pop("addr_src", None)
        args["addr-dst"] = args.pop("addr_dst", None)
        args["zone-src"] = args.pop("zone_src", None)
        args["zone-dst"] = args.pop("zone_dst", None)
        args["port-dst"] = args.pop("port_dst", None)
        args["show-detail"] = args.pop("show_detail", None)
        args["polling"] = True
        url_category = args.get("url_category")
        if url_category is not None:
            if args["log-type"] != "url":
                raise ValueError("url_category arg is only valid for querying with log_type url")
            elif url_category not in URL_CATEGORY_LIST:
                raise ValueError(f"Invalid URL category. Must be one of: {', '.join(URL_CATEGORY_LIST)}")
            else:
                # Convert entire string to lowercase and replace spaces with -
                url_category = url_category.lower().replace(" ", "-")
            args["query"] = f"url_category_list contains '{url_category}'"
        return_results(execute_polling_command("pan-os-query-logs", args))
    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
