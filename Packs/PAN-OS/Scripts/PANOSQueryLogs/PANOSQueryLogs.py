import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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
            if url_category.startswith("AI"):
                # Keep "AI" uppercase, convert rest to lowercase
                url_category = ("AI" + url_category[2:].lower().replace(" ","-"))
            else:
                # Convert entire string to lowercase
                url_category = url_category.lower().replace(" ","-")
            args["query"] = f"url_category_list contains '{url_category}'"
        return_results(execute_polling_command("pan-os-query-logs", args))
    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
