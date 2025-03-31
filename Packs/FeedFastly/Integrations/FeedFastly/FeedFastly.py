import demistomock as demisto
from CommonServerPython import *
from JSONFeedApiModule import *  # noqa: E402


def main():
    try:
        params = {k: v for k, v in demisto.params().items() if v is not None}

        params["feed_name_to_config"] = {
            "CIDR": {
                "url": "https://api.fastly.com/public-ip-list",
                "extractor": "addresses[].{ip:@}",
                "indicator": "ip",
                "indicator_type": FeedIndicatorType.CIDR,
            },
            "IPv6CIDR": {
                "url": "https://api.fastly.com/public-ip-list",
                "extractor": "ipv6_addresses[].{ip:@}",
                "indicator": "ip",
                "indicator_type": FeedIndicatorType.IPv6CIDR,
            },
        }

        feed_main(params, "Fastly Feed", "fastly")
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
