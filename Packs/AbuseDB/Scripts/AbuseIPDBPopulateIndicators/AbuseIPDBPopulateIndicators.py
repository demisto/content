import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BLACKLISTED = "Bad"
args = demisto.args()


def get_contents():
    """Get IP addresses on block lists from AbuseIPDB

    :return: dictionary containing block lists
    :rtype: ``dict[str, Any]``
    """
    res = demisto.executeCommand(
        "abuseipdb-get-blacklist",
        {
            "days": args.get("days"),
            "limit": args.get("limit"),
            "confidence": args.get("confidence"),
        },
    )
    return res[0].get("Contents")


def main():
    ips = get_contents()

    if not ips or "Too many requests" in ips:
        return_error("No Indicators were created (possibly bad API key)")

    # Extract IPs into new Indicators
    for ip in ips:
        demisto.executeCommand(
            "createNewIndicator",
            {
                "type": "ip",
                "value": ip,
                "source": "AbuseIPDB",
                "reputation": BLACKLISTED,
                "seenNow": "true",
            },
        )

    demisto.results("All Indicators were created successfully")


if __name__ == "__main__":
    main()
