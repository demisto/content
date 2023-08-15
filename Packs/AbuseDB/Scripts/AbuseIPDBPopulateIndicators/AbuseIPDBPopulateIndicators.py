import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BLACKLISTED = "Bad"


def get_contents(args: Dict[str, Any]):
    """Get IP addresses on block lists from AbuseIPDB

    :return: dictionary containing block lists
    :rtype: ``dict[str, Any]``
    """

    return (
        execute_command(
            "abuseipdb-get-blacklist",
            {
                "days": args.get("days"),
                "limit": args.get("limit"),
                "confidence": args.get("confidence"),
            },
        )
        or None
    )


def check_ips(ips: list):
    """Check 'ips' list validity

    :return: None if valid, else execute return_error()
    :rtype: ``None``
    """
    if not ips or "Too many requests" in ips:
        raise DemistoException("No Indicators were created (possibly bad API key)")


def main():
    try:
        args = demisto.args()
        ips = get_contents(args)
        check_ips(ips)

        # Extract IPs into new Indicators
        for ip in ips:
            execute_command(
                "createNewIndicator",
                {
                    "type": "IP",
                    "value": ip,
                    "source": "AbuseIPDB",
                    "reputation": BLACKLISTED,
                    "seenNow": "true",
                },
            )

        return_results("All Indicators were created successfully")

    except DemistoException as e:
        return_error(e.message)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
