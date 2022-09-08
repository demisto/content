import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BLACKLISTED = "Bad"
<<<<<<< HEAD
args = demisto.args()


def get_contents():
=======


def get_contents(args: Dict[str, Any]):
>>>>>>> 34f2d35b74 (updated UT)
    """Get IP addresses on block lists from AbuseIPDB

    :return: dictionary containing block lists
    :rtype: ``dict[str, Any]``
    """
<<<<<<< HEAD
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
=======

    res = execute_command(
        "abuseipdb-get-blacklist",
        {
            "days": args.get("days"),
            "limit": args.get("limit"),
            "confidence": args.get("confidence"),
        },
    )

    if not res:
        return None

    return res[0].get("Contents", None)


def check_ips(ips: dict):
    """Check 'ips' dictionary validity

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
                    "type": "ip",
                    "value": ip,
                    "source": "AbuseIPDB",
                    "reputation": BLACKLISTED,
                    "seenNow": "true",
                },
            )

        return_results("All Indicators were created successfully")

    except DemistoException as e:
        return_error(e.message)
>>>>>>> 34f2d35b74 (updated UT)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
