import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BLACKLISTED = "Bad"
res = demisto.executeCommand("abuseipdb-get-blacklist", {
    "days": demisto.args().get("days"),
    "limit": demisto.args().get("limit"),
    "confidence": demisto.args().get("confidence")
})

ips = res[0]['Contents']

if not ips or "Too many requests" in ips:
    return_error("No Indicators were created (possibly bad API key)")

# Extract IPs into new Indicators
for ip in ips:
    demisto.executeCommand("createNewIndicator", {
        "type": 'ip',
        "value": ip,
        "source": 'AbuseIPDB',
        "reputation": BLACKLISTED,
        "seenNow": "true",
    })

demisto.results("All Indicators were created successfully")
