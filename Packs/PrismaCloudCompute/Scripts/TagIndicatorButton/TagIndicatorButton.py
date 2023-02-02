import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
args = demisto.args()
res = demisto.executeCommand("setIndicators", {"indicatorsValues": args.get("Indicators"), args.get("Tags")})
demisto.results(res)
