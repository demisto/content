import json

from sigma import exceptions
from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.backends.cortexxdr import CortexXDRBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.backends.qradar import QradarBackend
from sigma.backends.sentinelone import SentinelOneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.rule import SigmaRule

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    siems = {
        "xql": CortexXDRBackend(),
        "splunk": SplunkBackend(),
        "sentinel_one": SentinelOneBackend(),
        "qradar": QradarBackend(),
        "microsoft_defender": Microsoft365DefenderBackend(),
        "carbon_black": CarbonBlackBackend(),
        "elastic": LuceneBackend(),
    }

    args = demisto.callingContext["args"]

    indicator = args["indicator"]

    try:
        siem = siems[args["SIEM"].lower()]

    except KeyError:
        return_error(f"Unknown SIEM - \"{args['SIEM']}\"")

    rule_dict = json.loads(indicator["CustomFields"]["sigmaruleraw"])
    rule = SigmaRule.from_dict(rule_dict)

    # Set the context
    try:
        query = siem.convert_rule(rule)[0]

    except exceptions.SigmaTransformationError as e:
        query = f"ERROR:\n{e}"

    demisto.executeCommand("setIndicator", {"sigmaconvertedquery": f"{query}", "value": indicator["value"]})

    return_results(CommandResults(readable_output=f"{args['SIEM']} output created"))


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
