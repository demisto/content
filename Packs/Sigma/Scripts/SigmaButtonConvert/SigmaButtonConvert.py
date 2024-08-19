import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from sigma.rule import SigmaRule
from sigma import exceptions
from sigma.backends.cortexxdr import CortexXDRBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sentinelone import SentinelOneBackend
from sigma.backends.qradar import QradarBackend
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.backends.elasticsearch import LuceneBackend

import json


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

    indicator = demisto.callingContext["args"]["indicator"]

    try:
        siem = siems[demisto.callingContext["args"]["SIEM"].lower()]

    except KeyError:
        return_error(f"Unknown SIEM - \"{demisto.callingContext['args']['SIEM']}\"")

    rule_dict = json.loads(indicator["CustomFields"]["sigmaruleraw"])
    rule = SigmaRule.from_dict(rule_dict)

    # Set the context
    try:
        query = siem.convert_rule(rule)[0]

    except exceptions.SigmaTransformationError as e:
        query = f"ERROR:\n{e}"

    demisto.executeCommand("setIndicator", {"sigmaconvertedquery": f"{query}", "value": indicator["value"]})

    return_results(CommandResults(readable_output=f"{demisto.callingContext['args']['SIEM']} output created"))


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
