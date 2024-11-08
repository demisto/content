
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
        rule_str = indicator["CustomFields"]["sigmaruleraw"]
        rule = SigmaRule.from_yaml(rule_str)
        query = siem.convert_rule(rule)[0]
        execute_command("setIndicator", {"sigmaconvertedquery": f"{query}",
                                         "querylanguage": f"{args['SIEM'].replace('_', ' ')}",
                                         "value": indicator["value"]})

    except exceptions.SigmaTransformationError as e:
        query = f"ERROR:\n{e}"
        execute_command("setIndicator", {"sigmaconvertedquery": f"{query}",
                                         "querylanguage": f"{args['SIEM'].replace('_', ' ')}",
                                         "value": indicator["value"]})
        return_error(f"Failed to parse Sigma rule to {args['SIEM']} language")

    except KeyError:
        return_error(f"Unknown SIEM - \"{args['SIEM']}\"")

    except Exception as e:
        return_error(f"Error: {e}")

    return_results(CommandResults(readable_output=f"{args['SIEM']} output created"))


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
