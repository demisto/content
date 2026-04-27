import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    indicator = demisto.callingContext.get("args", {}).get("indicator", {})
    epss = indicator.get("CustomFields", {}).get("dataminrpulseepssscore", "")
    epss = epss if epss else "N/A"

    return_results(CommandResults(readable_output=f"# <-:->**{epss}**"))  # noqa: E231


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
