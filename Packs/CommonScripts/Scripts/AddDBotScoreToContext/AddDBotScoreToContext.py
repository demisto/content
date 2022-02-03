import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    indicator = demisto.args().get("indicator")
    # new line
    indicatorType = demisto.args().get("indicatorType")
    score = int(demisto.args().get("score"))
    vendor = demisto.args().get("vendor")
    reliability = demisto.args().get("reliability", None)

    dbotscore = {
        "Indicator": indicator,
        "Type": indicatorType,
        "Vendor": vendor,
        "Score": score,
        "Reliability": reliability
    }

    command_results = CommandResults(
        outputs_prefix='DBotScore',
        outputs=dbotscore
    )
    return_results(command_results)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
