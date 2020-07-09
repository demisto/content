import demistomock as demisto
from CommonServerPython import *


def main():
    try:
        employees = demisto.executeCommand("Code42GetHighRiskEmployees",
                                           {"filtertype": "EXFILTRATION_24_HOURS"})[0]["Contents"]
        demisto.results(employees)
    except Exception as e:
        demisto.results(-1)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
