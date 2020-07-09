import demistomock as demisto
from CommonServerPython import *


def main():
    try:
        employees = demisto.executeCommand("code42-highriskemployee-get-all",
                                           {"filtertype": "EXFILTRATION_30_DAYS", "using": "c42_demisto"})[0]["Contents"]
        demisto.results(len(employees))
    except Exception as e:
        demisto.results(-1)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
