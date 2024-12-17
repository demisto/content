
from CommonServerPython import *
from GetIncidentsApiModule import *


def main():
    try:
        args = demisto.args()
        alert_ids = argToList(args.get("alert_ids"))
        final_message = ""
        closed_results = [demisto.executeCommand(
            "closeInvestigation", {"id": alert, "close_reason": "Resolved - Auto Resolve"})
            for alert in alert_ids]
        if closed_results:
            for result in closed_results:
                if type(result) is list:
                    final_message += f'{result[0].get("Contents")}\n'

        return_results(final_message)

    except Exception as e:
        return_error(str(e))


if __name__ in ["builtins", "__main__"]:
    main()
