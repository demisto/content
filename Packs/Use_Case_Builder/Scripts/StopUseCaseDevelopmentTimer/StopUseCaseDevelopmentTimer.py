import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main(incident):
    inprod = incident.get('CustomFields', {}).get('usecasedevelopmentstage')

    args = demisto.args()
    try:
        if args.get('new') and inprod == 'Production':  # checks if the stage was set to production:
            demisto.executeCommand("stopTimer", {"timerField": "usecasebuilderdevelopmentdeadline"})
            demisto.results("The use case development stage has been set to Production!"
                            " timer has been stopped.")
    except Exception as e:  # erro handling
        err_msg = f'Encountered an error while running the script: [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    incident = demisto.incidents()[0]
    main(incident)
