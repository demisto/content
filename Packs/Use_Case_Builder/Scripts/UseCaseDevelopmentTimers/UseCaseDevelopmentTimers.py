import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def stop_all_timers_except_backlog():
    timers_to_stop = ["usecasedevelopmenttimer", "usecasetestingtimer", "usecasepreproductiontimer",
                      "usecasebuilderdevelopmentdeadline", "usecaseproductiontimer"]
    for timer in timers_to_stop:
        demisto.executeCommand("pauseTimer", {"timerField": timer})


def stop_all_timers_except_production():
    timers_to_stop = ["usecasedevelopmenttimer", "usecasetestingtimer", "usecasebacklogtimer",
                      "usecasepreproductiontimer"]
    for timer in timers_to_stop:
        demisto.executeCommand("stopTimer", {"timerField": timer})


def stop_all_timers_except_development():
    timers_to_stop = ["usecasetestingtimer", "usecasepreproductiontimer", "usecasebacklogtimer",
                      "usecaseproductiontimer"]
    for timer in timers_to_stop:
        demisto.executeCommand("pauseTimer", {"timerField": timer})


def stop_all_timers_except_testing():
    timers_to_stop = ["usecasedevelopmenttimer", "usecasepreproductiontimer", "usecasebacklogtimer",
                      "usecaseproductiontimer"]
    for timer in timers_to_stop:
        demisto.executeCommand("pauseTimer", {"timerField": timer})


def stop_all_timers_except_preproduction():
    timers_to_stop = ["usecasedevelopmenttimer", "usecasetestingtimer", "usecasebacklogtimer", "usecaseproductiontimer"]
    for timer in timers_to_stop:
        demisto.executeCommand("pauseTimer", {"timerField": timer})


def main(incident):
    stage = incident.get('CustomFields', {}).get('usecasedevelopmentstage')

    args = demisto.args()
    # setting up timer
    try:
        if args.get('new') and stage == 'Production':  # checks if the stage was set to production
            demisto.executeCommand("stopTimer", {"timerField": "usecasebuilderdevelopmentdeadline"})
            demisto.executeCommand("startTimer", {"timerField": "usecaseproductiontimer"})
            stop_all_timers_except_production()
            demisto.results("The use case development stage has been set to Production!"
                            " timer has been stopped, total use case time in production started.")
        elif args.get('new') and stage == 'In Development':  # checks if the stage was set to in development
            demisto.executeCommand("startTimer", {"timerField": "usecasedevelopmenttimer"})
            stop_all_timers_except_development()
            demisto.results("The use case is in development"
                            " timer has been started.")
        elif args.get('new') and stage == 'Testing':  # checks if the stage was set to testing
            demisto.executeCommand("startTimer", {"timerField": "usecasetestingtimer"})
            stop_all_timers_except_testing()
            demisto.results("The use case has been moved to the testing stages"
                            " timer has been started.")
        elif args.get('new') and stage == 'Pre-Production':  # checks if the stage was set to pre-production
            demisto.executeCommand("startTimer", {"timerField": "usecasepreproductiontimer"})
            stop_all_timers_except_preproduction()
            demisto.results("The use case has been moved to the pre-production stages"
                            " timer has been started.")
        else:
            demisto.executeCommand("startTimer", {"timerField": "usecasebacklogtimer"})
            stop_all_timers_except_backlog()
            demisto.results("The use case has been moved to backlog"
                            " timer has been started.")

    except Exception as e:  # error handling
        err_msg = f'Encountered an error while running the script: [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    incident = demisto.incidents()[0]
    main(incident)
