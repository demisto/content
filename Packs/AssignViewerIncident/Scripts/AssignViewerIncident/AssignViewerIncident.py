import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

register_module_line('AssignViewerIncident', 'start', __line__())


def main():

    current_owner = demisto.incident().get('owner', {})
    if current_owner == "":
        lock_name = "assign_viewer_to_incident"
        lock = demisto.executeCommand("demisto-lock-get", {"name": lock_name, "timeout": 2})[0]
        if lock['Type'] == 4:
            return_error(lock['Contents'])

        else:
            user = demisto.executeCommand("getUsers", {"current": True})
            username = user[0].get('Contents')[0].get('username')
            demisto.executeCommand("setOwner", {"owner": username})
            demisto.executeCommand("demisto-lock-release", {"name": lock_name})

            # Have other functions for display like a field or something.1st run display if owner is not set.

            final_str = 'Incident owner: ' + str(username)
            return(final_str)

    else:

        # Have other functions for display like a field or something. Subsequent runs, when owner is already set either by this automation itself or by other methods.
        final_str = 'Incident owner: ' + str(current_owner)
        return(final_str)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error(f'Got an error: {e}', error=e)

register_module_line('AssignViewerIncident', 'end', __line__())
