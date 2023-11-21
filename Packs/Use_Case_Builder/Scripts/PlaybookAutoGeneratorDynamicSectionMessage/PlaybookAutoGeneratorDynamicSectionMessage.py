import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    incident_name = incident.get('name', '')
    usecasegeneratorkey = incident.get('CustomFields', {}).get('usecasebuilderautogeneratorkey', 0)

    if not incident_name:
        demisto.results(
            "This tool will help you develop, track, and maintain your use cases. As well as quickly generate custom "
            "playbooks to get you started on your automation journey! \n\nOnce you have created your use case, "
            "head over to the Downloads tab to retrieve your use case document")
    elif usecasegeneratorkey is not None:
        message = f'**{incident_name}** - has been generated and is now available in your playbook collection'

        dynamic_section = {
            "Type": 1,
            "ContentsFormat": "markdown",
            "Contents": message,
        }

        demisto.results(dynamic_section)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
