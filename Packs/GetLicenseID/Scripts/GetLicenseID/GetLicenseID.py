from CommonServerPython import *


def main():
    human_readable, context_data = get_license_id()
    return_outputs(human_readable, context_data)


def get_license_id():
    license_id = demisto.getLicenseID()
    human_readable = tableToMarkdown('Demisto License ID', license_id, headers='License ID')
    return human_readable, {'Demisto License': license_id}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
