import demistomock as demisto
from CommonServerPython import *
import uuid


def main():
    try:
        unique_string = str(demisto.getLicenseID() + str(datetime.now().timestamp()))
        external_id = uuid.uuid5(uuid.NAMESPACE_DNS, unique_string)
        return_results(CommandResults(
            readable_output=f'### External ID generated: *{external_id}*'
        ))
    except Exception as exc:
        return_error(exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
