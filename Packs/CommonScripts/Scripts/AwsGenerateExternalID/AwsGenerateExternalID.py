import demistomock as demisto
from CommonServerPython import *
import uuid


def main():
    try:
        # create a unique string based on the license ID and the current timestamp
        unique_string = f'{demisto.getLicenseID()} {datetime.now().timestamp()}'
        external_id = uuid.uuid5(uuid.NAMESPACE_DNS, unique_string)
        return_results(CommandResults(
            readable_output=f'### External ID generated: *{external_id}*'
        ))
    except Exception as exc:
        return_error(exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
