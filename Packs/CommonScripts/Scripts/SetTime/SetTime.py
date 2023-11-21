import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime


def set_time():

    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S+00:00')

    fieldName = demisto.args()['fieldName']

    # Example format: '2018-02-02T22:58:21+02:00'

    demisto.debug('[*] ' + fieldName + ' <- ' + now)

    demisto.setContext(fieldName, now)

    demisto.results(demisto.executeCommand("setIncident", {fieldName: now}))


def main():
    set_time()


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
