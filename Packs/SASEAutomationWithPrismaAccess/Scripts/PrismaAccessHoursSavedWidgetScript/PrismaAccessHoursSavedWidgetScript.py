from typing import List

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    res = demisto.executeCommand("getIncidents", {'query': 'type:"Prisma Access - Create Tenant"'})
    incidents = res[0]['Contents']['data']
    incidents_count = len(incidents) if incidents else 0

    hours_saved_per_task = 2
    demisto.results(incidents_count * hours_saved_per_task)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
