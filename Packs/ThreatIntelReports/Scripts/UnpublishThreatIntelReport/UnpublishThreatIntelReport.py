import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def unpublish():
    object_id = demisto.getArg('object.id')

    execute_command(
        'setThreatIntelReport',
        {
            'id': object_id,
            'xsoarReadOnlyRoles': '',
            'reportstatus': 'Draft',
            'published': '',
        },
    )

    demisto.results('ok')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    unpublish()
