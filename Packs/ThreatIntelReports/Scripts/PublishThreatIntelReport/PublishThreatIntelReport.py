from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def publish():
    now_utc = datetime.now(timezone.utc)
    object_id = demisto.getArg('object.id')
    if is_demisto_version_ge('6.9.0'):
        # getReadOnlyRoles is only supported from 6.8.0
        roles = execute_command('getReadOnlyRoles', {})
    else:
        roles = execute_command('getRoles', {})

    execute_command(
        'setThreatIntelReport',
        {
            'id': object_id,
            'xsoarReadOnlyRoles': demisto.dt(
                roles, 'name'
            ),
            'reportstatus': 'Published',
            'published': now_utc.isoformat(),
        },
    )

    demisto.results('ok')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    publish()
