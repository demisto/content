from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def publish():
    now_utc = datetime.now(timezone.utc)
    object_id = demisto.getArg('object.id')
    roles = execute_command('getRoles', {})

    execute_command(
        'setThreatIntelReport',
        {
            'id': object_id,
            'xsoarReadOnlyRoles': demisto.dt(
                roles, 'DemistoRoles.name'
            ),
            'reportstatus': 'Published',
            'published': now_utc.isoformat(),
        },
    )

    demisto.results('ok')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    publish()
