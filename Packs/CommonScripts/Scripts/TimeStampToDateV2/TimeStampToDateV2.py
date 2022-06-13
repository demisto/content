
import traceback
from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from datetime import datetime, timezone


def epoc_to_date(args: Dict[str, Any]) -> CommandResults:

    epoch_value = int(args.get('value', 0))
    format = args.get('format')

    date_obj = datetime.fromtimestamp(epoch_value, tz=timezone.utc)

    result = date_obj.strftime(format) if format else date_obj.isoformat()
    return CommandResults(
        outputs_prefix='TimeStampToDateV2',
        outputs_key_field='',
        readable_output=f'Formated timestamp: {result}',
        outputs=result,
    )


def main():
    try:
        return_results(epoc_to_date(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute TimeStampToDateV2. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
