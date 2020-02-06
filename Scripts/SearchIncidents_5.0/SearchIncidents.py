from typing import Dict, List
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


special = ['n', 't', '\\', '"', '\'', '7', 'r']


def check_if_found_incident(res: List):
    if res and isinstance(res, list) and isinstance(res[0].get('Contents'), dict):
        if 'data' not in res[0]['Contents']:
            raise DemistoException(res[0].get('Contents'))
        elif res[0]['Contents']['data'] is None:
            return_outputs("Incidents not found.", {}, {})
            sys.exit(0)

    else:
        raise DemistoException(f'failed to get incidents from demisto.\nGot: {res}')


def is_valid_args(args: Dict):
    array_args: List[str] = ['id', 'name', 'status', 'notstatus', 'reason', 'level', 'owner', 'type', 'query']
    error_msg: List[str] = []
    for _key, value in args.items():
        if _key in array_args:
            value = ','.join(value)
        i = 0
        while i < len(value):
            if value[i] == '\\':
                if value[i + 1] not in special:
                    error_msg.append(f'Error while parsing the argument: "{_key}" '
                                     f'\nSucceeded parsing untill:\n- "{value[0:i]}"')
                else:
                    i += 1
            i += 1
    if len(error_msg) != 0:
        raise DemistoException('\n'.join(error_msg))

    return True


def search_incidents(args: Dict):
    if is_valid_args(args):
        res: List = demisto.executeCommand('getIncidents', args)
        check_if_found_incident(res)
        data: Dict = res[0]['Contents']['data']
        context_entry: Dict = {'foundIncidents': data}
        headers: List[str] = ['id', 'name', 'severity', 'status', 'owner', 'created', 'closed']
        md: str = tableToMarkdown(name="Incidents found", t=data, headers=headers)
        return_outputs(md, context_entry, res)


def main():
    args: Dict = demisto.args()
    try:
        search_incidents(args)
    except DemistoException as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
