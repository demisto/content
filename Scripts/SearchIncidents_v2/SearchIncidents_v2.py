from typing import Dict, List, Tuple
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def outputs_handel(res) -> Tuple[str, Dict, List]:
    if isinstance(res, list) and res:
        if 'data' in res[0].get('Contents', {}):
            data = res[0]['Contents']['data']
            context_entry: Dict = {'foundIncidents': data}
            headers = ['id', 'name', 'severity', 'status', 'owner', 'created', 'closed']
            data = tableToMarkdown(name="Incidents found", t=data, headers=headers)

        else:
            context_entry: Dict = {}
            data = res[0].get('Contents')
            data = tableToMarkdown(name="Incidents not found", t=data, headers=[''])

        return data, context_entry, res
    else:
        return_error('', DemistoException(f'failed to get incidents from demisto got {str(res)}'))


def crate_search(args: Dict) -> Dict:
    array_fields: List = ['id', 'name', 'status', 'notstatus', 'reason', 'level', 'owner', 'type', 'query']
    for _key in array_fields:
        if _key in args:
            args[_key] = argToList(args[_key])
    return args


def main():
    args: Dict = crate_search(demisto.args())
    res = demisto.executeCommand('getIncidents', args)
    human_readable, context_entry, raw = outputs_handel(res)
    return_outputs(human_readable, context_entry, raw)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
