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
            return False
        return True
    else:
        raise DemistoException(f'failed to get incidents from demisto.\nGot: {res}')


def is_valid_args(args: Dict):
    array_args: List[str] = ['id', 'name', 'status', 'notstatus', 'reason', 'level', 'owner', 'type', 'query']
    error_msg: List[str] = []
    for _key, value in args.items():
        if _key in array_args:
            try:
                _ = bytes(value, "utf-8").decode("unicode_escape")
            except UnicodeDecodeError as ex:
                error_msg.append(f'Error while parsing the argument: "{_key}" '
                                 f'\nError:\n- "{str(ex)}"')

    if len(error_msg) != 0:
        raise DemistoException('\n'.join(error_msg))

    return True


def add_incidents_link(data):
    server_url = demisto.demistoUrls().get('server')
    for incident in data:
        incident_link = urljoin(server_url, f'#/Details/{incident.get("id")}')
        incident['incidentLink'] = incident_link
    return data


def search_incidents(args: Dict):
    if is_valid_args(args):
        res: List = demisto.executeCommand('getIncidents', args)
        if is_error(res):
            raise DemistoException(get_error(res))
        incident_found: bool = check_if_found_incident(res)
        if incident_found is False:
            return 'Incidents not found.', {}, {}
        else:
            data = res[0]['Contents']['data']
            data = add_incidents_link(data)
            headers: List[str] = ['id', 'name', 'severity', 'status', 'owner', 'created', 'closed', 'incidentLink']
            md: str = tableToMarkdown(name="Incidents found", t=data, headers=headers)
            return md, data, res


def main():
    args: Dict = demisto.args()
    try:
        readable_output, outputs, raw_response = search_incidents(args)
        results = CommandResults(
            outputs_prefix='foundIncidents',
            outputs_key_field='id',
            readable_output=readable_output,
            outputs=outputs,
            raw_response=raw_response
        )
        return_results(results)
    except DemistoException as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
