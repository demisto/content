import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main(args):
    file_name = f"{args.get('filename')}.json"

    if args.get('type') == 'Incident':
        res = demisto.incident()
        export = fileResult(file_name, json.dumps(res))
    elif args.get('type') == 'Context':
        incident_id = demisto.incident().get('id')
        context = demisto.executeCommand('getContext', {'id': incident_id})
        export = fileResult(file_name, json.dumps(context[0].get('Contents', {}).get('context', {})))
    elif args.get('type') == 'Both':
        incident = demisto.incident()
        context = demisto.executeCommand('getContext', {'id': incident.get('id')})
        incident['context'] = context[0].get('Contents', {}).get('context', {})
        export = fileResult(file_name, json.dumps(incident))

    return export


if __name__ in ('__main__', '__builtin__', 'builtins'):
    demisto.results(main(demisto.args()))
