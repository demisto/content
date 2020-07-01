import demistomock as demisto
from CommonServerPython import *
# from CommonServerUserPython import *
import hashlib
import pickle
import uuid


def hash_multiple(value):
    if isinstance(value, list):
        if not value:
            return []
        else:
            return [hash_multiple(value[0])] + hash_multiple(value[1:])
    if isinstance(value, dict):
        for k, v in value.items():
            value[k] = hash_multiple(v)
        return value
    else:
        return hashlib.md5(str(value).encode('utf-8')).hexdigest()


def get_context(incident_id):
    res = demisto.executeCommand("getContext", {'id': incident_id})
    try:
        return res[0]['Contents'].get('context') or {}
    except Exception:
        return {}


def hash_incident():
    args = demisto.args()
    fieldsToHash_list = args.pop('fieldsToHash', '').split(',')
    fieldsToHash_list = set([x.strip() for x in fieldsToHash_list if x])
    res = demisto.executeCommand('GetIncidentsByQuery', args)
    if is_error(res):
        return_error(get_error(res))
    else:
        entry = res[0]
        incident_list = json.loads(entry['Contents'])
        new_incident_list = []
        for incident in incident_list:
            for field in fieldsToHash_list:
                if field in incident:
                    incident[field] = hash_multiple(incident.get(field))
            new_ctx = {}
            context_keys = [x for x in demisto.args().get('contextKeys', '').split(",") if x]
            if context_keys:
                ctx = get_context(incident['id'])
            for key in context_keys:
                if key in ctx:
                    new_ctx[key] = demisto.dt(ctx, key)
            incident['context'] = new_ctx
            new_incident_list.append(incident)
    file_name = str(uuid.uuid4())
    output_format = args['outputFormat']
    if output_format == 'pickle':
        data_encoded = pickle.dumps(new_incident_list)
    elif output_format == 'json':
        data_encoded = json.dumps(new_incident_list)
    else:
        return_error("Invalid output format: %s" % output_format)
    entry = fileResult(file_name, data_encoded)
    entry['Contents'] = new_incident_list
    entry['HumanReadable'] = "Fetched %d incidents successfully by the query: %s" % (len(new_incident_list), args.get('query'))
    entry['EntryContext'] = {
        'HashIncidentsFields': {
            'Filename': file_name,
            'FileFormat': output_format,
        }
    }
    return entry


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(hash_incident())
