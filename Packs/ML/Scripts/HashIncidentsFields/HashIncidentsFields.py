from CommonServerPython import *

import base64
import hashlib
import pickle
import uuid

RANDOM_UUID = str(demisto.args().get('addRandomSalt', ''))
# Memo for key matching
CACHE = {}  # type: ignore


def hash_value(simple_value):
    if not isinstance(simple_value, str):
        simple_value = str(simple_value)
    if simple_value.lower() in ["none", "null"]:
        return None
    if RANDOM_UUID:
        simple_value += RANDOM_UUID
    return hashlib.md5(simple_value.encode('utf8')).hexdigest()  # nosec


def pattern_match(pattern, s):
    regex = re.compile(pattern.replace("*", ".*"))
    return re.match(regex, s) is not None


def is_key_match_fields_to_hash(key, fields_to_hash):
    if key is None:
        return False

    if key in CACHE:
        return CACHE[key]
    for field in fields_to_hash:
        if pattern_match(field, key):
            CACHE[key] = True
            return True
    CACHE[key] = False
    return False


def hash_incident_labels(incident_labels, fields_to_hash):
    labels = []
    if isinstance(incident_labels, list):
        for label in incident_labels:
            if is_key_match_fields_to_hash(label.get('type'), fields_to_hash):
                value = label.get('value') or ''
                if value:
                    label['value'] = hash_value(value)
            labels.append(label)
    return labels


def hash_multiple(value, fields_to_hash, to_hash=False):
    if isinstance(value, list):
        return [hash_multiple(x, fields_to_hash, to_hash) for x in value]
    if isinstance(value, dict):
        for k, v in value.items():
            _hash = to_hash or is_key_match_fields_to_hash(k, fields_to_hash)
            value[k] = hash_multiple(v, fields_to_hash, _hash)
        return value
    else:
        try:
            if isinstance(value, int | float | bool):
                to_hash = False
            if not isinstance(value, str):
                value = str(value)
        except Exception:
            value = ""
        if to_hash and value:
            return hash_value(value)
        else:
            return value


def output_file(data, description, output_format):
    data_encoded = b''
    file_name = str(uuid.uuid4())
    if output_format == 'pickle':
        pickled_incidents = []
        for i in data:
            pickled_incident = base64.b64encode(pickle.dumps(i))
            pickled_incidents.append(pickled_incident)
        data_encoded = pickle.dumps(pickled_incidents)
    elif output_format == 'json':
        data_encoded = json.dumps(data).encode('utf8')
    else:
        return_error("Invalid output format: %s" % output_format)
    entry = fileResult(file_name, data_encoded)
    entry['Contents'] = data
    entry['HumanReadable'] = description
    entry['EntryContext'] = {
        'HashIncidentsFields': {
            'Filename': file_name,
            'FileFormat': output_format,
        }
    }
    return entry


def copy_key_from_context(ctx, context_keys):
    new_ctx = {}
    if not ctx:
        return {}
    for key in context_keys:
        new_ctx[key] = demisto.dt(ctx, key)
    return new_ctx


def get_context(incident_id):
    res = demisto.executeCommand("getContext", {'id': incident_id})
    try:
        return res[0]['Contents'].get('context') or {}
    except Exception:
        return {}


def hash_incident(fields_to_hash, un_populate_fields):
    args = demisto.args()

    remove_labels = demisto.args().get('removeLabels', '') == 'true'
    context_keys = [x for x in argToList(demisto.args().get('contextKeys', '')) if x]

    # load incidents
    res = demisto.executeCommand('GetIncidentsByQuery', args)
    if is_error(res):
        return_error(get_error(res))
    incident_list = json.loads(res[0]['Contents'])

    # filter incidents
    new_incident_list = []
    for incident in incident_list:
        if context_keys:
            incident['context'] = copy_key_from_context(get_context(incident['id']), context_keys)

        # remove CustomFields
        incident.pop('CustomFields', None)

        incident = hash_multiple(incident, fields_to_hash)

        # filter out fields
        if un_populate_fields:
            incident = {k: v for k, v in incident.items() if k not in un_populate_fields}

        # remove or hash incident labels
        incident_labels = incident.pop('labels')
        if not remove_labels:
            incident['labels'] = hash_incident_labels(incident_labels, fields_to_hash)

        new_incident_list.append(incident)

    # Output
    desc = "Fetched %d incidents successfully by the query: %s" % (len(new_incident_list), args.get('query'))
    entry = output_file(new_incident_list, desc, args['outputFormat'])
    return entry


if __name__ in ['__main__', '__builtin__', 'builtins']:
    args = demisto.args()
    fields_to_hash = frozenset([x for x in argToList(args.get('fieldsToHash', '')) if x])
    un_populate_fields = frozenset([x for x in argToList(args.get('unPopulateFields', '')) if x])
    entry = hash_incident(fields_to_hash, un_populate_fields)
    demisto.results(entry)
