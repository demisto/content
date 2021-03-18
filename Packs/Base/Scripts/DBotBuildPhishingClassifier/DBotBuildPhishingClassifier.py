import base64
import copy

from CommonServerPython import *

PREFIXES_TO_REMOVE = ['incident.']
ALL_LABELS = "*"


def preprocess_incidents_field(incidents_field):
    incidents_field = incidents_field.strip()
    for prefix in PREFIXES_TO_REMOVE:
        if incidents_field.startswith(prefix):
            incidents_field = incidents_field[len(prefix):]
    return incidents_field


def get_phishing_map_labels(comma_values):
    if comma_values == ALL_LABELS:
        return comma_values
    values = [x.strip() for x in comma_values.split(",")]
    labels_dict = {}
    for v in values:
        v = v.strip()
        if ":" in v:
            splited = v.split(":")
            labels_dict[splited[0].strip()] = splited[1].strip()
        else:
            labels_dict[v] = v
    return {k: v for k, v in labels_dict.items()}


def build_query_in_reepect_to_phishing_labels(args):
    mapping = args.get('phishingLabels', ALL_LABELS)
    query = args.get('query', None)
    if mapping == ALL_LABELS:
        return args
    mapping_dict = get_phishing_map_labels(mapping)
    tag_field = args['tagField']
    tags_union = ' '.join(['"{}"'.format(label) for label in mapping_dict])
    mapping_query = '{}:({})'.format(tag_field, tags_union)
    if 'query' not in args:
        args['query'] = mapping_query
    else:
        args['query'] = '({}) and ({})'.format(query, mapping_query)
    return args


def main():
    d_args = dict(demisto.args())
    for arg in ['tagField', 'emailbody', 'emailbodyhtml', 'emailsubject', 'timeField']:
        d_args[arg] = preprocess_incidents_field(d_args.get(arg, ''))

    get_incidents_by_query_args = copy.deepcopy(d_args)
    get_incidents_by_query_args['NonEmptyFields'] = d_args['tagField']
    fields_names_to_populate = ['tagField', 'emailsubject', 'emailbody', "emailbodyhtml"]
    fields_to_populate = [get_incidents_by_query_args.get(x, None) for x in fields_names_to_populate]
    fields_to_populate = [x for x in fields_to_populate if x is not None]
    get_incidents_by_query_args['populateFileds'] = ','.join(fields_to_populate)
    get_incidents_by_query_args = build_query_in_reepect_to_phishing_labels(get_incidents_by_query_args)
    res = demisto.executeCommand("GetIncidentsByQuery", get_incidents_by_query_args)
    if is_error(res):
        return_error(get_error(res))
    incidents = res[-1]['Contents']

    text_pre_process_args = copy.deepcopy(d_args)
    text_pre_process_args['inputType'] = 'json_b64_string'
    text_pre_process_args['input'] = base64.b64encode(incidents.encode('utf-8')).decode('ascii')
    text_pre_process_args['preProcessType'] = 'nlp'
    email_body_fields = [text_pre_process_args.get("emailbody"), text_pre_process_args.get("emailbodyhtml")]
    email_body = "|".join([x for x in email_body_fields if x])
    text_pre_process_args['textFields'] = "%s,%s" % (text_pre_process_args['emailsubject'], email_body)
    text_pre_process_args['whitelistFields'] = "{0},{1}".format('dbot_processed_text',
                                                                text_pre_process_args['tagField'])
    res = demisto.executeCommand("DBotPreProcessTextData", text_pre_process_args)
    if is_error(res):
        return_error(get_error(res))

    processed_text_data = res[0]['Contents']
    demisto.results(res)
    train_model_args = copy.deepcopy(d_args)
    train_model_args['inputType'] = 'json_b64_string'
    train_model_args['input'] = base64.b64encode(processed_text_data.encode('utf-8')).decode('ascii')
    train_model_args['overrideExistingModel'] = 'true'
    res = demisto.executeCommand("DBotTrainTextClassifierV2", train_model_args)
    demisto.results(res)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
