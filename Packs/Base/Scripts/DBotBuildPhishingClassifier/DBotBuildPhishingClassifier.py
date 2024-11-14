from CommonServerPython import *
import base64
import gc

ALL_LABELS = "*"


def preprocess_incidents_field(incidents_field):
    return incidents_field.strip().removeprefix('incident.')


def get_phishing_map_labels(comma_values):
    if comma_values == ALL_LABELS:
        return comma_values
    values = [x.strip() for x in comma_values.split(",")]
    labels_dict = {}
    for v in values:
        v = v.strip()
        if ":" in v:
            splited = v.rsplit(":", maxsplit=1)
            labels_dict[splited[0].strip()] = splited[1].strip()
        else:
            labels_dict[v] = v
    return dict(labels_dict.items())


def build_query_in_reepect_to_phishing_labels(args):
    mapping = args.get('phishingLabels', ALL_LABELS)
    query = args.get('query', None)
    if mapping == ALL_LABELS:
        return args
    mapping_dict = get_phishing_map_labels(mapping)
    tag_field = args['tagField']
    tags_union = ' '.join([f'"{label}"' for label in mapping_dict])
    mapping_query = f'{tag_field}:({tags_union})'
    if 'query' not in args or args['query'].strip() == '':
        args['query'] = mapping_query
    else:
        args['query'] = f'({query}) and ({mapping_query})'
    return args


def get_incidents(d_args):
    get_incidents_by_query_args = d_args.copy()
    get_incidents_by_query_args['NonEmptyFields'] = d_args['tagField']
    fields_names_to_populate = ['tagField', 'emailsubject', 'emailbody', "emailbodyhtml"]
    fields_to_populate = [get_incidents_by_query_args.get(x, None) for x in fields_names_to_populate]
    fields_to_populate = [x for x in fields_to_populate if x is not None]
    get_incidents_by_query_args['populateFields'] = ','.join(fields_to_populate)
    get_incidents_by_query_args = build_query_in_reepect_to_phishing_labels(get_incidents_by_query_args)
    res = demisto.executeCommand("GetIncidentsByQuery", get_incidents_by_query_args)
    if is_error(res):
        return_error(get_error(res))
    incidents = res[-1]['Contents']
    return incidents


def preprocess_incidents(incidents, d_args):
    text_pre_process_args = d_args.copy()
    text_pre_process_args['inputType'] = 'json_b64_string'
    text_pre_process_args['input'] = base64.b64encode(incidents.encode('utf-8')).decode('ascii')
    text_pre_process_args['preProcessType'] = 'nlp'
    email_body_fields = [text_pre_process_args.get("emailbody"), text_pre_process_args.get("emailbodyhtml")]
    email_body = "|".join([x for x in email_body_fields if x])
    text_pre_process_args['textFields'] = "{},{}".format(text_pre_process_args['emailsubject'], email_body)
    text_pre_process_args['whitelistFields'] = "{},{}".format('dbot_processed_text',
                                                              text_pre_process_args['tagField'])
    res = demisto.executeCommand("DBotPreProcessTextData", text_pre_process_args)
    if is_error(res):
        return_error(get_error(res))
    processed_text_data = res[0]['Contents']
    demisto.results(res)
    return processed_text_data


def train_model(processed_text_data, d_args):
    train_model_args = d_args.copy()
    train_model_args['inputType'] = 'json_b64_string'
    train_model_args['input'] = base64.b64encode(processed_text_data.encode('utf-8')).decode('ascii')
    train_model_args['overrideExistingModel'] = 'true'
    res = demisto.executeCommand("DBotTrainTextClassifierV2", train_model_args)
    demisto.results(res)


def main():
    d_args = demisto.args()
    for arg in ['tagField', 'emailbody', 'emailbodyhtml', 'emailsubject', 'timeField']:
        d_args[arg] = preprocess_incidents_field(d_args.get(arg, ''))

    incidents = get_incidents(d_args)
    gc.collect()

    processed_text_data = preprocess_incidents(incidents, d_args)
    gc.collect()

    train_model(processed_text_data, d_args)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
