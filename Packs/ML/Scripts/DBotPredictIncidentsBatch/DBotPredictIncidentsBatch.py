import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import copy
import pandas as pd

ALL_LABELS = "*"


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


def build_query_in_respect_to_phishing_labels(args):
    mapping = args.get('phishingLabels', ALL_LABELS)
    query = args.get('query', None)
    if mapping == ALL_LABELS:
        return args
    mapping_dict = get_phishing_map_labels(mapping)
    tag_field = args['tagField']
    tags_union = ' '.join([f'"{label}"' for label in mapping_dict])
    mapping_query = f'{tag_field}:({tags_union})'
    if 'query' not in args:
        args['query'] = mapping_query
    else:
        args['query'] = f'({query}) and ({mapping_query})'
    return args


def main():
    d_args = dict(demisto.args())

    get_incidents_by_query_args = copy.deepcopy(d_args)
    get_incidents_by_query_args['NonEmptyFields'] = d_args['tagField']
    subject_field_name = d_args.get('emailsubject').strip()  # type: ignore
    body_field_name = d_args.get('emailbody').strip()  # type: ignore
    html_field_name = d_args.get('emailbodyhtml').strip()  # type: ignore
    tag_field_name = d_args.get('tagField').strip()  # type: ignore
    additional_populate_fields = d_args.get('populateFields')
    populate_fields = [subject_field_name, body_field_name, html_field_name, tag_field_name, 'id']
    get_incidents_by_query_args['populateFields'] = ','.join([x.strip() for x in populate_fields if x is not None])
    if additional_populate_fields is not None and additional_populate_fields.strip() != '':
        get_incidents_by_query_args['populateFields'] = ','.join([get_incidents_by_query_args['populateFields'],
                                                                 additional_populate_fields.strip()])
    non_empty_fields = [subject_field_name, tag_field_name]
    get_incidents_by_query_args['NonEmptyFields'] = ','.join([x.strip() for x in non_empty_fields if x is not None])
    get_incidents_by_query_args = build_query_in_respect_to_phishing_labels(get_incidents_by_query_args)
    res = demisto.executeCommand("GetIncidentsByQuery", get_incidents_by_query_args)
    if is_error(res):
        return_error(get_error(res))
    incidents = json.loads(res[-1]['Contents'])

    email_subject_list = [i.get(subject_field_name, '') for i in incidents]
    email_body_list = [i.get(body_field_name, '') for i in incidents]
    email_html_list = [i.get(html_field_name, '') for i in incidents]

    model_name = d_args.get('modelName')

    args = {'emailSubject': email_subject_list,
            'emailBody': email_body_list,
            'emailBodyHTML': email_html_list,
            'modelName': model_name}
    res = demisto.executeCommand("DBotPredictPhishingWords", args)
    if is_error(res):
        return_error(get_error(res))

    incidents_df = pd.DataFrame(incidents)
    predictions_df = pd.DataFrame(res[-1]['Contents'])
    df = pd.concat([incidents_df, predictions_df], axis=1)
    df = df.rename(columns={"Label": "Prediction"})
    file_name = 'predictions.csv'
    file_columns = ['id', tag_field_name, 'Prediction',
                    'Probability',
                    'Error']
    if additional_populate_fields is not None and additional_populate_fields.strip() != '':
        file_columns += [x.strip() for x in additional_populate_fields.split(',') if x.strip() != '']
    file_columns = [c for c in file_columns if c in df.columns]
    filtered_df = df[file_columns]
    csv_data = filtered_df.to_csv()
    entry = fileResult(file_name, csv_data)
    entry['Contents'] = filtered_df.to_json(orient='records')
    entry['HumanReadable'] = f'File contains predictions of {len(incidents)} incidents'
    return entry


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
