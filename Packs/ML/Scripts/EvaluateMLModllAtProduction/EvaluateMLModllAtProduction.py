import numpy as np
import pandas as pd

from CommonServerPython import *

ALL_LABELS = "*"
PREDICTIONS_OUT_FILE_NAME = 'predictions.csv'


def canonize_label(label):
    return label.replace(" ", "_")


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
    if len(set(labels_dict.values())) == 1:
        mapped_value = list(labels_dict.values())[0]
        error = [f'Label mapping error: you need to map to at least two labels: {mapped_value}.']
        return_error('\n'.join(error))
    return {k: canonize_label(v) for k, v in labels_dict.items()}


def get_data_with_mapped_label(y_true_list, labels_mapping):
    mapped_y_true = []
    relevant_indices = []
    for i, y_true in enumerate(y_true_list):
        if labels_mapping == ALL_LABELS:
            mapped_y_true.append(canonize_label(y_true))
            relevant_indices.append(i)
        elif y_true in labels_mapping:
            mapped_y_true.append(canonize_label(labels_mapping[y_true]))
            relevant_indices.append(i)
        else:
            continue
    return mapped_y_true, relevant_indices


def get_ml_model_evaluation(y_test, y_pred, target_accuracy, target_recall, detailed=False):
    res = demisto.executeCommand('GetMLModelEvaluation', {'yTrue': json.dumps(y_test),
                                                          'yPred': json.dumps(y_pred),
                                                          'targetPrecision': str(target_accuracy),
                                                          'targetRecall': str(target_recall),
                                                          'detailedOutput': 'true' if detailed else 'false'
                                                          })
    if is_error(res):
        return_error(get_error(res))
    return res


def output_model_evaluation(y_test, y_pred, res, context_field, human_readable_title=None):
    threshold = float(res[0]['Contents']['threshold'])
    confusion_matrix = json.loads(res[0]['Contents']['csr_matrix_at_threshold'])
    metrics_df = json.loads(res[0]['Contents']['metrics_df'])
    human_readable = res[0]['HumanReadable']
    if human_readable_title is not None:
        human_readable = '\n'.join([human_readable_title, human_readable])
    result_entry = {
        'Type': entryTypes['note'],
        'Contents': {'Threshold': threshold, 'ConfusionMatrixAtThreshold': confusion_matrix,
                     'Metrics': metrics_df, 'YTrue': y_test, 'YPred': y_pred},
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {
            context_field: {
                'EvaluationScores': metrics_df,
                'ConfusionMatrix': confusion_matrix,
            }
        }
    }
    demisto.results(result_entry)
    return confusion_matrix


def return_file_result_with_predictions_on_test_set(data, y_true, y_pred, y_pred_prob, additional_fields):
    predictions_data = {}
    for field in additional_fields:
        predictions_data[field] = [i.get(field, '') for i in data]
    predictions_data['y_true'] = y_true
    predictions_data['y_pred'] = y_pred
    predictions_data['y_pred_prob'] = y_pred_prob
    df = pd.DataFrame(predictions_data)
    non_empty_columns = [field for field in additional_fields if df[field].astype(bool).any()]
    csv_df = df.to_csv(columns=['y_true', 'y_pred', 'y_pred_prob'] + non_empty_columns, encoding='utf-8')
    demisto.results(fileResult(PREDICTIONS_OUT_FILE_NAME, csv_df))


def main(incident_types, incident_query, y_true_field, y_pred_field, y_pred_prob_field, model_target_accuracy,
         labels_mapping, additional_fields):
    non_empty_fields = f'{y_true_field.strip()},{y_pred_field.strip()}'
    incidents_query_args = {'incidentTypes': incident_types,
                            'NonEmptyFields': non_empty_fields,
                            }
    if incident_query is not None:
        incidents_query_args['query'] = incident_query
    incidents_query_res = demisto.executeCommand('GetIncidentsByQuery', incidents_query_args)
    if is_error(incidents_query_res):
        return_error(get_error(incidents_query_res))
    incidents = json.loads(incidents_query_res[0]['Contents'])
    if incidents:
        demisto.results(f'Found {len(incidents)} incident(s)')
        y_true = []
        y_pred = []
        y_pred_prob = []
        incidents_with_missing_pred_prob = 0
        for i in incidents:
            y_true.append(i[y_true_field])
            y_pred.append(i[y_pred_field])
            if y_pred_prob_field not in i:
                incidents_with_missing_pred_prob += 1
            y_pred_prob.append(i.get(y_pred_prob_field, None))
        y_true, relevant_indices = get_data_with_mapped_label(y_true, labels_mapping)
        y_pred = [y_pred[i] for i in relevant_indices]
        y_pred_prob = [y_pred_prob[i] for i in relevant_indices]
        incidents = [incidents[i] for i in relevant_indices]
        y_pred_prob_is_given = incidents_with_missing_pred_prob == 0
        if y_pred_prob_is_given:
            y_pred_dict = [{label: prob} for label, prob in zip(y_pred, y_pred_prob)]
        else:
            y_pred_dict = [{label: 1.0} for label in y_pred]
        if y_pred_prob_is_given:
            res_threshold = get_ml_model_evaluation(y_true, y_pred_dict, model_target_accuracy, target_recall=0,
                                                    detailed=True)
            # show results for the threshold found - last result so it will appear first
            output_model_evaluation(y_test=y_true, y_pred=y_pred_dict, res=res_threshold,
                                    context_field='EvaluateMLModllAtProduction')
        # show results if no threshold (threhsold=0) was used. Following code is reached only if a legal thresh was found:
        if not y_pred_prob_is_given or not np.isclose(float(res_threshold[0]['Contents']['threshold']), 0):
            res = get_ml_model_evaluation(y_true, y_pred_dict, target_accuracy=0, target_recall=0)
            human_readable = '\n'.join(['## Results for No Threshold',
                                        'The following results were achieved by using no threshold (threshold equals 0)'])
            output_model_evaluation(y_test=y_true, y_pred=y_pred_dict, res=res,
                                    context_field='EvaluateMLModllAtProductionNoThresh',
                                    human_readable_title=human_readable)
        return_file_result_with_predictions_on_test_set(incidents, y_true, y_pred, y_pred_prob, additional_fields)
    else:
        return_results('No incidents found.')


model_target_accuracy = demisto.args().get('modelTargetAccuracy', 0)
incident_types = demisto.args()['incidentTypes']
incident_query = demisto.args().get('incidentsQuery', None)
y_true_field = demisto.args()['emailTagKey']
y_pred_field = demisto.args()['emailPredictionKey']
y_pred_prob_field = demisto.args()['emailPredictionProbabilityKey']

labels_mapping = get_phishing_map_labels(demisto.args()['phishingLabels'])
additional_fields = demisto.args().get('additionalFields', '')
additional_fields = additional_fields.split(',')
additional_fields = [x.strip() for x in additional_fields]
main(incident_types, incident_query, y_true_field, y_pred_field, y_pred_prob_field, model_target_accuracy,
     labels_mapping, additional_fields)
