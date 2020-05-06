import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score
from tabulate import tabulate

from CommonServerPython import *

# pylint: disable=no-member

METRICS = {}
METRICS['Precision'] = 'The precision of the class in the evaluation set that were classified as this class by the ' \
                       'model. Precision is calculated by dividing the TPs of the class by the number of incidents that ' \
                       'the model predicted as this class.'
METRICS['TP (true positive)'] = 'The number of incidents from the class in the evaluation set that were predicted ' \
                                'correctly. '
METRICS['FP (false positive)'] = 'The number of incidents from other classes that were predicted incorrectly as this class.'
METRICS['Coverage'] = 'The number of incidents from the class in the evaluation set for which the confidence level of ' \
                      'the model exceeded the threshold in the prediction.'
METRICS['Total'] = 'The total number of incidents from the class in the evaluation set.'


def bold_hr(s):
    return '**{}:**'.format(s)


def binarize(arr, threshold):
    return np.where(arr > threshold, 1.0, 0)


def calculate_confusion_matrix(y_true, y_pred, y_pred_per_class, threshold):
    indices_higher_than_threshold = set()
    for i, y in enumerate(y_pred):
        if y_pred_per_class[y][i] >= threshold:
            indices_higher_than_threshold.add(i)

    y_true_at_threshold = [y for i, y in enumerate(y_true) if i in indices_higher_than_threshold]
    y_pred_at_threshold = [y for i, y in enumerate(y_pred) if i in indices_higher_than_threshold]
    test_tag = pd.Series(y_true_at_threshold)
    ft_test_predictions_labels = pd.Series(y_pred_at_threshold)
    csr_matrix = pd.crosstab(test_tag, ft_test_predictions_labels, rownames=['True'], colnames=['Predicted'],
                             margins=True)
    return csr_matrix


def generate_metrics_df(y_true, y_true_per_class, y_pred, y_pred_per_class, threshold):
    df = pd.DataFrame(columns=['Class', 'Precision', 'Recall', 'TP', 'FP', 'Coverage', 'Total'])
    for class_ in sorted(y_pred_per_class):
        y_pred_class = y_pred_per_class[class_]
        y_true_class = y_true_per_class[class_]
        y_pred_class_binary = binarize(y_pred_class, threshold)
        precision = precision_score(y_true=y_true_class, y_pred=y_pred_class_binary)
        recall = recall_score(y_true=y_true_class, y_pred=y_pred_class_binary)
        classified_correctly = sum(1 for y_true_i, y_pred_i in zip(y_true_class, y_pred_class_binary) if y_true_i == 1
                                   and y_pred_i == 1)
        above_thresh = sum(1 for i, y_true_i in enumerate(y_true_class) if y_true_i == 1
                           and any(y_pred_per_class[c][i] >= threshold for c in y_pred_per_class))
        fp = sum(1 for i, y_true_i in enumerate(y_true_class) if y_true_i == 0 and y_pred_class_binary[i] == 1.0)
        total = int(sum(y_true_class))
        df = df.append({'Class': class_,
                        'Precision': precision,
                        'Recall': recall,
                        'TP': classified_correctly,
                        'FP': fp,
                        'Coverage': int(above_thresh),
                        'Total': total}, ignore_index=True)
    df = df.append({'Class': 'All',
                    'Precision': df["Precision"].mean(),
                    'Recall': df["Recall"].mean(),
                    'TP': df["TP"].sum(),
                    'FP': df["FP"].sum(),
                    'Coverage': df["Coverage"].sum(),
                    'Total': df["Total"].sum()}, ignore_index=True)
    df = df[['Class', 'Precision', 'TP', 'FP', 'Coverage', 'Total']]
    explained_metrics = ['Precision', 'TP (true positive)', 'FP (false positive)', 'Coverage', 'Total']
    explanation = ['{} {}'.format(bold_hr(metric), METRICS[metric]) for metric in explained_metrics]
    df.set_index('Class', inplace=True)
    return df, explanation


def convert_df_to_human(metrics_df):
    hr_df = metrics_df.copy()
    hr_df['Precision'] = hr_df['Precision'].apply(lambda p: '{:.1f}%'.format(p * 100))
    hr_df['TP'] = hr_df.apply(lambda row: '{}/{} ({:.1f}%)'.format(int(row['TP']),
                                                                   int(row['Coverage']),
                                                                   float(row['TP']) * 100 / row['Coverage']),
                              axis=1)
    hr_df['Coverage'] = hr_df.apply(lambda row: '{}/{} ({:.1f}%)'.format(int(row['Coverage']), row['Total'],
                                                                         float(row['Coverage']) * 100 / row['Total']),
                                    axis=1)
    return hr_df


def output_report(y_true, y_true_per_class, y_pred, y_pred_per_class, threshold, detailed_output=True):
    csr_matrix_at_threshold = calculate_confusion_matrix(y_true, y_pred, y_pred_per_class, threshold)
    metrics_df, metrics_explanation = generate_metrics_df(y_true, y_true_per_class, y_pred, y_pred_per_class, threshold)

    coverage = metrics_df.loc[['All']]['Coverage'][0]
    test_set_size = metrics_df.loc[['All']]['Total'][0]
    human_readable_threshold = [
        '## Summary',
        '- A confidence threshold of {:.2f} meets the conditions of required precision.'.format(threshold),
        '- {}/{} incidents of the evaluation set were predicted with higher confidence than this threshold.'.format(
            int(coverage), int(test_set_size)),
        '- The remainder, {}/{} incidents of the evaluation set, were predicted with lower confidence than this threshold '
        '(these predictions were ignored).'.format(
            int(test_set_size - coverage), int(test_set_size)),
        '- Expected coverage ratio: The model will attempt to provide a prediction for {:.2f}% of incidents. '
        '({}/{})'.format(
            float(coverage) / test_set_size * 100, int(coverage), int(test_set_size)),
        '- Evaluation of the model performance using this probability threshold can be found below:']
    pd.set_option('display.max_columns', None)

    tablualted_csr = tabulate(convert_df_to_human(metrics_df), tablefmt="pipe", headers="keys")
    class_metrics_human_readable = ['## Metrics per Class', tablualted_csr]
    class_metrics_explanation_human_readable = ['### Metrics Explanation'] + ['- ' + row for row in metrics_explanation]
    csr_matrix_readable = ['## Confusion Matrix',
                           'This table displays the predictions of the model on the evaluation set per each '
                           + 'class:',
                           tabulate(csr_matrix_at_threshold,
                                    tablefmt="pipe",
                                    headers="keys").replace("True", "True \\ Predicted"),
                           '\n']
    human_readable = []  # type: ignore
    if detailed_output:
        human_readable += human_readable_threshold + ['\n']
    else:
        human_readable += ['## Results for confidence threshold = {:.2f}'.format(threshold)] + ['\n']
    human_readable += class_metrics_human_readable + ['\n']
    human_readable += class_metrics_explanation_human_readable
    human_readable += csr_matrix_readable
    human_readable = '\n'.join(human_readable)
    contents = {'threshold': threshold, 'csr_matrix_at_threshold': csr_matrix_at_threshold.to_json(),
                'metrics_df': metrics_df.to_json()}
    entry = {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {
            'GetMLModelEvaluation': {
                'Threshold': threshold,
                'ConfusionMatrixAtThreshold': csr_matrix_at_threshold.to_json(),
                'Metrics': metrics_df.to_json()
            }
        }
    }
    return entry


def find_threshold(y_true_str, y_pred_str, target_precision, target_recall, detailed_output=True):
    y_true = convert_str_to_json(y_true_str, 'yTrue')
    y_pred_all_classes = convert_str_to_json(y_pred_str, 'yPred')
    labels = sorted(set(y_true + y_pred_all_classes[0].keys()))
    n_instances = len(y_true)
    y_true_per_class = {class_: np.zeros(n_instances) for class_ in labels}
    for i, y in enumerate(y_true):
        y_true_per_class[y][i] = 1.0
    y_pred_per_class = {class_: np.zeros(n_instances) for class_ in labels}
    y_pred = []
    for i, y in enumerate(y_pred_all_classes):
        predicted_class = sorted(y.items(), key=lambda x: x[1], reverse=True)[0][0]
        y_pred_per_class[predicted_class][i] = y[predicted_class]
        y_pred.append(predicted_class)
    for threshold in np.arange(0, 1, 0.05):
        if any(binarize(y_pred_per_class[class_], threshold).sum() == 0 for class_ in labels):
            break
        if all(precision_score(y_true_per_class[class_],
                               binarize(y_pred_per_class[class_], threshold)) >= target_precision for class_ in
               labels) and \
                all(recall_score(y_true_per_class[class_],
                                 binarize(y_pred_per_class[class_], threshold)) >= target_recall for class_ in labels):
            entry = output_report(np.array(y_true), y_true_per_class, np.array(y_pred), y_pred_per_class,
                                  threshold, detailed_output)
            return entry

    return_error('Could not find threshold which satisfies the following conditions :\n\
    1. precision larger or equal than {} for all classes \n\
    2. recall larger or equal than {} for all classes'.format(target_precision, target_recall))


def convert_str_to_json(str_json, var_name):
    try:
        y_true = json.loads(str_json)
        return y_true
    except Exception as e:
        return_error('Exception while reading {} :{}'.format(var_name, e))


def main():
    y_pred_all_classes = demisto.args()["yPred"]
    y_true = demisto.args()["yTrue"]
    target_precision = calculate_and_validate_float_parameter("targetPrecision")
    target_recall = calculate_and_validate_float_parameter("targetRecall")
    detailed_output = 'detailedOutput' in demisto.args() and demisto.args()['detailedOutput'] == 'true'
    entry = find_threshold(y_true_str=y_true,
                           y_pred_str=y_pred_all_classes,
                           target_precision=target_precision,
                           target_recall=target_recall,
                           detailed_output=detailed_output)

    demisto.results(entry)


def calculate_and_validate_float_parameter(var_name):
    try:
        res = float(demisto.args()[var_name]) if var_name in demisto.args() else 0
    except Exception:
        return_error('{} must be a float between 0-1 or left empty'.format(var_name))
    if res < 0 or res > 1:
        return_error('{} must be a float between 0-1 or left empty'.format(var_name))
    return res


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
