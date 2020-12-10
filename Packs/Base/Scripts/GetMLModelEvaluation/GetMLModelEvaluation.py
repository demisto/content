import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, precision_recall_curve
from tabulate import tabulate
from typing import Dict
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
    return np.where(arr >= threshold, 1.0, 0)


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
        row = calculate_df_row(class_, threshold, y_true_per_class, y_pred_per_class)
        df = df.append(row, ignore_index=True)
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


def calculate_df_row(class_, threshold, y_true_per_class, y_pred_per_class):
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
    row = {'Class': class_,
           'Precision': precision,
           'Recall': recall,
           'TP': classified_correctly,
           'FP': fp,
           'Coverage': int(above_thresh),
           'Total': total}
    return row


def reformat_df_fractions_to_percentage(metrics_df):
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


def output_report(y_true, y_true_per_class, y_pred, y_pred_per_class, found_threshold, target_precision,
                  actual_threshold_precision, detailed_output=True):
    csr_matrix_at_threshold = calculate_confusion_matrix(y_true, y_pred, y_pred_per_class, found_threshold)
    csr_matrix_no_threshold = calculate_confusion_matrix(y_true, y_pred, y_pred_per_class, 0)

    metrics_df, metrics_explanation = generate_metrics_df(y_true, y_true_per_class, y_pred, y_pred_per_class,
                                                          found_threshold)

    coverage = metrics_df.loc[['All']]['Coverage'][0]
    test_set_size = metrics_df.loc[['All']]['Total'][0]
    human_readable_threshold = ['## Summary']
    # in case the found threshold meets the target accuracy
    if actual_threshold_precision >= target_precision or abs(found_threshold - target_precision) < 10 ** -2:
        human_readable_threshold += ['- A confidence threshold of {:.2f} meets the conditions of required precision.'
                                     .format(found_threshold)]
    else:
        human_readable_threshold += ['- Could not find a threshold which meets the conditions of required precision. '
                                     'The confidence threshold of {:.2f} achieved highest '
                                     'possible precision'.format(found_threshold)]
    human_readable_threshold += [
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

    tablualted_csr = tabulate(reformat_df_fractions_to_percentage(metrics_df), tablefmt="pipe", headers="keys")
    class_metrics_human_readable = ['## Metrics per Class', tablualted_csr]
    class_metrics_explanation_human_readable = ['### Metrics Explanation'] + ['- ' + row for row in metrics_explanation]
    csr_matrix_readable = ['## Confusion Matrix',
                           'This table displays the predictions of the model on the evaluation set per each '
                           + 'class:',
                           tabulate(csr_matrix_at_threshold,
                                    tablefmt="pipe",
                                    headers="keys").replace("True", "True \\ Predicted"),
                           '\n']
    csr_matrix_no_thresh_readable = ['## Confusion Matrix - No Threshold',
                                     'This table displays the predictions of the model on the evaluation set per each '
                                     + 'class when no threshold is used:',
                                     tabulate(csr_matrix_no_threshold,
                                              tablefmt="pipe",
                                              headers="keys").replace("True", "True \\ Predicted"),
                                     '\n']
    human_readable = []  # type: ignore
    if detailed_output:
        human_readable += human_readable_threshold + ['\n']
    else:
        human_readable += ['## Results for confidence threshold = {:.2f}'.format(found_threshold)] + ['\n']
    human_readable += class_metrics_human_readable + ['\n']
    human_readable += class_metrics_explanation_human_readable
    human_readable += csr_matrix_readable
    human_readable += csr_matrix_no_thresh_readable
    human_readable = '\n'.join(human_readable)
    contents = {'threshold': found_threshold,
                'csr_matrix_at_threshold': csr_matrix_at_threshold.to_json(orient='index'),
                'csr_matrix_no_threshold': csr_matrix_no_threshold.to_json(orient='index'),
                'metrics_df': metrics_df.to_json()}
    entry = {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {
            'GetMLModelEvaluation': {
                'Threshold': found_threshold,
                'ConfusionMatrixAtThreshold': csr_matrix_at_threshold.to_json(orient='index'),
                'ConfusionMatrixNoThreshold': csr_matrix_no_threshold.to_json(orient='index'),
                'Metrics': metrics_df.to_json()
            }
        }
    }
    return entry


def merge_entries(entry, per_class_entry):
    entry = {
        'Type': entryTypes['note'],
        'Contents': entry['Contents'],
        'ContentsFormat': formats['json'],
        'HumanReadable': entry['HumanReadable'] + '\n' + per_class_entry['HumanReadable'],
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {**entry['EntryContext'], **per_class_entry['EntryContext']}
    }
    return entry


def find_threshold(y_true_str, y_pred_str, customer_target_precision, target_recall, detailed_output=True):
    y_true = convert_str_to_json(y_true_str, 'yTrue')
    y_pred_all_classes = convert_str_to_json(y_pred_str, 'yPred')
    labels = sorted(set(y_true + list(y_pred_all_classes[0].keys())))
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

    class_to_arrs = {class_: {} for class_ in labels}  # type: Dict[str, Dict[str, Any]]
    for class_ in labels:
        precision_arr, recall_arr, thresholds_arr = precision_recall_curve(y_true_per_class[class_],
                                                                           y_pred_per_class[class_])
        class_to_arrs[class_]['precisions'] = precision_arr
        class_to_arrs[class_]['recalls'] = recall_arr
        class_to_arrs[class_]['thresholds'] = thresholds_arr

    # find threshold for all classes such as precision of all classes are higher than target precision:
    unified_threshold, unified_threshold_precision, target_unified_precision = find_best_threshold_for_target_precision(
        class_to_arrs, customer_target_precision, labels)
    if unified_threshold is None or unified_threshold_precision is None:
        error_message = 'Could not find any threshold at ranges {} - {:.2f}.'.format(target_unified_precision,
                                                                                     customer_target_precision)
        return_error(error_message)
    entry = output_report(np.array(y_true), y_true_per_class, np.array(y_pred), y_pred_per_class, unified_threshold,
                          customer_target_precision, unified_threshold_precision, detailed_output)
    per_class_entry = calculate_per_class_report_entry(class_to_arrs, labels, y_pred_per_class, y_true_per_class)
    res = merge_entries(entry, per_class_entry)
    return res


def find_best_threshold_for_target_precision(class_to_arrs, customer_target_precision, labels):
    target_unified_precision = round(customer_target_precision, 2)
    unified_threshold_found = False
    threshold = None
    threshold_precision = None
    while not unified_threshold_found:
        threshold_per_class = {}
        precision_per_class = {}
        for class_ in labels:
            # indexing is done by purpose - the ith precision corresponds with threshold i-1. Last precision is 1
            for i, precision in enumerate(class_to_arrs[class_]['precisions'][:-1]):
                if class_to_arrs[class_]['thresholds'][i] == 0:
                    continue
                if precision > target_unified_precision:
                    threshold_per_class[class_] = class_to_arrs[class_]['thresholds'][i]
                    precision_per_class[class_] = precision
                    break
        if len(threshold_per_class) == len(labels):
            threshold_candidates = sorted(list(threshold_per_class.values()))
            for threshold in threshold_candidates:
                legal_threshold_for_all_classes = True
                threshold_precision = sys.maxsize
                for class_ in labels:
                    i = np.argmax(class_to_arrs[class_]['thresholds'] >= threshold)
                    threshold_precision_for_class = class_to_arrs[class_]['precisions'][i]
                    threshold_precision = min(threshold_precision, threshold_precision_for_class)
                    if threshold_precision_for_class >= target_unified_precision:
                        legal_threshold_for_all_classes = True
                    else:
                        legal_threshold_for_all_classes = False
                        break
                if legal_threshold_for_all_classes:
                    unified_threshold_found = True
                    break
        elif target_unified_precision < 0:
            break
        target_unified_precision -= 0.01
    return threshold, threshold_precision, target_unified_precision


def calculate_per_class_report_entry(class_to_arrs, labels, y_pred_per_class, y_true_per_class):
    per_class_hr = ['## Per-Class Report']
    per_class_hr += [
        'The following tables present evlauation of the model per class at different confidence thresholds:']
    class_to_thresholds = {}
    for class_ in labels:
        class_to_thresholds[class_] = set([0.001])  # using no threshold
        for target_precision in np.arange(0.95, 0.5, -0.05):
            # indexing is done by purpose - the ith precision corresponds with threshold i-1. Last precision is 1
            for i, precision in enumerate(class_to_arrs[class_]['precisions'][:-1]):
                if class_to_arrs[class_]['thresholds'][i] == 0:
                    continue
                if precision > target_precision and class_to_arrs[class_]['recalls'][i] > 0:
                    threshold = class_to_arrs[class_]['thresholds'][i]
                    class_to_thresholds[class_].add(threshold)
                    break
            if len(class_to_thresholds[class_]) >= 4:
                break
    per_class_context = {}
    for class_ in labels:
        class_threshold_df = pd.DataFrame(columns=['Threshold', 'Precision', 'Recall', 'TP', 'FP', 'Coverage', 'Total'])
        for threshold in sorted(class_to_thresholds[class_]):
            row = calculate_df_row(class_, threshold, y_true_per_class, y_pred_per_class)
            row['Threshold'] = threshold
            class_threshold_df = class_threshold_df.append(row, ignore_index=True)
        class_threshold_df = reformat_df_fractions_to_percentage(class_threshold_df)
        class_threshold_df['Threshold'] = class_threshold_df['Threshold'].apply(lambda p: '{:.2f}'.format(p))
        class_threshold_df = class_threshold_df[['Threshold', 'Precision', 'TP', 'FP', 'Coverage', 'Total']]
        class_threshold_df.sort_values(by='Coverage', ascending=False, inplace=True)
        class_threshold_df.drop_duplicates(subset='Threshold', inplace=True, keep='first')
        class_threshold_df.drop_duplicates(subset='Precision', inplace=True, keep='first')
        class_threshold_df.set_index('Threshold', inplace=True)
        per_class_context[class_] = class_threshold_df.to_json()
        tabulated_class_df = tabulate(class_threshold_df, tablefmt="pipe", headers="keys")
        per_class_hr += ['### {}'.format(class_), tabulated_class_df]
    per_class_entry = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': [],
        'HumanReadable': '\n'.join(per_class_hr),
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {'GetMLModelEvaluation': {'PerClassReport': per_class_context}}
    }
    return per_class_entry


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
    entries = find_threshold(y_true_str=y_true,
                             y_pred_str=y_pred_all_classes,
                             customer_target_precision=target_precision,
                             target_recall=target_recall,
                             detailed_output=detailed_output)

    demisto.results(entries)


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
