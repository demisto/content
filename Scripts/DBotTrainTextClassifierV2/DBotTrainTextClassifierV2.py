# pylint: disable=no-member
from collections import defaultdict, Counter
from io import BytesIO, StringIO

import demisto_ml
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold

from CommonServerPython import *

ALL_LABELS = "*"
GENERAL_SCORES = {
    'micro avg': 'The metrics is applied globally by counting the total true positives, '
                 'false negatives and false positives',
    'macro avg': 'The metrics is applied for each label, and find their unweighted mean.',
    'weighted avg': 'The metrics is applied for each label, and find their average weighted by support '
                    '(the number of true instances for each label). This alters macro to account for label imbalance;'
}

DBOT_TAG_FIELD = "dbot_internal_tag_field"
MIN_INCIDENTS_THRESHOLD = 50


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
            splited = v.split(":")
            labels_dict[splited[0].strip()] = splited[1].strip()
        else:
            labels_dict[v] = v
    if len(set(labels_dict.values())) == 1:
        mapped_value = list(labels_dict.values())[0]
        error = ['Label mapping error: you need to map to at least two labels: {}.'.format(mapped_value)]
        return_error('\n'.join(error))
    return {k: canonize_label(v) for k, v in labels_dict.items()}


def read_file(input_entry_or_string, file_type):
    data = []  # type: List[Dict[str, str]]
    if not input_entry_or_string:
        return data
    if file_type.endswith("string"):
        if 'b64' in file_type:
            input_entry_or_string = base64.b64decode(input_entry_or_string)
        if isinstance(input_entry_or_string, str):
            file_content = BytesIO(input_entry_or_string)
        elif isinstance(input_entry_or_string, unicode):
            file_content = StringIO(input_entry_or_string)  # type: ignore
    else:
        res = demisto.getFilePath(input_entry_or_string)
        if not res:
            return_error("Entry {} not found".format(input_entry_or_string))
        file_path = res['path']
        with open(file_path, 'rb') as f:
            file_content = BytesIO(f.read())
    if file_type.startswith('json'):
        return json.loads(file_content.getvalue())
    elif file_type.startswith('pickle'):
        return pd.read_pickle(file_content, compression=None)
    else:
        return_error("Unsupported file type %s" % file_type)


def get_file_entry_id(file_name):
    file_name = file_name.strip()
    res = demisto.dt(demisto.context(), "File(val.Name == '%s')" % file_name)
    if not res or len(res) == 0:
        return_error("Cannot find file entry id in context by filename: " + file_name)
    if type(res) is list:
        res = res[0]
    return res['EntryID']


def read_files_by_name(file_names, input_type):
    file_names = file_names.split(",")
    file_names = [f for f in file_names if f]
    data = []  # type: List[Dict[str, str]]
    for file_name in file_names:
        data += read_file(get_file_entry_id(file_name), input_type)
    return data


def get_data_with_mapped_label(data, labels_mapping, tag_field):
    new_data = []
    exist_labels_counter = defaultdict(int)  # type: Dict[str, int]
    missing_labels_counter = defaultdict(int)  # type: Dict[str, int]
    for row in data:
        original_label = row[tag_field]
        if labels_mapping == ALL_LABELS:
            row[tag_field] = canonize_label(original_label)
        else:
            if original_label in labels_mapping:
                row[tag_field] = labels_mapping[original_label]
            else:
                missing_labels_counter[original_label] += 1
                continue
        exist_labels_counter[original_label] += 1
        new_data.append(row)

    return new_data, dict(exist_labels_counter), dict(missing_labels_counter)


def store_model_in_demisto(model_name, model_override, train_text_data, train_tag_data, confusion_matrix):
    model = demisto_ml.train_text_classifier(train_text_data, train_tag_data, True)
    model_data = demisto_ml.encode_model(model)
    model_labels = demisto_ml.get_model_labels(model)

    res = demisto.executeCommand('createMLModel', {'modelData': model_data,
                                                   'modelName': model_name,
                                                   'modelLabels': model_labels,
                                                   'modelOverride': model_override})
    if is_error(res):
        return_error(get_error(res))
    confusion_matrix_no_all = {k: v for k, v in confusion_matrix.items() if k != 'All'}
    confusion_matrix_no_all = {k: {sub_k: sub_v for sub_k, sub_v in v.items() if sub_k != 'All'}
                               for k, v in confusion_matrix_no_all.items()}
    res = demisto.executeCommand('evaluateMLModel',
                                 {'modelConfusionMatrix': confusion_matrix_no_all,
                                  'modelName': model_name})
    if is_error(res):
        return_error(get_error(res))


def find_keywords(data, tag_field, text_field, min_score):
    keywords = demisto_ml.get_keywords_for_labels(data, tag_field, text_field)
    human_readable = "# Keywords per category\n"
    for category, scores in keywords.items():
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        table_items = [{"Word": word, "Score": score} for word, score in sorted_scores if score >= min_score]
        human_readable += tableToMarkdown(category, table_items, ["Word", "Score"])
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': keywords,
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
    })


def set_tag_field(data, tag_fields):
    empty_label_indices = []
    for i, d in enumerate(data):
        found_field = False
        for field in tag_fields:
            if d.get(field):
                d[DBOT_TAG_FIELD] = d[field]
                found_field = True
                break
        if not found_field:
            empty_label_indices.append(i)
    data = [d for i, d in enumerate(data) if i not in empty_label_indices]
    return data


def get_predictions_for_test_set(train_text_data, train_tag_data):
    X = pd.Series(train_text_data)
    y = pd.Series(train_tag_data)
    train_set_ratio = float(demisto.args()['trainSetRatio'])
    n_splits = int(1.0 / (1 - train_set_ratio))
    skf = StratifiedKFold(n_splits=n_splits, shuffle=False, random_state=None)
    skf.get_n_splits(X, y)
    train_index, test_index = list(skf.split(X, y))[-1]
    X_train, X_test = list(X[train_index]), list(X[test_index])
    y_train, y_test = list(y[train_index]), list(y[test_index])
    model = demisto_ml.train_text_classifier(X_train, y_train)
    ft_test_predictions = demisto_ml.predict(model, X_test)
    y_pred = [{y_tuple[0]: y_tuple[1]} for y_tuple in ft_test_predictions]
    return y_test, y_pred


def output_model_evaluation(model_name, train_tag_data, train_text_data, y_test, y_pred, res, context_field,
                            store_model=False, model_override=False, human_readable_title=None):
    threshold = float(res[0]['Contents']['threshold'])
    confusion_matrix = json.loads(res[0]['Contents']['csr_matrix_at_threshold'])
    metrics_df = json.loads(res[0]['Contents']['metrics_df'])
    human_readable = res[0]['HumanReadable']
    # store model
    if store_model:
        store_model_in_demisto(model_name, model_override, train_text_data, train_tag_data, confusion_matrix)
        human_readable += "\nDone training on {} samples model stored successfully".format(len(train_text_data))
    else:
        human_readable += "\n\nSkip storing model"
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
                'ModelName': model_name,
                'EvaluationScores': metrics_df,
                'ConfusionMatrix': confusion_matrix,
            }
        }
    }
    demisto.results(result_entry)


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


def validate_data_and_labels(data, exist_labels_counter, labels_mapping, missing_labels_counter):
    labels_counter = Counter([x[DBOT_TAG_FIELD] for x in data])
    labels_below_thresh = [l for l, count in labels_counter.items() if count < MIN_INCIDENTS_THRESHOLD]
    if len(labels_below_thresh) > 0:
        err = ['Minimum number of incidents per label required for training is {}.'.format(MIN_INCIDENTS_THRESHOLD)]
        err += ['The following labels have less than {} incidents: '.format(MIN_INCIDENTS_THRESHOLD)]
        for l in labels_below_thresh:
            err += ['- {}: {}'.format(l, str(labels_counter[l]))]
        err += ['Make sure that enough incidents exist in the environment per each of these labels.']
        missing_labels = ', '.join(missing_labels_counter.keys())
        err += ['The following labels were not mapped to any label in the labels mapping: {}.'.format(missing_labels)]
        if labels_mapping != ALL_LABELS:
            err += ['The given mapped labels are: {}.'.format(', '.join(labels_mapping.keys()))]
        return_error('\n'.join(err))
    if len(missing_labels_counter) > 0:
        human_readable = tableToMarkdown("Skip labels - did not match any of specified labels", missing_labels_counter)
        entry = {
            'Type': entryTypes['note'],
            'Contents': missing_labels_counter,
            'ContentsFormat': formats['json'],
            'HumanReadable': human_readable,
            'HumanReadableFormat': formats['markdown'],
        }
        demisto.results(entry)
    if len(exist_labels_counter) > 0:
        exist_labels_counter_mapped = {}
        for label, count in exist_labels_counter.items():
            mapped_label = labels_mapping[label] if isinstance(labels_mapping, dict) else label
            if mapped_label != label:
                label = "%s -> %s" % (label, mapped_label)
            exist_labels_counter_mapped[label] = count
        human_readable = tableToMarkdown("Found labels", exist_labels_counter_mapped)
        entry = {
            'Type': entryTypes['note'],
            'Contents': exist_labels_counter,
            'ContentsFormat': formats['json'],
            'HumanReadable': human_readable,
            'HumanReadableFormat': formats['markdown'],
        }
        demisto.results(entry)
    demisto.results(set([x[DBOT_TAG_FIELD] for x in data]))
    if len(set([x[DBOT_TAG_FIELD] for x in data])) == 1:
        single_label = [x[DBOT_TAG_FIELD] for x in data][0]
        if labels_mapping == ALL_LABELS:
            err = ['All received incidents have the same label: {}.'.format(single_label)]
        else:
            err = ['All received incidents mapped to the same label: {}.'.format(single_label)]
        err += ['At least 2 different labels are required to train a classifier.']
        if labels_mapping == ALL_LABELS:
            err += ['Please make sure that incidents of at least 2 labels exist in the environment.']
        else:
            err += ['The following labels were not mapped to any label in the labels mapping:']
            err += [', '.join([l for l in missing_labels_counter])]
            not_found_mapped_label = [l for l in labels_mapping if l not in exist_labels_counter
                                      or exist_labels_counter[l] == 0]
            if len(not_found_mapped_label) > 0:
                miss = ', '.join(not_found_mapped_label)
                err += ['Notice that the following mapped labels were not found among all incidents: {}.'.format(miss)]
        return_error('\n'.join(err))


def main():
    input = demisto.args()['input']
    input_type = demisto.args()['inputType']
    model_name = demisto.args()['modelName']
    store_model = demisto.args()['storeModel'] == 'true'
    model_override = demisto.args()['overrideExistingModel'] == 'true'
    target_accuracy = float(demisto.args()['targetAccuracy'])
    text_field = demisto.args()['textField']
    tag_fields = demisto.args()['tagField'].split(",")
    labels_mapping = get_phishing_map_labels(demisto.args()['phishingLabels'])
    keyword_min_score = float(demisto.args()['keywordMinScore'])
    if input_type.endswith("filename"):
        data = read_files_by_name(input, input_type.split("_")[0].strip())
    else:
        data = read_file(input, input_type)

    demisto.results(len(data))
    if len(data) == 0:
        err = ['No incidents were received.']
        err += ['Make sure that all arguments are set correctly and that incidents exist in the environment.']
        return_error(' '.join(err))
    if len(data) < MIN_INCIDENTS_THRESHOLD:
        err = ['Only {} incident(s) were received.'.format(len(data))]
        err += ['Minimum number of incidents per label required for training is {}.'.format(MIN_INCIDENTS_THRESHOLD)]
        err += ['Make sure that all arguments are set correctly and that enough incidents exist in the environment.']
        return_error('\n'.join(err))

    data = set_tag_field(data, tag_fields)
    data, exist_labels_counter, missing_labels_counter = get_data_with_mapped_label(data, labels_mapping,
                                                                                    DBOT_TAG_FIELD)
    validate_data_and_labels(data, exist_labels_counter, labels_mapping, missing_labels_counter)
    # print important words for each category
    find_keywords_bool = 'findKeywords' in demisto.args() and demisto.args()['findKeywords'] == 'true'
    if find_keywords_bool:
        try:
            find_keywords(data, DBOT_TAG_FIELD, text_field, keyword_min_score)
        except Exception:
            pass
    train_tag_data = [x[DBOT_TAG_FIELD] for x in data]
    train_text_data = [x[text_field] for x in data]
    if len(train_text_data) != len(train_tag_data):
        return_error("Error: data and tag data are different length")
    y_test, y_pred = get_predictions_for_test_set(train_text_data, train_tag_data)
    if 'maxBelowThreshold' in demisto.args():
        target_recall = 1 - float(demisto.args()['maxBelowThreshold'])
    else:
        target_recall = 0
    res_threshold = get_ml_model_evaluation(y_test, y_pred, target_accuracy, target_recall, detailed=True)
    # show results if no threshold (threhsold=0) was used. Following code is reached only if a legal thresh was found:
    if not np.isclose(float(res_threshold[0]['Contents']['threshold']), 0):
        res = get_ml_model_evaluation(y_test, y_pred, target_accuracy=0, target_recall=0)
        human_readable = '\n'.join(['## Results for No Threshold',
                                    'The following results were achieved by using no threshold (threshold equals 0)'])
        output_model_evaluation(model_name=model_name, train_tag_data=train_tag_data, train_text_data=train_text_data,
                                y_test=y_test, y_pred=y_pred, res=res, store_model=False,
                                model_override=model_override, context_field='DBotPhishingClassifierNoThresh',
                                human_readable_title=human_readable)
    # show results for the threshold found - last result so it will appear first
    output_model_evaluation(model_name=model_name, train_tag_data=train_tag_data, train_text_data=train_text_data,
                            y_test=y_test, y_pred=y_pred, res=res_threshold, store_model=store_model,
                            model_override=model_override, context_field='DBotPhishingClassifier')


if __name__ in ['__builtin__', '__main__']:
    main()
