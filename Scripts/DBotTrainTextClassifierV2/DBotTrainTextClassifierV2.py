# pylint: disable=no-member
from collections import defaultdict
from io import BytesIO, StringIO

import demisto_ml
import pandas as pd
from tabulate import tabulate

from CommonServerPython import *

ALL_LABELS = "*"
GENERAL_SCORES = ['macro avg', 'micro avg', 'weighted avg']
DBOT_TAG_FIELD = "dbot_internal_tag_field"


def get_hr_for_scores(header, confusion_matrix, report):
    scores_rows = ["#### Overall score: %.2f" % report['macro avg']['precision']]
    for k, v in report.items():
        if isinstance(v, dict):
            if k not in GENERAL_SCORES:
                scores_rows.append("- %s: %.2f" % (k, v['precision']))
    scores_desc = "\n".join(scores_rows)

    confusion_matrix_desc = tabulate(confusion_matrix,
                                     tablefmt="pipe",
                                     headers="keys").replace("True", "True \\ Predicted")
    return "# {0}\n ## Confusion Matrix:\n{1}\n ## Scores:\n{2} ".format(header, confusion_matrix_desc, scores_desc)


def canonize_label(label):
    return label.replace(" ", "_")


def get_phishing_map_labels(comma_values):
    if comma_values == ALL_LABELS:
        return comma_values
    values = map(lambda x: x.strip(), comma_values.split(","))
    labels_dict = {}
    for v in values:
        v = v.strip()
        if ":" in v:
            splited = v.split(":")
            labels_dict[splited[0].strip()] = splited[1].strip()
        else:
            labels_dict[v] = v
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

    res = demisto.executeCommand('evaluateMLModel',
                                 {'modelConfusionMatrix': confusion_matrix.to_json(),
                                  'modelName': model_name})
    if is_error(res):
        return_error(get_error(res))


def evaluate_model(train_text_data, train_tag_data, target_accuracy, max_samples_below_threshold):
    confusion_matrix, report, cut, confusion_matrix_cut, report_cut \
        = demisto_ml.evaluate_text_model(train_text_data,
                                         train_tag_data,
                                         target_precision_recall=target_accuracy)
    model_evaluation_success = False
    if report['macro avg']['precision'] >= target_accuracy and report['macro avg']['recall'] >= target_accuracy:
        model_evaluation_success = True
    else:
        if report_cut and report_cut['belowThresholdRatio'] <= max_samples_below_threshold:
            if report_cut['macro avg']['precision'] >= target_accuracy \
                    and report_cut['macro avg']['recall'] >= target_accuracy:
                model_evaluation_success = True

    if not model_evaluation_success:
        low_score = min(report['macro avg']['precision'], report['macro avg']['recall'])
        return_error("Model target accuracy %.2f is below %.2f" % (low_score, target_accuracy))

    human_readable = get_hr_for_scores("Model Evaluation", confusion_matrix, report)
    if cut > 0.5 and confusion_matrix_cut is not None:
        human_readable += "\n"
        human_readable += "### Found optimal probability  %.2f threshold for target accuracy %.2f " % (cut,
                                                                                                       target_accuracy)
        human_readable += "Samples below threshold: %d (%.2f%%)\n" % (report_cut['belowThreshold'],
                                                                      report_cut['belowThresholdRatio'] * 100)
        human_readable += get_hr_for_scores("Model Evaluation probability >= %.2f" % cut,
                                            confusion_matrix_cut,
                                            report_cut)
    return human_readable, confusion_matrix, report


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


def main():
    input = demisto.args()['input']
    input_type = demisto.args()['inputType']
    model_name = demisto.args()['modelName']
    store_model = demisto.args()['storeModel'] == 'true'
    model_override = demisto.args()['overrideExistingModel'] == 'true'
    target_accuracy = float(demisto.args()['targetAccuracy'])
    max_samples_below_threshold = float(demisto.args()['maxBelowThreshold'])
    text_field = demisto.args()['textField']
    tag_fields = demisto.args()['tagField'].split(",")
    labels_mapping = get_phishing_map_labels(demisto.args()['phishingLabels'])
    keyword_min_score = float(demisto.args()['keywordMinScore'])

    if input_type.endswith("filename"):
        data = read_files_by_name(input, input_type.split("_")[0].strip())
    else:
        data = read_file(input, input_type)

    data = set_tag_field(data, tag_fields)

    data, exist_labels_counter, missing_labels_counter = get_data_with_mapped_label(data, labels_mapping,
                                                                                    DBOT_TAG_FIELD)
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

    train_tag_data = map(lambda x: x[DBOT_TAG_FIELD], data)
    train_text_data = map(lambda x: x[text_field], data)
    if len(train_text_data) != len(train_tag_data):
        return_error("Error: data and tag data are different length")

    # print important words for each category
    try:
        find_keywords(data, DBOT_TAG_FIELD, text_field, keyword_min_score)
    except Exception:
        pass

    # evaluate model
    human_readable, confusion_matrix, report = evaluate_model(train_text_data,
                                                              train_tag_data,
                                                              target_accuracy,
                                                              max_samples_below_threshold)

    # store model
    if store_model:
        store_model_in_demisto(model_name, model_override, train_text_data, train_tag_data, confusion_matrix)
        human_readable += "\nDone training on {} samples model stored successfully".format(len(train_text_data))
    else:
        human_readable += "\n\nSkip storing model"
    result_entry = {
        'Type': entryTypes['note'],
        'Contents': {'scores': report, 'confusion_matrix': confusion_matrix.to_dict()},
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {
            'DBotPhishingClassifier': {
                'ModelName': model_name,
                'EvaluationScores': {k.strip().replace(" ", "_"): v for k, v in report.items()},
                'ConfusionMatrix': confusion_matrix.to_dict()
            }
        }
    }
    demisto.results(result_entry)


if __name__ in ['__builtin__', '__main__']:
    main()
