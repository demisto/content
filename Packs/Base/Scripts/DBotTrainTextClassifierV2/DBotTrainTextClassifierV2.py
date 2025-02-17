from CommonServerPython import *
# pylint: disable=no-member
import gc
import demisto_ml
import pandas as pd
from collections import defaultdict, Counter
from sklearn.model_selection import StratifiedKFold

ALL_LABELS = "*"
GENERAL_SCORES = {
    'micro avg': 'The metrics is applied globally by counting the total true positives, '
                 'false negatives and false positives',
    'macro avg': 'The metrics is applied for each label, and find their unweighted mean.',
    'weighted avg': 'The metrics is applied for each label, and find their average weighted by support '
                    '(the number of true instances for each label). This alters macro to account for label imbalance;'
}

DBOT_TAG_FIELD = "dbot_internal_tag_field"
MIN_INCIDENTS_THRESHOLD = 100
PREDICTIONS_OUT_FILE_NAME = 'predictions_on_test_set.csv'

# FROM_SCRATCH_TRAINING_ALGO is the UI equivalent of FASTTEXT_TRAINING_ALGO
FROM_SCRATCH_TRAINING_ALGO = 'from_scratch'
FINETUNE_TRAINING_ALGO = 'fine_tune'
FASTTEXT_TRAINING_ALGO = 'fasttext'
AUTO_TRAINING_ALGO = 'auto'

# the following mapping need to correspond to predict_phishing_words func at DBotPredictPhishingWords
ALGO_TO_MODEL_TYPE = {FASTTEXT_TRAINING_ALGO: 'Phishing', FINETUNE_TRAINING_ALGO: 'torch'}
FINETUNE_LABELS = ['Malicious', 'Non-Malicious']


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
        return_error(f'Label mapping error: you need to map to at least two labels: {mapped_value}.')
    return {k.encode('utf-8', 'ignore').decode("utf-8"): v for k, v in labels_dict.items()}


def read_file(input_data, input_type):
    data = []  # type: List[Dict[str, str]]
    file_path, file_content = '', ''
    if not input_data:
        return data
    if input_type.endswith("string"):
        if 'b64' in input_type:
            input_data = base64.b64decode(input_data)
            file_content = input_data.decode("utf-8")
        else:
            file_content = input_data
    else:
        res = demisto.getFilePath(input_data)
        if not res:
            return_error(f"Entry {input_data} not found")
        file_path = res['path']
        if input_type.startswith('json'):
            with open(file_path) as f:
                file_content = f.read()
    if input_type.startswith('csv'):
        return pd.read_csv(file_path).fillna('').to_dict(orient='records')
    elif input_type.startswith('json'):
        return json.loads(file_content)
    elif input_type.startswith('pickle'):
        return pd.read_pickle(file_path, compression=None)
    else:
        return_error("Unsupported file type %s" % input_type)
        return None


def get_file_entry_id(file_name):
    file_name = file_name.strip()
    res = demisto.dt(demisto.context(), f"File(val.Name == '{file_name}')")
    if not res or len(res) == 0:
        return_error(f"Cannot find file entry id in context by filename: {file_name}")
    if isinstance(res, list):
        res = res[0]
    return res['EntryID']


def read_files_by_name(file_names, input_type):
    names = filter(None, argToList(file_names))  # type: ignore[var-annotated]
    data = []
    for name in names:
        data += read_file(get_file_entry_id(name), input_type)
    return data


def get_data_with_mapped_label(data, labels_mapping, tag_field):
    new_data = []
    exist_labels_counter = defaultdict(int)  # type: Dict[str, int]
    missing_labels_counter = defaultdict(int)  # type: Dict[str, int]
    for row in data:
        original_label = row[tag_field]
        if labels_mapping == ALL_LABELS:
            row[tag_field] = original_label
        else:
            if original_label in labels_mapping:
                row[tag_field] = labels_mapping[original_label]
            elif original_label.lower() in labels_mapping:
                original_label = original_label.lower()
                row[tag_field] = labels_mapping[original_label]
            else:
                missing_labels_counter[original_label] += 1
                continue
        exist_labels_counter[original_label] += 1
        new_data.append(row)

    return new_data, dict(exist_labels_counter), dict(missing_labels_counter)


def store_model_in_demisto(model_name, model_override, X, y, confusion_matrix, threshold, y_test_true,
                           y_test_pred, y_test_pred_prob, target_accuracy, algorithm):
    global ALGO_TO_MODEL_TYPE
    phishing_model = demisto_ml.train_model_handler(X, y, algorithm=algorithm, compress=True)
    model_labels = phishing_model.get_model_labels()
    model_data = phishing_model.dumps()
    res = demisto.executeCommand('createMLModel', {'modelData': model_data,
                                                   'modelName': model_name,
                                                   'modelLabels': model_labels,
                                                   'modelOverride': model_override,
                                                   'modelExtraInfo': {'threshold': threshold},
                                                   'modelType': ALGO_TO_MODEL_TYPE[algorithm],
                                                   })
    if is_error(res):
        return_error(get_error(res))

    y_test_pred_prob = [float(x) for x in y_test_pred_prob]
    res = demisto.executeCommand('evaluateMLModel',
                                 {'modelConfusionMatrix': confusion_matrix,
                                  'modelName': model_name,
                                  'modelEvaluationVectors': {'Ypred': y_test_pred,
                                                             'Ytrue': y_test_true,
                                                             'YpredProb': y_test_pred_prob

                                                             },
                                  'modelConfidenceThreshold': threshold,
                                  'modelTargetPrecision': target_accuracy
                                  })
    if is_error(res):
        return_error(get_error(res))


def find_keywords(data, tag_field, text_field, min_score):
    keywords = demisto_ml.get_keywords_for_labels(data, tag_field, text_field)
    human_readable = "# Keywords per category\n"
    for category, scores in keywords.items():
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        table_items = [{"Word": word, "Score": f'{score:.2f}'} for
                       word, score in sorted_scores if score >= min_score]
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
            if d.get(field) is not None:
                label = d[field]
                if isinstance(label, list) and len(label) > 0:
                    label = label[0]
                elif isinstance(label, list) and len(label) == 0:
                    continue
                label = label.encode('utf-8', 'ignore').decode("utf-8")
                d[DBOT_TAG_FIELD] = str(label)
                found_field = True
                break
        if not found_field:
            empty_label_indices.append(i)
    data = [d for i, d in enumerate(data) if i not in empty_label_indices]
    return data


def output_model_evaluation(model_name, y_test, y_pred, res, context_field, human_readable_title=None):
    threshold = float(res['Contents']['threshold'])
    confusion_matrix_at_thresh = json.loads(res['Contents']['csr_matrix_at_threshold'])
    confusion_matrix_no_thresh = json.loads(res['Contents']['csr_matrix_no_threshold'])
    metrics_df = json.loads(res['Contents']['metrics_df'])
    human_readable = res['HumanReadable']
    if human_readable_title is not None:
        human_readable = '\n'.join([human_readable_title, human_readable])
    result_entry = {
        'Type': entryTypes['note'],
        'Contents': {'Threshold': threshold, 'ConfusionMatrixAtThreshold': confusion_matrix_at_thresh,
                     'ConfusionMatrixNoThreshold': confusion_matrix_no_thresh, 'Metrics': metrics_df,
                     'YTrue': y_test, 'YPred': y_pred},
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {
            context_field: {
                'ModelName': model_name,
                'EvaluationScores': metrics_df,
                'ConfusionMatrix': confusion_matrix_at_thresh,
                'ConfusionMatrixNoThresh': confusion_matrix_no_thresh,

            }
        }
    }
    demisto.results(result_entry)
    confusion_matrix_at_thresh = {k: v for k, v in confusion_matrix_at_thresh.items() if k != 'All'}
    confusion_matrix_at_thresh = {k: {sub_k: sub_v for sub_k, sub_v in v.items() if sub_k != 'All'}
                                  for k, v in confusion_matrix_at_thresh.items()}
    return confusion_matrix_at_thresh, metrics_df


def get_ml_model_evaluation(y_test, y_pred, target_accuracy, target_recall, detailed=False):
    res = demisto.executeCommand('GetMLModelEvaluation', {'yTrue': json.dumps(y_test),
                                                          'yPred': json.dumps(y_pred),
                                                          'targetPrecision': str(target_accuracy),
                                                          'targetRecall': str(target_recall),
                                                          'detailedOutput': 'true' if detailed else 'false',
                                                          })
    if is_error(res):
        return_error(get_error(res))
    return res[0]


def validate_data_and_labels(data, exist_labels_counter, labels_mapping, missing_labels_counter):
    labels_counter = Counter([x[DBOT_TAG_FIELD] for x in data])
    labels_below_thresh = [label for label, count in labels_counter.items() if count < MIN_INCIDENTS_THRESHOLD]
    if len(labels_below_thresh) > 0:
        err = [f'Minimum number of incidents per label required for training is {MIN_INCIDENTS_THRESHOLD}.']
        err += [f'The following labels have less than {MIN_INCIDENTS_THRESHOLD} incidents: ']
        for x in labels_below_thresh:
            err += [f'- {x}: {str(labels_counter[x])}']
        err += ['Make sure that enough incidents exist in the environment per each of these labels.']
        missing_labels = ', '.join(missing_labels_counter.keys())
        err += [f'The following labels were not mapped to any label in the labels mapping: {missing_labels}.']
        if labels_mapping != ALL_LABELS:
            err += ['The given mapped labels are: {}.'.format(', '.join(labels_mapping.keys()))]
        return_error('\n'.join(err))
    if len(exist_labels_counter) == 0:
        err = ['Did not found any incidents with labels of the labels mapping.']
        if len(missing_labels_counter) > 0:
            err += ['The following labels were found: {}'.format(', '.join(k for k in missing_labels_counter))]
            err += ['Please include these labels at the mapping, or change the query to include your relevant labels']
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
                label = f"{label} -> {mapped_label}"
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
    if len({x[DBOT_TAG_FIELD] for x in data}) == 1:
        single_label = [x[DBOT_TAG_FIELD] for x in data][0]
        if labels_mapping == ALL_LABELS:
            err = [f'All received incidents have the same label: {single_label}.']
        else:
            err = [f'All received incidents mapped to the same label: {single_label}.']
        err += ['At least 2 different labels are required to train a classifier.']
        if labels_mapping == ALL_LABELS:
            err += ['Please make sure that incidents of at least 2 labels exist in the environment.']
        else:
            err += ['The following labels were not mapped to any label in the labels mapping:']
            err += [', '.join(list(missing_labels_counter))]
            not_found_mapped_label = [x for x in labels_mapping if x not in exist_labels_counter
                                      or exist_labels_counter[x] == 0]
            if len(not_found_mapped_label) > 0:
                miss = ', '.join(not_found_mapped_label)
                err += [f'Notice that the following mapped labels were not found among all incidents: {miss}.']
        return_error('\n'.join(err))


def return_file_result_with_predictions_on_test_set(data, original_text_fields, test_index, text_field, y_test,
                                                    y_pred_dict):
    if original_text_fields is None or original_text_fields.strip() == '':
        original_text_fields = [text_field]
    else:
        original_text_fields = re.split(r'[|,]', original_text_fields)
        original_text_fields = [x.strip() for x in original_text_fields] + [text_field]
    predictions_data = {}
    test_data = [data[i] for i in test_index]
    for field in original_text_fields:
        predictions_data[field] = [record.get(field, '') for record in test_data]
    predictions_data['y_true'] = y_test
    y_pred = []
    y_pred_prob = []
    for y_i in y_pred_dict:
        y_pred_prob_i = max(y_i.values())
        y_pred_i = [label for label, label_prob in y_i.items() if y_i[label] == y_pred_prob_i][0]
        y_pred.append(y_pred_i)
        y_pred_prob.append(y_pred_prob_i)
    predictions_data['y_pred'] = y_pred
    predictions_data['y_pred_prob'] = y_pred_prob
    df = pd.DataFrame(predictions_data)
    non_empty_columns = [field for field in original_text_fields if df[field].astype(bool).any()]
    csv_df = df.to_csv(columns=non_empty_columns + ['y_true', 'y_pred', 'y_pred_prob'], encoding='utf-8')
    demisto.results(fileResult(PREDICTIONS_OUT_FILE_NAME, csv_df))


def get_train_and_test_sets_indices(X, y):
    train_set_ratio = float(demisto.args()['trainSetRatio'])
    n_splits = int(1.0 / (1 - train_set_ratio))
    skf = StratifiedKFold(n_splits=n_splits, shuffle=False, random_state=None)
    skf.get_n_splits(X, y)
    train_index, test_index = list(skf.split(X, y))[-1]
    return test_index, train_index


def get_X_and_y_from_data(data, text_field):
    y = [x[DBOT_TAG_FIELD] for x in data]
    X = [x[text_field] for x in data]
    if len(X) != len(y):
        return_error("Error: data and tag data are different length")
    return X, y


def validate_labels_and_decide_algorithm(y, algorithm):
    labels_counter = Counter(y)  # type: Dict[str, int]
    illegal_labels_for_fine_tune = [label for label in labels_counter if label not in FINETUNE_LABELS]
    if algorithm == FINETUNE_TRAINING_ALGO and len(illegal_labels_for_fine_tune) > 0:
        error = ['When trainingAlgorithm is set to {}, all labels mus be mapped to {}.\n'.format(algorithm,
                                                                                                 ', '.join(
                                                                                                     FINETUNE_LABELS))]
        error += ['The following labels/verdicts need to be mapped to one of those values: ']
        error += [', '.join(illegal_labels_for_fine_tune) + '.']
        return_error('\n'.join(error))
        return None
    elif algorithm == AUTO_TRAINING_ALGO:
        return FASTTEXT_TRAINING_ALGO
    else:
        return algorithm


def validate_confusion_matrix(confusion_matrix):
    for label in confusion_matrix:
        tp = confusion_matrix[label][label]
        fp = sum(confusion_matrix[label_other][label] for label_other in confusion_matrix if label != label_other)
        if tp == fp == 0:
            return False
    return True


def main():
    input = demisto.args().get('input')
    input_type = demisto.args().get('inputType', 'pickle_filename')
    model_name = demisto.args().get('modelName', 'phishing_model')
    store_model = demisto.args().get('storeModel') == 'true'
    model_override = demisto.args().get('overrideExistingModel', 'false') == 'true'
    target_accuracy = float(demisto.args().get('targetAccuracy', '0.8'))
    text_field = demisto.args().get('textField', 'dbot_processed_text')
    tag_fields = demisto.args().get('tagField').split(",")
    labels_mapping = get_phishing_map_labels(demisto.args().get('phishingLabels'))
    keyword_min_score = float(demisto.args().get('keywordMinScore', '0.05'))
    return_predictions_on_test_set = demisto.args().get('returnPredictionsOnTestSet', 'false') == 'true'
    original_text_fields = demisto.args().get('originalTextFields', 'emailsubject|name,emailbody|emailbodyhtml')
    algorithm = demisto.args().get('trainingAlgorithm', AUTO_TRAINING_ALGO)
    # FASTTEXT_TRAINING_ALGO and FROM_SCRATCH_TRAINING_ALGO are equivalent, replacement is done because ml_lib
    # expects algorithm as one of (FASTTEXT_TRAINING_ALGO, FINETUNE_TRAINING_ALGO)
    algorithm = FASTTEXT_TRAINING_ALGO if algorithm == FROM_SCRATCH_TRAINING_ALGO else algorithm

    if input_type.endswith("filename"):
        data = read_files_by_name(input, input_type.split("_")[0].strip())
    else:
        data = read_file(input, input_type)

    if len(data) < MIN_INCIDENTS_THRESHOLD:
        return_results(
            f'{len(data)} incident(s) received.'
            f'\nMinimum number of incidents per label required for training: {MIN_INCIDENTS_THRESHOLD}.'
            '\nMake sure that all arguments are set correctly and that enough incidents exist in the environment.'
        )
    else:
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
        X, y = get_X_and_y_from_data(data, text_field)
        algorithm = validate_labels_and_decide_algorithm(y, algorithm)
        test_index, train_index = get_train_and_test_sets_indices(X, y)
        X_train, X_test = [X[i] for i in train_index], [X[i] for i in test_index]
        y_train, y_test = [y[i] for i in train_index], [y[i] for i in test_index]
        phishing_model = demisto_ml.train_model_handler(X_train, y_train, algorithm=algorithm, compress=False)
        ft_test_predictions = phishing_model.predict(X_test)
        y_pred = [{y_tuple[0]: float(y_tuple[1])} for y_tuple in ft_test_predictions]
        if return_predictions_on_test_set:
            return_file_result_with_predictions_on_test_set(data, original_text_fields, test_index, text_field, y_test,
                                                            y_pred)
        target_recall = 1 - float(demisto.args().get('maxBelowThreshold', 1))
        threshold_metrics_entry = get_ml_model_evaluation(y_test, y_pred, target_accuracy, target_recall, detailed=True)
        # show results for the threshold found - last result so it will appear first
        confusion_matrix, metrics_json = output_model_evaluation(model_name=model_name, y_test=y_test, y_pred=y_pred,
                                                                 res=threshold_metrics_entry,
                                                                 context_field='DBotPhishingClassifier')
        actual_min_accuracy = min(v for k, v in metrics_json['Precision'].items() if k != 'All')
        if store_model:
            del phishing_model
            gc.collect()
            if not validate_confusion_matrix(confusion_matrix):
                return_error("The trained model didn't manage to predict some of the classes. This model won't be stored."
                             "Please try to retrain the model using a different configuration.")
            y_test_pred = [y_tuple[0] for y_tuple in ft_test_predictions]
            y_test_pred_prob = [y_tuple[1] for y_tuple in ft_test_predictions]
            threshold = float(threshold_metrics_entry['Contents']['threshold'])
            store_model_in_demisto(model_name=model_name, model_override=model_override, X=X, y=y,
                                   confusion_matrix=confusion_matrix, threshold=threshold,
                                   y_test_true=y_test, y_test_pred=y_test_pred, y_test_pred_prob=y_test_pred_prob,
                                   target_accuracy=actual_min_accuracy, algorithm=algorithm)
            demisto.results(f"Done training on {len(y)} samples model stored successfully")
        else:
            demisto.results('Skip storing model')


if __name__ in ['builtins', '__main__']:
    main()
