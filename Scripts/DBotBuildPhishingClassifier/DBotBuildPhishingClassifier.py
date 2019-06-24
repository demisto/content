import demisto_ml as demisto_ml
from tabulate import tabulate
import pandas as pd
from CommonServerPython import *


DBOT_TEXT_FIELD = 'dbot_text'


def pre_process_nlp(data, hash_seed):
    text_data = map(lambda x: x[DBOT_TEXT_FIELD], data)
    res = demisto.executeCommand('WordTokenizerNLP', {
        'value': json.dumps(text_data),
        'isValueJson': 'yes',
        'hashWordWithSeed': hash_seed
    })
    if is_error(res):
        return_error(get_error(res))
    processed_text_data = res[0]['Contents']
    if not isinstance(processed_text_data, list):
        processed_text_data = [processed_text_data]
    train_text_data = map(lambda x: x.get('hashedTokenizedText') or x.get('tokenizedText'), processed_text_data)
    for d, text_data in zip(data, train_text_data):
        d[DBOT_TEXT_FIELD] = text_data
    return data

def get_hr_for_scores(confusion_matrix, scores):
    scores_description = tableToMarkdown('Scores', {k.capitalize(): "%.2f" % v for k, v in scores.items()})
    confusion_matrix_desc = tabulate(confusion_matrix,
                                     tablefmt="pipe",
                                     headers="keys").replace("True", "True \\ Predicted")
    return "# Model Evaluation\n ### Confusion Matrix:\n{0}\n{1}".format(confusion_matrix_desc,
                                                                       scores_description)


def read_file(entry_id, file_type):
    data = []
    if not entry_id:
        return data
    res = demisto.getFilePath(entry_id)
    if not res:
        return_error("Entry {} not found".format(entry_id))
    file_path = res['path']
    if file_type == 'csv':
        df = pd.read_csv(file_path)
    elif file_type == 'json':
        df = pd.read_json(file_path)
    elif file_type == 'pickle':
        df = pd.read_pickle(file_path)
    else:
        return_error("Unsupported file type %s" % file_type)

    return df.to_dict(orient='rows')


def filter_by_condition(arr, filter_func, message):
    before_size = len(arr)
    arr = [x for x in arr if filter_func(x)]
    after_size = len(arr)
    diff_size = before_size - after_size
    if diff_size > 0:
        demisto.log("Drop %d samples " + message)
    return arr


def main():
    text_fields = demisto.args()['textFields'].split(",")
    entry_id = demisto.args()['entryId']
    file_type = demisto.args()['fileType']
    model_name = demisto.args()['modelName']
    store_model = demisto.args()['storeModel'] == 'true'
    hash_seed = demisto.args().get('hashSeed')
    model_override = demisto.args()['overrideExistingModel'] == 'true'
    target_accuracy = float(demisto.args()['targetAccuracy'])
    max_samples_below_threshold = float(demisto.args()['maxBelowThreshold'])
    remove_short_threshold = int(demisto.args().get('removeShortEmailsThreshold', 0))
    dedup_threshold = float(demisto.args()['dedupThreshold'])

    # read data
    if entry_id:
        data = read_file(entry_id, file_type)

    data = data[:200]

    # pre-process data
    for d in data:
        text = ''
        for field in text_fields:
            text += d.get(field, '')
            text += ' '
        text = text.strip()
        d[DBOT_TEXT_FIELD] = text
    data = filter_by_condition(data, lambda x: len(x[DBOT_TEXT_FIELD]) > 0, 'that has no empty text')

    pre_process_type = demisto.args()['preProcessType']
    if pre_process_type == 'nlp':
        data = pre_process_nlp(data, hash_seed)
    elif pre_process_type == 'none':
        pass
    else:
        return_error('Pre-process type {} is not supported'.format(pre_process_type))

    # remove short emails
    data = filter_by_condition(data, lambda x: len(x[DBOT_TEXT_FIELD].split(" ")) > remove_short_threshold, 'shorter then %d words' % remove_short_threshold)

    # remove duplicates
    # try:
    #     before_dedup = len(train_text_data)
    #     train_text_data = demisto_ml.remove_duplicates(train_text_data, dedup_threshold)
    #     dedup_diff = len(train_text_data) - before_dedup
    #     if dedup_diff > 0:
    #         demisto.log("Removed %d samples duplicate to other samples" % dedup_diff)
    # except Exception:
    #     pass

    # tag_field = demisto.args()['tagField']
    # train_tag_data = map(lambda x: x[tag_field], data)
    # if len(train_text_data) != len(train_tag_data):
    #     return_error("Error: data and tag data are different length")
    #


    # # evaluate model
    # confusion_matrix, scores, cut, confusion_matrix_cut, scores_cut \
    #     = demisto_ml.get_model_confusion_matrix(train_text_data,
    #                                             train_tag_data,
    #                                             target_precision_recall=target_accuracy)
    #
    # model_evaluation_success = False
    # if scores['precision'] >= target_accuracy and scores['recall'] >= target_accuracy:
    #     model_evaluation_success = True
    # else:
    #     if scores_cut['belowThresholdRatio'] <= max_samples_below_threshold:
    #         if scores_cut['precision'] >= target_accuracy and scores_cut['recall'] >= target_accuracy:
    #             model_evaluation_success = True
    # if not model_evaluation_success:
    #     return_error("Model target accuracy %.2f is below threshold %.2f".format(scores['accuracy'], target_accuracy))
    #
    # hr = get_hr_for_scores(confusion_matrix, scores)
    # if cut > 0.5 and confusion_matrix_cut:
    #     hr += "\n"
    #     hr += "Found optimal probability  %.2f threshold for target accuracy %.2f".format(cut, target_accuracy)
    #     hr += "\n"
    #     hr += get_hr_for_scores(confusion_matrix_cut, scores_cut)
    #
    # result_entry = {
    #     'Type': entryTypes['note'],
    #     'Contents': {'scores': scores, 'confusion_matrix': confusion_matrix.to_dict()},
    #     'ContentsFormat': formats['json'],
    #     'HumanReadable': hr,
    #     'HumanReadableFormat': formats['markdown'],
    #     'EntryContext': {
    #         'DBotPhishingClassifier': {
    #             'ModelName': model_name,
    #             'EvaluationScores': scores,
    #             'ConfusionMatrix': confusion_matrix.to_dict()
    #         }
    #     }
    # }
    #
    # if store_model:
    #     model = demisto_ml.train_text_classifier(train_text_data, train_tag_data, True)
    #     model_data = demisto_ml.encode_model(model)
    #     model_labels = demisto_ml.get_model_labels(model)
    #
    #     res = demisto.executeCommand('createMLModel', {'modelData': model_data,
    #                                                    'modelName': model_name,
    #                                                    'modelLabels': model_labels,
    #                                                    'modelOverride': model_override})
    #     if is_error(res):
    #         return_error(get_error(res))
    #
    #     res = demisto.executeCommand('evaluateMLModel',
    #                                  {'modelConfusionMatrix': confusion_matrix.to_json(),
    #                                   'modelName': model_name})
    #     if is_error(res):
    #         return_error(get_error(res))
    #     result_entry['HumanReadable'] += "\nDone training on {} samples model stored successfully".format(
    #         len(train_text_data))
    # else:
    #     result_entry['HumanReadable'] += "\nSkip storing model"
    #
    # demisto.results(result_entry)


if __name__ in ['__builtin__', '__main__']:
    main()
