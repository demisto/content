import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pickle
import demisto_ml
from tabulate import tabulate
import warnings

warnings.simplefilter("ignore")


def get_file_path(file_name):
    file_name = file_name.strip()
    res = demisto.dt(demisto.context(), "File(val.Name == '%s')" % file_name)
    if type(res) is list:
        res = res[0]
    entry_id = res['EntryID']
    res = demisto.executeCommand("getFilePath", {"id": entry_id})
    if res[0]['Type'] == entryTypes['error']:
        demisto.results(res)
        sys.exit(0)
    return res[0]['Contents']['path']


filename = demisto.args()['inputFilename']
if type(filename) is list:
    filename = filename[-1]
model_name = demisto.args()['modelName']

file_path = get_file_path(filename)
urls = pickle.load(open(file_path, 'r'))

# evaluate model
confusion_matrix, scores = demisto_ml.url_model_confusion_matrix(urls.keys(), urls.values())
accuracy_threshold = float(demisto.args()['accuracyThreshold'])

scores_description = tableToMarkdown('Scores', {k.capitalize(): "%.2f" % v for k, v in scores.items()})
confusion_matrix_description = tabulate(confusion_matrix, tablefmt="pipe", headers="keys").replace("True",
                                                                                                   "True \\ Predicted")
result_entry = {
    'Type': entryTypes['note'],
    'Contents': {'scores': scores, 'confusion_matrix': confusion_matrix.to_dict()},
    'ContentsFormat': formats['json'],
    'HumanReadable': "# Model Evaluation\n ### Confusion Matrix:\n{0}\n{1}".format(confusion_matrix_description,
                                                                                   scores_description),
    'HumanReadableFormat': formats['markdown'],
    'EntryContext': {
        'DBotURLClassifier': {
            'ModelName': model_name,
            'EvaluationScores': scores,
            'ConfusionMatrix': confusion_matrix.to_dict()
        }
    }
}

if scores['accuracy'] < accuracy_threshold:
    return_error("Model accuracy %.2f is below threshold %.2f".format(scores['accuracy'], accuracy_threshold))
if scores['precision'] < accuracy_threshold:
    return_error("Model precision %.2f is below threshold %.2f" % (scores['precision'], accuracy_threshold))

model_encoded = demisto_ml.url_train_model(model_name, urls.keys(), urls.values())
res = demisto.executeCommand('createMLModel', {
    'modelName': model_name,
    'modelData': model_encoded,
    'modelType': 'url',
    'modelLabels': ['valid', 'malicious'],
    'modelOverride': demisto.args()['modelOverride'] == 'true'
})
if is_error(res):
    return_error(get_error(res))

res = demisto.executeCommand('evaluateMLModel',
                             {'modelConfusionMatrix': confusion_matrix.to_json(),
                              'modelName': model_name})
if is_error(res):
    return_error(get_error(res))

demisto.results(result_entry)
