# pylint: disable=no-member
import demisto_ml

from CommonServerPython import *

OUT_OF_THE_BOX_MODEL_NAME = 'demisto_out_of_the_box_model'
OUT_OF_THE_BOX_MODEL_PATH = '/var/oob_model.ftz'
EVALUATION_PATH = '/var/oob_evaluation.json'
HASH_SEED = 5381


def oob_model_exists():
    res_model = demisto.executeCommand("getMLModel", {"modelName": OUT_OF_THE_BOX_MODEL_NAME})[0]
    return not is_error(res_model)


def load_oob_model():
    encoded_model = demisto_ml.load_oob(OUT_OF_THE_BOX_MODEL_PATH)
    res = demisto.executeCommand('createMLModel', {'modelData': encoded_model,
                                                   'modelName': OUT_OF_THE_BOX_MODEL_NAME,
                                                   'modelLabels': ['legit', 'spam', 'malicious'],
                                                   'modelOverride': 'true'})
    if is_error(res):
        return_error(get_error(res))

    with open(EVALUATION_PATH, 'r') as json_file:
        data = json.load(json_file)
    y_test = data['y_true']
    y_pred = data['y_pred']
    res = demisto.executeCommand('GetMLModelEvaluation', {'yTrue': json.dumps(y_test),
                                                          'yPred': json.dumps(y_pred),
                                                          'targetPrecision': str(0),
                                                          'targetRecall': str(0),
                                                          'detailedOutput': 'false'
                                                          })
    if is_error(res):
        return_error(get_error(res))
    confusion_matrix = json.loads(res[0]['Contents']['csr_matrix_at_threshold'])
    confusion_matrix_no_all = {k: v for k, v in confusion_matrix.items() if k != 'All'}
    confusion_matrix_no_all = {k: {sub_k: sub_v for sub_k, sub_v in v.items() if sub_k != 'All'}
                               for k, v in confusion_matrix_no_all.items()}
    res = demisto.executeCommand('evaluateMLModel',
                                 {'modelConfusionMatrix': confusion_matrix_no_all,
                                  'modelName': OUT_OF_THE_BOX_MODEL_NAME})
    if is_error(res):
        return_error(get_error(res))


def predict_phishing_words():
    if not oob_model_exists():
        load_oob_model()
    dargs = demisto.args()
    dargs['modelName'] = OUT_OF_THE_BOX_MODEL_NAME
    dargs['hashSeed'] = '5381'
    res = demisto.executeCommand('DBotPredictPhishingWords', dargs)
    if is_error(res):
        return_error(get_error(res))
    return res


def main():
    res = predict_phishing_words()
    return res


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
