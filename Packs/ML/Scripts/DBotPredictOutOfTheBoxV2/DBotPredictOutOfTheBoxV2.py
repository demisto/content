# pylint: disable=no-member
import demisto_ml
from CommonServerPython import *
import traceback

TARGET_PRECISION = 0.97
THRESHOLD = 0.9
OUT_OF_THE_BOX_MODEL_NAME = 'demisto_out_of_the_box_model_v2'
OUT_OF_THE_BOX_MODEL_PATH = '/ml/encrypted_model.b'
EVALUATION_PATH = '/ml/oob_evaluation.txt'
SCRIPT_MODEL_VERSION = '4.0'
OOB_VERSION_INFO_KEY = 'oob_version'


def oob_model_exists_and_updated():
    res_model = demisto.executeCommand("getMLModel", {"modelName": OUT_OF_THE_BOX_MODEL_NAME})[0]
    if is_error(res_model):
        return False
    existing_model_version = res_model['Contents']['model']['extra'].get(OOB_VERSION_INFO_KEY, -1)
    return existing_model_version == SCRIPT_MODEL_VERSION


def load_oob_model():
    try:
        encoded_model = demisto_ml.load_oob(OUT_OF_THE_BOX_MODEL_PATH)
    except Exception:
        return_error(traceback.format_exc())
    res = demisto.executeCommand('createMLModel', {'modelData': encoded_model,
                                                   'modelName': OUT_OF_THE_BOX_MODEL_NAME,
                                                   'modelLabels': ['Malicious', 'Non-Malicious'],
                                                   'modelOverride': 'true',
                                                   'modelType': 'torch',
                                                   'modelExtraInfo': {'threshold': THRESHOLD,
                                                                      OOB_VERSION_INFO_KEY: SCRIPT_MODEL_VERSION
                                                                      }
                                                   })
    if is_error(res):
        return_error(get_error(res))

    with open(EVALUATION_PATH) as json_file:
        data = json.load(json_file)
    y_test = data['YTrue']
    y_pred = data['YPred']
    y_pred_prob = data['YPredProb']

    y_pred_evaluation = [{pred: prob} for pred, prob in zip(y_pred, y_pred_prob)]
    res = demisto.executeCommand('GetMLModelEvaluation', {'yTrue': json.dumps(y_test),
                                                          'yPred': json.dumps(y_pred_evaluation),
                                                          'targetPrecision': str(0.85),
                                                          'targetRecall': str(0),
                                                          'detailedOutput': 'true'
                                                          })
    if is_error(res):
        return_error(get_error(res))
    confusion_matrix = json.loads(res[0]['Contents']['csr_matrix_at_threshold'])
    confusion_matrix_no_all = {k: v for k, v in confusion_matrix.items() if k != 'All'}
    confusion_matrix_no_all = {k: {sub_k: sub_v for sub_k, sub_v in v.items() if sub_k != 'All'}
                               for k, v in confusion_matrix_no_all.items()}
    res = demisto.executeCommand('evaluateMLModel',
                                 {'modelConfusionMatrix': confusion_matrix_no_all,
                                  'modelName': OUT_OF_THE_BOX_MODEL_NAME,
                                  'modelEvaluationVectors': {'Ypred': y_pred,
                                                             'Ytrue': y_test,
                                                             'YpredProb': y_pred_prob
                                                             },
                                  'modelConfidenceThreshold': THRESHOLD,
                                  'modelTargetPrecision': TARGET_PRECISION
                                  })

    if is_error(res):
        return_error(get_error(res))


def predict_phishing_words():
    if not oob_model_exists_and_updated():
        load_oob_model()
    dargs = demisto.args()
    dargs['modelName'] = OUT_OF_THE_BOX_MODEL_NAME
    dargs['modelStoreType'] = 'mlModel'
    res = demisto.executeCommand('DBotPredictPhishingWords', dargs)
    if is_error(res):
        return_error(get_error(res))
    return res


def main():
    res = predict_phishing_words()
    return res


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
