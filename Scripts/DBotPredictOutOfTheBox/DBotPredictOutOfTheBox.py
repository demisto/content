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
    with open(OUT_OF_THE_BOX_MODEL_PATH, 'rb') as input_file:
        encryped_model = input_file.read()
    encoded_model = demisto_ml.decrypt_model(encryped_model)
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


def predict_phishing_words(email_subject, email_body, email_body_html, min_text_length, label_threshold,
                           word_threshold, top_word_limit, is_return_error):
    if not oob_model_exists() or True:
        load_oob_model()
    res = demisto.executeCommand('DBotPredictPhishingWords', {'modelName': OUT_OF_THE_BOX_MODEL_NAME,
                                                              'emailBody': email_body,
                                                              'emailBodyHTML': email_body_html,
                                                              'emailSubject': email_subject,
                                                              'labelProbabilityThreshold': label_threshold,
                                                              'minTextLength': min_text_length,
                                                              'wordThreshold': word_threshold,
                                                              'top_word_limit': top_word_limit,
                                                              'returnError': is_return_error,
                                                              'hashSeed': HASH_SEED
                                                              })
    if is_error(res):
        return_error(get_error(res))
    return res


def main():
    res = predict_phishing_words(demisto.args().get('emailSubject', ''),
                                 demisto.args().get('emailBody', ''),
                                 demisto.args().get('emailBodyHTML', ''),
                                 int(demisto.args()['minTextLength']),
                                 float(demisto.args().get("labelProbabilityThreshold", 0)),
                                 float(demisto.args().get('wordThreshold', 0)),
                                 int(demisto.args()['topWordsLimit']),
                                 demisto.args()['returnError'] == 'true'
                                 )
    return res


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
