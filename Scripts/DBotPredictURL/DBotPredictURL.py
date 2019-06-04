import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import demisto_ml

SUSPICIOUS_SCORE = 2
GOOD_SCORE = 1
NO_SCORE = 0


def get_entry_with_dbot_score(value, label, probability, probability_threshold):
    if label == 1 and probability >= probability_threshold:
        hr = 'Similar to other bad URLs by URL Classification model'
        score = SUSPICIOUS_SCORE
    elif label == 0 and probability >= probability_threshold:
        hr = 'Similar to other good URLs by URL Classification model'
        score = GOOD_SCORE
    else:
        hr = 'URL Classification model return no answer for URL'
        score = NO_SCORE

    entry = {
        'Type': entryTypes['note'],
        'HumanReadable': hr,
        'ReadableContentsFormat': formats['markdown'],
        'Contents': score,
        'ContentsFormat': formats['text'],
    }
    ec = {}
    ec['DBotScore'] = {
        'Indicator': value,
        'Type': 'url',
        'Vendor': 'DBot',
        'Score': score
    }
    ec['DBotPredictURL'] = {
        'URL': value,
        'Probability': "%.2f" % probability,
        'Label': 'valid' if label == 0 else 'malicious'
    }
    entry['EntryContext'] = ec
    return entry


def format_prediction(prediction):
    return {
        'Probability': '%.2f' % prediction['probability'],
        'Label': prediction['label'],
        'URL': prediction['url']
    }


MODEL_NAME = demisto.args()['modelName']
res = demisto.executeCommand('getMLModel', {'modelName': MODEL_NAME})
if is_error(res):
    return_error(get_error(res))
encoded_model = res[0]['Contents']['modelData']

urls = demisto.args()['input']
if type(urls) is not list:
    urls = [urls]

demisto_ml.url_load_model(encoded_model, MODEL_NAME)
predictions = demisto_ml.url_predict(MODEL_NAME, urls)
entries = []
threshold = float(demisto.args()['threshold'])
for prediction in predictions:
    entry = get_entry_with_dbot_score(prediction['url'],
                                      prediction['label'],
                                      prediction['probability'],
                                      threshold)
    entries.append(entry)
demisto.results(entries)
