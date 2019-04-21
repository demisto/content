# pylint: disable=no-member
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import demisto_ml


def get_model_data(model_name, store_type):
    if store_type == 'list':
        res = demisto.executeCommand("getList", {"listName": model_name})
        res = res[0]
        if is_error(res):
            return_error("error reading list %s from Demisto" % model_name)
        return res["Contents"]
    elif store_type == 'mlModel':
        res = demisto.executeCommand("getMLModel", {"modelName": model_name})
        res = res[0]
        if is_error(res):
            return_error("error reading model %s from Demisto" % model_name)
        return res['Contents']['modelData']


def predict_phishing_words(model_name, model_store_type, email_subject, email_body):
    model_data = get_model_data(model_name, model_store_type)
    model = demisto_ml.decode_model(model_data)
    text = "%s %s" % (email_subject, email_body)
    res = demisto.executeCommand('WordTokenizerNLP', {'value': text,
                                                      'hashWordWithSeed': demisto.args().get('hashSeed')})
    if is_error(res[0]):
        return_error(res[0]['Contents'])
    tokenized_text_result = res[0]['Contents']
    input_text = tokenized_text_result['hashedTokenizedText'] if tokenized_text_result.get('hashedTokenizedText') else \
        tokenized_text_result['tokenizedText']
    filtered_text, filtered_text_number_of_words = demisto_ml.filter_model_words(input_text, model)
    if filtered_text_number_of_words == 0:
        return_error("The model does not contains any of the input text words")

    explain_result = demisto_ml.explain_model_words(model,
                                                    input_text,
                                                    float(demisto.args().get('labelProbabilityThreshold', 0)),
                                                    float(demisto.args().get('wordThreshold', 0)),
                                                    int(demisto.args()['topWordsLimit']))

    if tokenized_text_result.get('hashedTokenizedText'):
        hash_word_to_plain = dict(
            zip(tokenized_text_result['hashedTokenizedText'].split(" "),
                tokenized_text_result['tokenizedText'].split(" ")))
        explain_result['PositiveWords'] = map(lambda x: hash_word_to_plain[x], explain_result['PositiveWords'])
        explain_result['NegativeWords'] = map(lambda x: hash_word_to_plain[x], explain_result['NegativeWords'])
    explain_result['OriginalText'] = tokenized_text_result['originalText']
    explain_result['TextTokensHighlighted'] = tokenized_text_result['tokenizedText']

    res = demisto.executeCommand('HighlightWords', {'text': tokenized_text_result['tokenizedText'],
                                                    'terms': ",".join(explain_result['PositiveWords'])})
    res = res[0]
    if not is_error(res):
        highlighted_text_markdown = res['Contents']
        explain_result['TextTokensHighlighted'] = highlighted_text_markdown

    return {
        'Type': entryTypes['note'],
        'Contents': explain_result,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('DBot Predict Phihsing Words', explain_result,
                                         headers=['TextTokensHighlighted', 'Label', 'Probability',
                                                  'PositiveWords', 'NegativeWords'],
                                         removeNull=True),
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {
            'DBotPredictPhishingWords': explain_result
        }
    }


if __name__ in ['__main__', '__builtin__', 'builtins']:
    result = predict_phishing_words(demisto.args()['modelName'],
                                    demisto.args()['modelStoreType'],
                                    demisto.args().get('emailSubject', ''),
                                    demisto.args().get('emailBody', '')
                                    )

    demisto.results(result)
