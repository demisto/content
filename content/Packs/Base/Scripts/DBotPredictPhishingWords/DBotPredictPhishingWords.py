# pylint: disable=no-member
from string import punctuation

import demisto_ml
from CommonServerPython import *


def OrderedSet(iterable):
    return list(dict.fromkeys(iterable))


def get_model_data(model_name, store_type, is_return_error):
    res_model_list = demisto.executeCommand("getList", {"listName": model_name})[0]
    res_model = demisto.executeCommand("getMLModel", {"modelName": model_name})[0]

    if is_error(res_model_list) and not is_error(res_model):
        return res_model['Contents']['modelData']
    elif not is_error(res_model_list) and is_error(res_model):
        return res_model_list["Contents"]
    elif not is_error(res_model_list) and not is_error(res_model):
        if store_type == "list":
            return res_model_list["Contents"]
        elif store_type == "mlModel":
            return res_model['Contents']['modelData']
    else:
        handle_error("error reading model %s from Demisto" % model_name, is_return_error)


def handle_error(message, is_return_error):
    if is_return_error:
        return_error(message)
    else:
        demisto.results(message)
        sys.exit(0)


def predict_phishing_words(model_name, model_store_type, email_subject, email_body, min_text_length, label_threshold,
                           word_threshold, top_word_limit, is_return_error, set_incidents_fields=False):
    model_data = get_model_data(model_name, model_store_type, is_return_error)
    phishing_model = demisto_ml.phishing_model_loads(model_data)
    text = "%s \n%s" % (email_subject, email_body)
    language = demisto.args().get('language', 'English')
    tokenization = demisto.args().get('tokenizationMethod', 'tokenizer')
    res = demisto.executeCommand('WordTokenizerNLP', {'value': text,
                                                      'hashWordWithSeed': demisto.args().get('hashSeed'),
                                                      'language': language,
                                                      'tokenizationMethod': tokenization})
    if is_error(res[0]):
        handle_error(res[0]['Contents'], is_return_error)
    tokenized_text_result = res[0]['Contents']
    input_text = tokenized_text_result['hashedTokenizedText'] if tokenized_text_result.get('hashedTokenizedText') else \
        tokenized_text_result['tokenizedText']
    filtered_text, filtered_text_number_of_words = phishing_model.filter_model_words(input_text)
    if filtered_text_number_of_words == 0:
        handle_error("The model does not contain any of the input text words", is_return_error)
    if filtered_text_number_of_words < min_text_length:
        handle_error("The model contains fewer than %d words" % min_text_length, is_return_error)

    explain_result = phishing_model.explain_model_words(
        input_text,
        0,
        word_threshold,
        top_word_limit
    )
    explain_result['Probability'] = float(explain_result["Probability"])
    predicted_prob = explain_result["Probability"]
    if predicted_prob < label_threshold:
        handle_error("Label probability is {:.2f} and it's below the input confidence threshold".format(
            predicted_prob), is_return_error)

    if tokenized_text_result.get('hashedTokenizedText'):
        words_to_token_maps = tokenized_text_result['wordsToHashedTokens']
    else:
        words_to_token_maps = tokenized_text_result['originalWordsToTokens']
    positive_tokens = OrderedSet(explain_result['PositiveWords'])
    negative_tokens = OrderedSet(explain_result['NegativeWords'])
    positive_words = find_words_contain_tokens(positive_tokens, words_to_token_maps)
    negative_words = find_words_contain_tokens(negative_tokens, words_to_token_maps)
    positive_words = list(OrderedSet([s.strip(punctuation) for s in positive_words]))
    negative_words = list(OrderedSet([s.strip(punctuation) for s in negative_words]))

    positive_words = [w for w in positive_words if w.isalnum()]
    negative_words = [w for w in negative_words if w.isalnum()]
    highlighted_text_markdown = tokenized_text_result['originalText'].strip()
    for word in positive_words:
        for cased_word in [word.lower(), word.title(), word.upper()]:
            highlighted_text_markdown = re.sub(r'(?<!\w)({})(?!\w)'.format(cased_word), '**{}**'.format(cased_word),
                                               highlighted_text_markdown)
    highlighted_text_markdown = re.sub(r'\n+', '\n', highlighted_text_markdown)
    explain_result['PositiveWords'] = [w.lower() for w in positive_words]
    explain_result['NegativeWords'] = [w.lower() for w in negative_words]
    explain_result['OriginalText'] = tokenized_text_result['originalText'].strip()
    explain_result['TextTokensHighlighted'] = highlighted_text_markdown
    predicted_label = explain_result["Label"]

    explain_result_hr = dict()
    explain_result_hr['TextTokensHighlighted'] = highlighted_text_markdown
    explain_result_hr['Label'] = predicted_label
    explain_result_hr['Probability'] = "%.2f" % predicted_prob
    explain_result_hr['Confidence'] = "%.2f" % predicted_prob
    explain_result_hr['PositiveWords'] = ", ".join([w.lower() for w in positive_words])
    explain_result_hr['NegativeWords'] = ", ".join([w.lower() for w in negative_words])
    incident_context = demisto.incidents()[0]
    if not incident_context['isPlayground'] and set_incidents_fields:
        demisto.executeCommand("setIncident", {'dbotprediction': predicted_label,
                                               'dbotpredictionprobability': predicted_prob,
                                               'dbottextsuggestionhighlighted': highlighted_text_markdown})
    return {
        'Type': entryTypes['note'],
        'Contents': explain_result,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('DBot Predict Phishing Words', explain_result_hr,
                                         headers=['TextTokensHighlighted', 'Label', 'Confidence',
                                                  'PositiveWords', 'NegativeWords'],
                                         removeNull=True),
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {
            'DBotPredictPhishingWords': explain_result
        }
    }


def find_words_contain_tokens(positive_tokens, words_to_token_maps):
    positive_words = []
    for word, word_in_tokens_list in words_to_token_maps.items():
        if any(token in positive_tokens for token in word_in_tokens_list):
            positive_words.append(word)
    return positive_words


def try_get_incident_field(field):
    value = ''
    incident = demisto.incident()
    if 'CustomFields' in incident and field in incident['CustomFields']:
        value = incident['CustomFields'][field]
    return value


def main():
    confidence_threshold = 0
    confidence_threshold = float(demisto.args().get("labelProbabilityThreshold", confidence_threshold))
    confidence_threshold = float(demisto.args().get("confidenceThreshold", confidence_threshold))
    email_subject = demisto.args().get('emailSubject', '')
    email_body = demisto.args().get('emailBody', '') or demisto.args().get('emailBodyHTML', '')
    if email_subject == '':
        email_subject = try_get_incident_field(field='emailsubject')
    if email_body == '':
        email_body = try_get_incident_field(field='emailbody')
    result = predict_phishing_words(demisto.args()['modelName'],
                                    demisto.args()['modelStoreType'],
                                    email_subject,
                                    email_body,
                                    int(demisto.args()['minTextLength']),
                                    confidence_threshold,
                                    float(demisto.args().get('wordThreshold', 0)),
                                    int(demisto.args()['topWordsLimit']),
                                    demisto.args()['returnError'] == 'true',
                                    demisto.args().get('setIncidentFields', 'false') == 'true'
                                    )

    return result


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
