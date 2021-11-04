# pylint: disable=no-member

from CommonServerPython import *
from string import punctuation
import demisto_ml
import numpy as np

FASTTEXT_MODEL_TYPE = 'FASTTEXT_MODEL_TYPE'
TORCH_TYPE = 'torch'
UNKNOWN_MODEL_TYPE = 'UNKNOWN_MODEL_TYPE'


def OrderedSet(iterable):
    return list(dict.fromkeys(iterable))


def get_model_data(model_name, store_type, is_return_error):
    res_model_list = demisto.executeCommand("getList", {"listName": model_name})[0]
    res_model = demisto.executeCommand("getMLModel", {"modelName": model_name})[0]
    if is_error(res_model_list) and not is_error(res_model):
        model_data = res_model['Contents']['modelData']
        try:
            model_type = res_model['Contents']['model']["type"]["type"]
            return model_data, model_type
        except Exception:
            return model_data, UNKNOWN_MODEL_TYPE
    elif not is_error(res_model_list) and is_error(res_model):
        return res_model_list["Contents"], UNKNOWN_MODEL_TYPE
    elif not is_error(res_model_list) and not is_error(res_model):
        if store_type == "list":
            return res_model_list["Contents"], UNKNOWN_MODEL_TYPE
        elif store_type == "mlModel":
            model_data = res_model['Contents']['modelData']
            model_type = res_model['Contents']['model']["type"]["type"]
            return model_data, model_type
    else:
        handle_error("error reading model %s from Demisto" % model_name, is_return_error)


def handle_error(message, is_return_error):
    if is_return_error:
        return_error(message)
    else:
        demisto.results(message)
        sys.exit(0)


def preprocess_text(text, model_type, is_return_error):
    if model_type in [FASTTEXT_MODEL_TYPE, UNKNOWN_MODEL_TYPE]:
        preprocess_type = 'nlp'
        hash_seed = demisto.args().get('hashSeed')
        clean_html = 'true'
    elif model_type == TORCH_TYPE:
        preprocess_type = 'none'
        hash_seed = None
        clean_html = 'false'
    if isinstance(text, str):
        input_type = 'string'
        input_ = text
    elif isinstance(text, list):
        input_type = 'json_string'
        input_ = json.dumps(text)
    language = demisto.args().get('language', 'English')
    tokenization = demisto.args().get('tokenizationMethod', 'tokenizer')
    args = {'input': input_,
            'hashSeed': hash_seed,
            'language': language,
            'tokenizationMethod': tokenization,
            'inputType': input_type,
            'preProcessType': preprocess_type,
            'dedupThreshold': '-1',
            'outputFormat': 'json',
            'textFields': 'text',
            'removeShortTextThreshold': '-1',
            'cleanHTML': clean_html}
    res = demisto.executeCommand('DBotPreProcessTextData', args)
    if is_error(res):
        handle_error(res[0]['Contents'], is_return_error)
    if isinstance(text, list):
        return [x['dbot_processed_text'] for x in json.loads(res[0]['Contents'])]
    elif isinstance(text, str):
        tokenized_text_result = res[0]['Contents']
        input_text = tokenized_text_result['hashedTokenizedText'] if tokenized_text_result.get(
            'hashedTokenizedText') else \
            tokenized_text_result['tokenizedText']
        if tokenized_text_result.get('hashedTokenizedText'):
            words_to_token_maps = tokenized_text_result['wordsToHashedTokens']
        else:
            words_to_token_maps = tokenized_text_result['originalWordsToTokens']
        return input_text, words_to_token_maps


def predict_phishing_words(model_name, model_store_type, email_subject, email_body, min_text_length, label_threshold,
                           word_threshold, top_word_limit, is_return_error, set_incidents_fields=False):
    model_data, model_type = get_model_data(model_name, model_store_type, is_return_error)
    if model_type.strip() == '' or model_type.strip() == 'Phishing':
        model_type = FASTTEXT_MODEL_TYPE
    if model_type not in [FASTTEXT_MODEL_TYPE, TORCH_TYPE, UNKNOWN_MODEL_TYPE]:
        model_type = UNKNOWN_MODEL_TYPE
    phishing_model = demisto_ml.phishing_model_loads_handler(model_data, model_type)
    is_model_applied_on_a_single_incidents = isinstance(email_subject, str) and isinstance(email_body, str)
    if is_model_applied_on_a_single_incidents:
        return predict_single_incident_full_output(email_subject, email_body, is_return_error, label_threshold,
                                                   min_text_length,
                                                   model_type, phishing_model, set_incidents_fields, top_word_limit,
                                                   word_threshold)
    else:
        return predict_batch_incidents_light_output(email_subject, email_body, phishing_model, model_type,
                                                    min_text_length)


def predict_batch_incidents_light_output(email_subject, email_body, phishing_model, model_type, min_text_length):
    text_list = [{'text': "%s \n%s" % (subject, body)} for subject, body in zip(email_subject, email_body)]
    preprocessed_text_list = preprocess_text(text_list, model_type, is_return_error=False)
    batch_predictions = []
    for input_text in preprocessed_text_list:
        incident_res = {'Label': -1, 'Probability': -1, 'Error': ''}
        filtered_text, filtered_text_number_of_words = phishing_model.filter_model_words(input_text)
        if filtered_text_number_of_words == 0:
            incident_res['Error'] = "The model does not contain any of the input text words"
        elif filtered_text_number_of_words < min_text_length:
            incident_res['Error'] = "The model contains fewer than %d words" % min_text_length
        else:
            pred = phishing_model.predict(input_text)
            incident_res['Label'] = pred[0]
            prob = pred[1]
            if isinstance(prob, np.floating):
                prob = prob.item()
            incident_res['Probability'] = prob
        batch_predictions.append(incident_res)
    return {
        'Type': entryTypes['note'],
        'Contents': batch_predictions,
        'ContentsFormat': formats['json'],
        'HumanReadable': 'Applied predictions on {} incidents.'.format(len(batch_predictions)),
    }


def predict_single_incident_full_output(email_subject, email_body, is_return_error, label_threshold, min_text_length,
                                        model_type, phishing_model, set_incidents_fields, top_word_limit,
                                        word_threshold):
    text = "%s \n%s" % (email_subject, email_body)
    input_text, words_to_token_maps = preprocess_text(text, model_type, is_return_error)
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

    positive_tokens = OrderedSet(explain_result['PositiveWords'])
    negative_tokens = OrderedSet(explain_result['NegativeWords'])
    positive_words = find_words_contain_tokens(positive_tokens, words_to_token_maps)
    negative_words = find_words_contain_tokens(negative_tokens, words_to_token_maps)
    positive_words = list(OrderedSet([s.strip(punctuation) for s in positive_words]))
    negative_words = list(OrderedSet([s.strip(punctuation) for s in negative_words]))
    positive_words = [w for w in positive_words if w.isalnum()]
    negative_words = [w for w in negative_words if w.isalnum()]
    highlighted_text_markdown = text.strip()
    for word in positive_words:
        for cased_word in [word.lower(), word.title(), word.upper()]:
            highlighted_text_markdown = re.sub(r'(?<!\w)({})(?!\w)'.format(cased_word), '**{}**'.format(cased_word),
                                               highlighted_text_markdown)
    highlighted_text_markdown = re.sub(r'\n+', '\n', highlighted_text_markdown)
    explain_result['PositiveWords'] = [w.lower() for w in positive_words]
    explain_result['NegativeWords'] = [w.lower() for w in negative_words]
    explain_result['OriginalText'] = text.strip()
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
    if 'CustomFields' in incident and incident['CustomFields'] is not None and field in incident['CustomFields']:
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
