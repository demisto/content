# pylint: disable=no-member
from string import punctuation

import demisto_ml

from CommonServerPython import *


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
        sys.exit(1)


def predict_phishing_words(model_name, model_store_type, email_subject, email_body, min_text_length, label_threshold,
                           word_threshold, top_word_limit, is_return_error):
    model_data = get_model_data(model_name, model_store_type, is_return_error)
    model = demisto_ml.decode_model(model_data)
    text = "%s %s" % (email_subject, email_body)
    res = demisto.executeCommand('WordTokenizerNLP', {'value': text,
                                                      'hashWordWithSeed': demisto.args().get('hashSeed')})
    if is_error(res[0]):
        handle_error(res[0]['Contents'], is_return_error)
    tokenized_text_result = res[0]['Contents']
    input_text = tokenized_text_result['hashedTokenizedText'] if tokenized_text_result.get('hashedTokenizedText') else \
        tokenized_text_result['tokenizedText']
    filtered_text, filtered_text_number_of_words = demisto_ml.filter_model_words(input_text, model)
    if filtered_text_number_of_words == 0:
        handle_error("The model does not contains any of the input text words", is_return_error)
    if filtered_text_number_of_words < min_text_length:
        handle_error("The model contains less then %d words" % min_text_length, is_return_error)

    explain_result = demisto_ml.explain_model_words(model,
                                                    input_text,
                                                    0,
                                                    word_threshold,
                                                    top_word_limit)
    if explain_result["Probability"] < label_threshold:
        handle_error("Label probability is {:.2f} and it's below the input threshold".format(
            explain_result["Probability"]), is_return_error)

    if tokenized_text_result.get('hashedTokenizedText'):
        words_to_token_maps = tokenized_text_result['wordsToHashedTokens']
    else:
        words_to_token_maps = tokenized_text_result['originalWordsToTokens']
    positive_tokens = set([''.join(c for c in word if c.isalnum()) for word in explain_result['PositiveWords']])
    negative_tokens = set([''.join(c for c in word if c.isalnum()) for word in explain_result['NegativeWords']])
    positive_words = find_words_contain_tokens(positive_tokens, words_to_token_maps)
    negative_words = find_words_contain_tokens(negative_tokens, words_to_token_maps)
    positive_words = [s.strip(punctuation) for s in positive_words]
    negative_words = [s.strip(punctuation) for s in negative_words]

    explain_result['PositiveWords'] = positive_words
    explain_result['NegativeWords'] = negative_words
    explain_result['OriginalText'] = tokenized_text_result['originalText'].strip()
    explain_result['TextTokensHighlighted'] = tokenized_text_result['tokenizedText']

    res = demisto.executeCommand('HighlightWords', {'text': tokenized_text_result['originalText'],
                                                    'terms': ",".join(positive_words)})
    res = res[0]
    if not is_error(res):
        highlighted_text_markdown = res['Contents']
        explain_result['TextTokensHighlighted'] = highlighted_text_markdown
    explain_result_hr = dict(explain_result)
    explain_result_hr['PositiveWords'] = ", ".join(positive_words)
    explain_result_hr['NegativeWords'] = ", ".join(negative_words)
    explain_result_hr['Probability'] = "%.2f" % explain_result_hr['Probability']
    return {
        'Type': entryTypes['note'],
        'Contents': explain_result,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('DBot Predict Phishing Words', explain_result_hr,
                                         headers=['TextTokensHighlighted', 'Label', 'Probability',
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


def main():
    result = predict_phishing_words(demisto.args()['modelName'],
                                    demisto.args()['modelStoreType'],
                                    demisto.args().get('emailSubject', ''),
                                    demisto.args().get('emailBody', '') or demisto.args().get('emailBodyHTML', ''),
                                    int(demisto.args()['minTextLength']),
                                    float(demisto.args().get("labelProbabilityThreshold", 0)),
                                    float(demisto.args().get('wordThreshold', 0)),
                                    int(demisto.args()['topWordsLimit']),
                                    demisto.args()['returnError'] == 'true'
                                    )

    return result


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
