from collections import defaultdict

import pytest
from CommonServerPython import *
from DBotPredictPhishingWords import get_model_data, predict_phishing_words, main

TOKENIZATION_RESULT = None


class PhishingModelMock:

    def __init__(self, filter_words_res=None, explain_model_words_res=None):
        self.filter_words_res = filter_words_res
        self.explain_model_words_res = explain_model_words_res

    def filter_model_words(self):
        return self.filter_words_res

    def explain_model_words(self, a, b, c, d):
        return self.explain_model_words_res


def get_args():
    args = defaultdict(lambda: "yes")
    args['encoding'] = 'utf8'
    args['encoding'] = 'utf8'
    args['removeNonEnglishWords'] = 'no'
    return args


def bold(word):
    return f'**{word}**'


def executeCommand(command, args=None):
    global TOKENIZATION_RESULT
    if command == 'getList':
        return [{'Contents': "ModelDataList", 'Type': 'note'}]
    elif command == 'getMLModel':
        return [{'Contents': {'modelData': "ModelDataML",
                              'model': {'type': {'type': ''}}},
                 'Type': 'note'}]
    elif command == 'DBotPreProcessTextData':
        TOKENIZATION_RESULT['originalText'] = args['input']
        TOKENIZATION_RESULT['tokenizedText'] = args['input']
        return [{'Contents': TOKENIZATION_RESULT,
                 'Type': 'note'}]
    elif command == 'HighlightWords':
        text = args['text']
        terms = set(args['terms'].split(','))
        words = text.split()
        for i, w in enumerate(words):
            if w in terms:
                words[i] = bold(w)
        return [{'Contents': ' '.join(words), 'Type': 'note'}]
    return None


def test_get_model_data(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    assert get_model_data("test", "list", True)[0] == "ModelDataList"
    assert get_model_data("test", "mlModel", True)[0] == "ModelDataML"


def test_predict_phishing_words(mocker):
    global TOKENIZATION_RESULT
    d = {"Label": 'Valid',
         'Probability': 0.7,
         'PositiveWords': ['word1'],
         'NegativeWords': ['word2']}
    phishing_mock = PhishingModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.phishing_model_loads_handler', return_value=phishing_mock, create=True)
    mocker.patch.object(demisto, 'incidents', return_value=[{'isPlayground': True}])
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("text", 2), create=True)
    mocker.patch.object(phishing_mock, 'explain_model_words', return_value=d,
                        create=True)

    TOKENIZATION_RESULT = {'originalText': 'word1 word2 word3',
                           'tokenizedText': "word1 word2 word3",
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           }

    email_subject = "word1"
    email_body = "word2 word3"
    res = predict_phishing_words("modelName", "list", email_subject, email_body, 0, 0, 0, 10, True)
    correct_res = {'OriginalText': concatenate_subject_body(email_subject, email_body),
                   'Probability': 0.7, 'NegativeWords': ['word2'],
                   'TextTokensHighlighted': concatenate_subject_body(f'**{email_subject}**', email_body),
                   'PositiveWords': ['word1'],
                   'Label': 'Valid'}
    assert res['Contents'] == correct_res


def concatenate_subject_body(email_subject, email_body):
    return f'{email_subject} \n{email_body}'


def test_predict_phishing_words_low_threshold(mocker):
    global TOKENIZATION_RESULT
    d = {"Label": 'Valid',
         'Probability': 0.7,
         'PositiveWords': ['word1'],
         'NegativeWords': ['word2']}
    phishing_mock = PhishingModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.phishing_model_loads_handler', return_value=phishing_mock, create=True)
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("text", 2), create=True)
    mocker.patch.object(phishing_mock, 'explain_model_words', return_value=d,
                        create=True)
    TOKENIZATION_RESULT = {'originalText': 'word1 word2 word3',
                           'tokenizedText': "word1 word2 word3",
                           'hashedTokenizedText': '23423 432432 12321',
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           'wordsToHashedTokens': {'word1': ['23423'], 'word2': ['432432'], 'word3': ['12321']},
                           }
    with pytest.raises(SystemExit):
        predict_phishing_words("modelName", "list", "subject", "body", 0, 0.8, 0, 10, True)


def test_predict_phishing_words_no_words(mocker):
    global TOKENIZATION_RESULT
    phishing_mock = PhishingModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.phishing_model_loads_handler', return_value=phishing_mock, create=True)
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("", 0), create=True)
    TOKENIZATION_RESULT = {'originalText': 'word1 word2 word3',
                           'tokenizedText': "word1 word2 word3",
                           'hashedTokenizedText': '23423 432432 12321',
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           'wordsToHashedTokens': {'word1': ['23423'], 'word2': ['432432'], 'word3': ['12321']},
                           }
    with pytest.raises(SystemExit):
        predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("", 10), create=True)
    with pytest.raises(SystemExit):
        predict_phishing_words("modelName", "list", "subject", "body", 20, 0, 0, 10, True)


def test_predict_phishing_words_hashed(mocker):
    global TOKENIZATION_RESULT
    d = {"Label": 'Valid',
         'Probability': 0.7,
         'PositiveWords': ['23423'],
         'NegativeWords': ['432432']}
    phishing_mock = PhishingModelMock()
    mocker.patch.object(demisto, 'incidents', return_value=[{'isPlayground': True}])

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10, 'hashSeed': 10})
    mocker.patch('demisto_ml.phishing_model_loads_handler', return_value=phishing_mock, create=True)
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("text", 2), create=True)
    mocker.patch.object(phishing_mock, 'explain_model_words', return_value=d,
                        create=True)
    TOKENIZATION_RESULT = {'originalText': 'word1 word2 word3',
                           'tokenizedText': "word1 word2 word3",
                           'hashedTokenizedText': '23423 432432 12321',
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           'wordsToHashedTokens': {'word1': ['23423'], 'word2': ['432432'], 'word3': ['12321']},
                           }
    email_subject = "word1"
    email_body = "word2 word3"
    res = predict_phishing_words("modelName", "list", email_subject, email_body, 0, 0, 0, 10, True)
    assert res['Contents'] == {'OriginalText': concatenate_subject_body(email_subject, email_body),
                               'Probability': 0.7, 'NegativeWords': ['word2'],
                               'TextTokensHighlighted': concatenate_subject_body(f'**{email_subject}**',
                                                                                 email_body),
                               'PositiveWords': ['word1'], 'Label': 'Valid'}


def test_predict_phishing_words_tokenization_by_character(mocker):
    global TOKENIZATION_RESULT
    phishing_mock = PhishingModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10, 'hashSeed': 10})
    mocker.patch('demisto_ml.phishing_model_loads_handler', return_value=phishing_mock, create=True)
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("text", 2), create=True)
    mocker.patch.object(demisto, 'incidents', return_value=[{'isPlayground': True}])
    original_text = 'this is a test'
    tokenized_text = ' '.join(c for c in original_text if c != ' ')
    original_words_to_tokes = {w: list(w) for w in original_text.split()}
    TOKENIZATION_RESULT = {'originalText': original_text,
                           'tokenizedText': tokenized_text,
                           'originalWordsToTokens': original_words_to_tokes,
                           }
    positive_tokens = ['t', 'i']
    negative_tokens = []
    d = {"Label": 'Valid',
         'Probability': 0.7,
         'PositiveWords': positive_tokens,
         'NegativeWords': negative_tokens}
    mocker.patch.object(phishing_mock, 'explain_model_words', return_value=d,
                        create=True)
    res = predict_phishing_words("modelName", "list", original_text, "", 0, 0, 0, 10, True)
    correct_highlighted = ' '.join(
        bold(w) if any(pos_token in w for pos_token in positive_tokens) else w for w in original_text.split())
    assert res['Contents'] == {'OriginalText': original_text,
                               'Probability': 0.7, 'NegativeWords': negative_tokens,
                               'TextTokensHighlighted': correct_highlighted,
                               'PositiveWords': [w for w in original_text.split() if
                                                 any(pos_token in w for pos_token in positive_tokens)],
                               'Label': 'Valid'}


def test_predict_phishing_words_tokenization_by_character_hashed(mocker):
    global TOKENIZATION_RESULT

    def hash_token(t):
        return str(ord(t))

    def unhash_token(t):
        return chr(int(t))

    phishing_mock = PhishingModelMock()
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10, 'hashSeed': 10})
    mocker.patch('demisto_ml.phishing_model_loads_handler', return_value=phishing_mock, create=True)
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("text", 2), create=True)
    mocker.patch.object(demisto, 'incidents', return_value=[{'isPlayground': True}])
    original_text = 'this is a test'
    tokenized_text = ' '.join(c for c in original_text if c != ' ')
    original_words_to_tokes = {w: list(w) for w in original_text.split()}
    TOKENIZATION_RESULT = {'originalText': original_text,
                           'tokenizedText': tokenized_text,
                           'originalWordsToTokens': original_words_to_tokes,
                           'hashedTokenizedText': ''.join(hash_token(t) if t != ' ' else t for t in tokenized_text),
                           'wordsToHashedTokens': {w: [hash_token(t) for t in token_list] for w, token_list in
                                                   original_words_to_tokes.items()},
                           }
    positive_tokens = [hash_token('t'), hash_token('i')]
    negative_tokens = []
    d = {"Label": 'Valid',
         'Probability': 0.7,
         'PositiveWords': positive_tokens,
         'NegativeWords': negative_tokens}
    mocker.patch.object(phishing_mock, 'explain_model_words', return_value=d,
                        create=True)
    res = predict_phishing_words("modelName", "list", original_text, "", 0, 0, 0, 10, True)
    correct_highlighted = ' '.join(
        bold(w) if any(unhash_token(pos_token) in w for pos_token in positive_tokens) else w for w in
        original_text.split())
    assert res['Contents'] == {'OriginalText': original_text,
                               'Probability': 0.7, 'NegativeWords': negative_tokens,
                               'TextTokensHighlighted': correct_highlighted,
                               'PositiveWords': [w for w in original_text.split() if
                                                 any(unhash_token(pos_token) in w for pos_token in positive_tokens)],
                               'Label': 'Valid'}


def test_main(mocker):
    global TOKENIZATION_RESULT
    phishing_mock = PhishingModelMock()
    d = {"Label": 'Valid',
         'Probability': 0.7,
         'PositiveWords': ['word1'],
         'NegativeWords': ['word2']}
    args = {'modelName': 'modelName', 'modelStoreType': 'list', 'emailSubject': 'word1', 'emailBody': 'word2 word3',
            'minTextLength': '0', 'labelProbabilityThreshold': '0', 'wordThreshold': '0', 'topWordsLimit': '10',
            'returnError': 'true'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[{'isPlayground': True}])
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch('demisto_ml.phishing_model_loads_handler', return_value=phishing_mock, create=True)
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("text", 2), create=True)
    mocker.patch.object(phishing_mock, 'explain_model_words', return_value=d,
                        create=True)

    TOKENIZATION_RESULT = {'originalText': '{} {}'.format(args['emailSubject'], args['emailBody']),
                           'tokenizedText': '{} {}'.format(args['emailSubject'], args['emailBody']),
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           }

    res = main()
    correct_res = {'OriginalText': concatenate_subject_body(args['emailSubject'], args['emailBody']),
                   'Probability': 0.7, 'NegativeWords': ['word2'],
                   'TextTokensHighlighted': concatenate_subject_body(bold(args['emailSubject']), args['emailBody']),
                   'PositiveWords': ['word1'], 'Label': 'Valid'}
    assert res['Contents'] == correct_res

    args['emailBodyHTML'] = args.pop('emailBody')
    TOKENIZATION_RESULT = {'originalText': concatenate_subject_body(args['emailSubject'], args['emailBodyHTML']),
                           'tokenizedText': concatenate_subject_body(args['emailSubject'], args['emailBodyHTML']),
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           }
    main()
    assert res['Contents'] == correct_res


def test_no_positive_words(mocker):
    # make sure that if no positive words were found, TextTokensHighlighted output is equivalent to original text
    global TOKENIZATION_RESULT
    phishing_mock = PhishingModelMock()
    d = {"Label": 'Valid',
         'Probability': 0.7,
         'PositiveWords': [],
         'NegativeWords': ['word2']}
    args = {'modelName': 'modelName', 'modelStoreType': 'list', 'emailSubject': 'word1', 'emailBody': 'word2 word3',
            'minTextLength': '0', 'labelProbabilityThreshold': '0', 'wordThreshold': '0', 'topWordsLimit': '10',
            'returnError': 'true'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    phishing_mock = PhishingModelMock(("text", 2))
    mocker.patch('demisto_ml.phishing_model_loads_handler', return_value=phishing_mock, create=True)
    mocker.patch.object(demisto, 'incidents', return_value=[{'isPlayground': True}])
    mocker.patch.object(phishing_mock, 'filter_model_words', return_value=("text", 2), create=True)
    mocker.patch.object(phishing_mock, 'explain_model_words', return_value=d,
                        create=True)

    TOKENIZATION_RESULT = {'originalText': '{} {}'.format(args['emailSubject'], args['emailBody']),
                           'tokenizedText': '{} {}'.format(args['emailSubject'], args['emailBody']),
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           }

    res = main()
    assert res['Contents']['TextTokensHighlighted'] == TOKENIZATION_RESULT['originalText']
