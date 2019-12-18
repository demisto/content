from collections import defaultdict

import pytest

from CommonServerPython import *
from DBotPredictPhishingWords import get_model_data, predict_phishing_words

TOKENIZATION_RESULT = None


def get_args():
    args = defaultdict(lambda: "yes")
    args['encoding'] = 'utf8'
    args['encoding'] = 'utf8'
    args['removeNonEnglishWords'] = 'no'
    return args


def bold(word):
    return '<b>{}</b>'.format(word)


def executeCommand(command, args=None):
    global TOKENIZATION_RESULT
    if command == 'getList':
        return [{'Contents': "ModelDataList", 'Type': 'note'}]
    elif command == 'getMLModel':
        return [{'Contents': {'modelData': "ModelDataML"}, 'Type': 'note'}]
    elif command == 'WordTokenizerNLP':
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


def test_get_model_data(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    assert "ModelDataList" == get_model_data("test", "list")
    assert "ModelDataML" == get_model_data("test", "mlModel")


def test_predict_phishing_words(mocker):
    global TOKENIZATION_RESULT
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("text", 2), create=True)
    mocker.patch('demisto_ml.explain_model_words', return_value={"Label": 'Valid',
                                                                 'Probability': 0.7,
                                                                 'PositiveWords': ['word1'],
                                                                 'NegativeWords': ['word2']},
                 create=True)

    TOKENIZATION_RESULT = {'originalText': 'word1 word2 word3',
                           'tokenizedText': "word1 word2 word3",
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           }

    res = predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
    correct_res = {'OriginalText': 'word1 word2 word3',
                   'Probability': 0.7, 'NegativeWords': ['word2'],
                   'TextTokensHighlighted': '<b>word1</b> word2 word3',
                   'PositiveWords': ['word1'], 'Label': 'Valid'}
    assert res['Contents'] == correct_res


def test_predict_phishing_words_low_threshold(mocker):
    global TOKENIZATION_RESULT
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("text", 2), create=True)
    mocker.patch('demisto_ml.explain_model_words', return_value={"Label": 'Valid',
                                                                 'Probability': 0.7,
                                                                 'PositiveWords': ['word1'],
                                                                 'NegativeWords': ['word2']},
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

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("", 0), create=True)
    TOKENIZATION_RESULT = {'originalText': 'word1 word2 word3',
                           'tokenizedText': "word1 word2 word3",
                           'hashedTokenizedText': '23423 432432 12321',
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           'wordsToHashedTokens': {'word1': ['23423'], 'word2': ['432432'], 'word3': ['12321']},
                           }
    with pytest.raises(SystemExit):
        predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("", 10), create=True)
    with pytest.raises(SystemExit):
        predict_phishing_words("modelName", "list", "subject", "body", 20, 0, 0, 10, True)


def test_predict_phishing_words_hashed(mocker):
    global TOKENIZATION_RESULT
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10, 'hashSeed': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("text", 2), create=True)
    mocker.patch('demisto_ml.explain_model_words', return_value={"Label": 'Valid',
                                                                 'Probability': 0.7,
                                                                 'PositiveWords': ['23423'],
                                                                 'NegativeWords': ['432432']},
                 create=True)
    TOKENIZATION_RESULT = {'originalText': 'word1 word2 word3',
                           'tokenizedText': "word1 word2 word3",
                           'hashedTokenizedText': '23423 432432 12321',
                           'originalWordsToTokens': {'word1': ['word1'], 'word2': ['word2'], 'word3': ['word3']},
                           'wordsToHashedTokens': {'word1': ['23423'], 'word2': ['432432'], 'word3': ['12321']},
                           }
    res = predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
    assert res['Contents'] == {'OriginalText': 'word1 word2 word3',
                               'Probability': 0.7, 'NegativeWords': ['word2'],
                               'TextTokensHighlighted': '<b>word1</b> word2 word3',
                               'PositiveWords': ['word1'], 'Label': 'Valid'}


def test_predict_phishing_words_tokenization_by_character(mocker):
    global TOKENIZATION_RESULT
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10, 'hashSeed': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("text", 2), create=True)
    original_text = 'this is a test'
    tokenized_text = ' '.join(c for c in original_text if c != ' ')
    original_words_to_tokes = {w: [c for c in w] for w in original_text.split()}
    TOKENIZATION_RESULT = {'originalText': original_text,
                           'tokenizedText': tokenized_text,
                           'originalWordsToTokens': original_words_to_tokes,
                           }
    positive_tokens = ['t', 'i']
    negative_tokens = []
    mocker.patch('demisto_ml.explain_model_words', return_value={"Label": 'Valid',
                                                                 'Probability': 0.7,
                                                                 'PositiveWords': positive_tokens,
                                                                 'NegativeWords': negative_tokens}, create=True)
    res = predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
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

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10, 'hashSeed': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("text", 2), create=True)
    original_text = 'this is a test'
    tokenized_text = ' '.join(c for c in original_text if c != ' ')
    original_words_to_tokes = {w: [c for c in w] for w in original_text.split()}
    TOKENIZATION_RESULT = {'originalText': original_text,
                           'tokenizedText': tokenized_text,
                           'originalWordsToTokens': original_words_to_tokes,
                           'hashedTokenizedText': ''.join(hash_token(t) if t != ' ' else t for t in tokenized_text),
                           'wordsToHashedTokens': {w: [hash_token(t) for t in token_list] for w, token_list in
                                                   original_words_to_tokes.items()},
                           }
    positive_tokens = [hash_token('t'), hash_token('i')]
    negative_tokens = []
    mocker.patch('demisto_ml.explain_model_words', return_value={"Label": 'Valid',
                                                                 'Probability': 0.7,
                                                                 'PositiveWords': positive_tokens,
                                                                 'NegativeWords': negative_tokens}, create=True)
    res = predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
    correct_highlighted = ' '.join(
        bold(w) if any(unhash_token(pos_token) in w for pos_token in positive_tokens) else w for w in original_text.split())
    assert res['Contents'] == {'OriginalText': original_text,
                               'Probability': 0.7, 'NegativeWords': negative_tokens,
                               'TextTokensHighlighted': correct_highlighted,
                               'PositiveWords': [w for w in original_text.split() if
                                                 any(unhash_token(pos_token) in w for pos_token in positive_tokens)],
                               'Label': 'Valid'}
