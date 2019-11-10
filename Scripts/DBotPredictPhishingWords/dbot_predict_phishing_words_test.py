from CommonServerPython import *
from collections import defaultdict
from DBotPredictPhishingWords import get_model_data, predict_phishing_words
import pytest


def get_args():
    args = defaultdict(lambda: "yes")
    args['encoding'] = 'utf8'
    args['encoding'] = 'utf8'
    args['removeNonEnglishWords'] = 'no'
    return args


def executeCommand(command, args=None):
    if command == 'getList':
        return [{'Contents': "ModelDataList", 'Type': 'note'}]
    elif command == 'getMLModel':
        return [{'Contents': {'modelData': "ModelDataML"}, 'Type': 'note'}]
    elif command == 'WordTokenizerNLP':
        if args.get('hashWordWithSeed'):
            return [{'Contents': {'originalText': 'word1 word2 word3',
                                  'tokenizedText': "word1 word2 word3", 'hashedTokenizedText': '23423 432432 12321'},
                     'Type': 'note'}]
        else:
            return [{'Contents': {'originalText': 'word1 word2 word3',
                                  'tokenizedText': "word1 word2 word3"},
                     'Type': 'note'}]
    elif command == 'HighlightWords':
        return [{'Contents': 'word1 word2 word3', 'Type': 'note'}]


def test_get_model_data(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    assert "ModelDataList" == get_model_data("test", "list")
    assert "ModelDataML" == get_model_data("test", "mlModel")


def test_predict_phishing_words(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("text", 2), create=True)
    mocker.patch('demisto_ml.explain_model_words', return_value={"Label": 'Valid',
                                                                 'Probability': 0.7,
                                                                 'PositiveWords': ['word1'],
                                                                 'NegativeWords': ['word2']},
                 create=True)
    res = predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
    assert res['Contents'] == {'OriginalText': 'word1 word2 word3',
                               'Probability': 0.7, 'NegativeWords': ['word2'],
                               'TextTokensHighlighted': 'word1 word2 word3',
                               'PositiveWords': ['word1'], 'Label': 'Valid'}


def test_predict_phishing_words_low_threshold(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("text", 2), create=True)
    mocker.patch('demisto_ml.explain_model_words', return_value={"Label": 'Valid',
                                                                 'Probability': 0.7,
                                                                 'PositiveWords': ['word1'],
                                                                 'NegativeWords': ['word2']},
                 create=True)
    with pytest.raises(SystemExit):
        predict_phishing_words("modelName", "list", "subject", "body", 0, 0.8, 0, 10, True)


def test_predict_phishing_words_no_words(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("", 0), create=True)
    with pytest.raises(SystemExit):
        predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("", 10), create=True)
    with pytest.raises(SystemExit):
        predict_phishing_words("modelName", "list", "subject", "body", 20, 0, 0, 10, True)



def test_predict_phishing_words_hashed(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'args', return_value={'topWordsLimit': 10, 'hashSeed': 10})
    mocker.patch('demisto_ml.decode_model', return_value="Model", create=True)
    mocker.patch('demisto_ml.filter_model_words', return_value=("text", 2), create=True)
    mocker.patch('demisto_ml.explain_model_words', return_value={"Label": 'Valid',
                                                                 'Probability': 0.7,
                                                                 'PositiveWords': ['23423'],
                                                                 'NegativeWords': ['432432']},
                 create=True)
    res = predict_phishing_words("modelName", "list", "subject", "body", 0, 0, 0, 10, True)
    assert res['Contents'] == {'OriginalText': 'word1 word2 word3',
                               'Probability': 0.7, 'NegativeWords': ['word2'],
                               'TextTokensHighlighted': 'word1 word2 word3',
                               'PositiveWords': ['word1'], 'Label': 'Valid'}
