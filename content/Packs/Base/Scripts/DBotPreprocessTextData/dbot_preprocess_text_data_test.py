import unittest

from CommonServerPython import *
from DBotPreprocessTextData import clean_html, remove_line_breaks, hash_word, \
    concat_text_fields, whitelist_dict_fields, remove_short_text, remove_duplicate_by_indices, pre_process_batch, main, \
    read_file, Tokenizer
import string

from copy import deepcopy
import pandas as pd
import pickle


def test_clean_html(mocker):
    html_string = """
    <!DOCTYPE html>
        <html>
        <body>
        <h1>My First Heading</h1>
        </body>
        </html>
    """
    assert clean_html(html_string) == "My First Heading"


def test_remove_line_breaks():
    html_string = """
line1
line2
    """.strip()
    assert remove_line_breaks(html_string) == "line1 line2"


def test_hash_word():
    html_string = "word1"
    assert hash_word(html_string, 5381) == "279393330"


def test_concat_text_field(mocker):
    data = [
        {
            'body': 'TestBody',
            'body2': 'TestBody2',
            'subject': 'TestSubject',
        },
        {
            'body': 'TestBody',
            'subject': 'TestSubject'
        },
        {
            'body2': 'TestBody2',
            'subject': 'TestSubject'
        }
    ]
    text_fields = 'subject | subject2, Body | body2'
    concat_text_fields(data, 'target', text_fields.split(","))
    assert data[0]['target'] == 'TestSubject TestBody'
    assert data[1]['target'] == 'TestSubject TestBody'
    assert data[2]['target'] == 'TestSubject TestBody2'

    mocker.patch.object(demisto, 'dt', return_value=["value"])
    data = [{"Email": {"Body": "value", "Subject": "value"}}]
    concat_text_fields(data, 'target', "Email.Subject, Email.Body")
    assert data[0]['target'] == 'value value'

    mocker.patch.object(demisto, 'dt', return_value="value")
    data = [{"Email": {"Body": "value", "Subject": "value"}}]
    concat_text_fields(data, 'target', "Email.Subject, Email.Body")
    assert data[0]['target'] == 'value value'


def test_remove_fields_from_dict():
    data = [
        {
            'body': 'TestBody',
            'body2': 'TestBody2',
            'subject': 'TestSubject',
        },
        {
            'body': 'TestBody',
            'subject': 'TestSubject',
        },
        {
            'body2': 'TestBody2',
            'subject': 'TestSubject',
        }
    ]
    data = whitelist_dict_fields(data, ['subject', 'body'])
    found = False
    for d in data:
        if 'body2' in d:
            found = True
    assert not found


def test_remove_short_text():
    data = [
        {
            'body': 'TestBody1 TestBody2 TestBody3 TestBody4',
        },
        {
            'body': 'TestBody1 TestBody2',
        }
    ]
    filtered_data, desc = remove_short_text(data, 'body', 'body', 2)
    assert len(data) - len(filtered_data) == 1
    assert len(filtered_data) == 1


def test_remove_dups():
    data = [
        {
            'body': 'TestBody1 TestBody2 TestBody3 TestBody4',
        },
        {
            'body': 'TestBody1 TestBody2',
        },
        {
            'body': 'TestBody1 TestBody2',
        }
    ]
    data, desc = remove_duplicate_by_indices(data, [1])
    assert desc == "Dropped 1 samples duplicate to other samples\n"
    assert len(data) == 2


def test_pre_process():
    data = [
        {
            'body': 'TestBody1 TestBody2 TestBody3 TestBody4',
        },
        {
            'body': 'TestBody1 TestBody2 <h1> html </h1>',
        }
    ]
    data1 = pre_process_batch(data, "body", "processed", True, "none", None)
    assert data1 == [
        {'body': 'TestBody1 TestBody2 TestBody3 TestBody4', 'processed': 'TestBody1 TestBody2 TestBody3 TestBody4'},
        {'body': 'TestBody1 TestBody2 <h1> html </h1>', 'processed': 'TestBody1 TestBody2 html'}]
    data2 = pre_process_batch(data, "body", "processed", True, "none", 5381)
    assert data2 == [
        {'body': 'TestBody1 TestBody2 TestBody3 TestBody4', 'processed': '148060132 148060133 148060134 148060135'},
        {'body': 'TestBody1 TestBody2 <h1> html </h1>', 'processed': '148060132 148060133 2090341082'}]


def test_main(mocker):
    args = {
        'textFields': 'subject|subject2,body|body2',
        'input': './TestData/input_json_file_test',
        'inputType': 'json',
        'removeShortTextThreshold': 5,
        'dedupThreshold': -1,
        'preProcessType': 'nlp',
        'tokenizationMethod': '',
        'language': 'English',
        'cleanHTML': 'true',
        'outputFormat': 'json'
    }
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input_json_file_test'})
    mocker.patch.object(demisto, 'args', return_value=args)
    entry = main()
    os.remove('1_' + entry['FileID'])
    assert 'Read initial 3 samples' in entry['HumanReadable']
    assert 'Done processing' in entry['HumanReadable']
    assert entry['EntryContext']['DBotPreProcessTextData']['TextField'] == 'dbot_text'
    assert entry['EntryContext']['DBotPreProcessTextData']['TextFieldProcessed'] == 'dbot_processed_text'
    assert len(entry['Contents']) > 1


neagative_initalization = \
    {
        'clean_html': False,
        'remove_new_lines': False,
        'remove_non_english': False,
        'remove_stop_words': False,
        'remove_punct': False,
        'remove_non_alpha': False,
        'replace_emails': False,
        'replace_numbers': False,
        'lemma': False,
        'replace_urls': False
    }


class TestTokenizer(unittest.TestCase):
    def test_clean_html_tokenizer(self):
        args = deepcopy(neagative_initalization)
        args['clean_html'] = True
        t1 = Tokenizer(**args)
        text = """
            <!DOCTYPE html>
        <html>
        <body>
        <h1>My First Heading</h1>
        <p>My first paragraph</p>
        </body>
        </html>
        """
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == 'My First Heading My first paragraph'.lower()

        args['clean_html'] = False
        t2 = Tokenizer(**args)
        res2 = t2.word_tokenize(text)
        assert re.sub(r"\s+", "", res2['tokenizedText']) == re.sub(r"\s+", "", text.lower())

    def test_number_pattern(self):
        args = deepcopy(neagative_initalization)
        args['replace_numbers'] = True
        t1 = Tokenizer(**args)
        text = "I have 3 dogs"
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == "I have {} dogs".lower().format(t1.number_pattern)

        args['replace_numbers'] = False
        t1 = Tokenizer(**args)
        text = "I have 3 dogs"
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == text.lower()

    def test_remove_new_lines(self):
        args = deepcopy(neagative_initalization)
        args['remove_new_lines'] = True
        t1 = Tokenizer(**args)
        text = \
            """
I have 3 dogs
 I lied
"""
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == text.lower().replace('\n', '').replace('\r', '').strip()

    def test_hash_seed(self):
        def hash_djb2(s, seed=5381):
            """
             Hash string with djb2 hash function

             :type s: ``str``
             :param s: The input string to hash

             :type seed: ``int``
             :param seed: The seed for the hash function (default is 5381)

             :return: The hashed value
             :rtype: ``int``
            """
            hash_name = seed
            for x in s:
                hash_name = ((hash_name << 5) + hash_name) + ord(x)

            return hash_name & 0xFFFFFFFF

        args = deepcopy(neagative_initalization)
        args['hash_seed'] = 5
        t1 = Tokenizer(**args)
        text = 'hello world'
        res1 = t1.word_tokenize(text)
        assert res1['hashedTokenizedText'] == ' '.join(str(hash_djb2(word, 5)) for word in text.split())

        args['hash_seed'] = None
        t1 = Tokenizer(**args)
        text = 'hello world'
        res1 = t1.word_tokenize(text)
        assert 'hashedTokenizedText' not in res1

    def test_remove_stop_words(self):
        args = deepcopy(neagative_initalization)
        args['remove_stop_words'] = False
        t1 = Tokenizer(**args)
        text = 'let it be'
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == text

        args['remove_stop_words'] = True
        t1 = Tokenizer(**args)
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == 'let'

    def test_remove_punct(self):
        args = deepcopy(neagative_initalization)
        args['remove_punct'] = False
        t1 = Tokenizer(**args)
        text = 'let, it. be!'
        res1 = t1.word_tokenize(text)
        expected_result = text
        for punct in string.punctuation:
            expected_result = expected_result.replace(punct, ' ' + punct)
        assert res1['tokenizedText'] == expected_result

        args['remove_punct'] = True
        t1 = Tokenizer(**args)
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == 'let it be'

    def test_remove_non_alpha(self):
        tested_arg = 'remove_non_alpha'
        args = deepcopy(neagative_initalization)
        args[tested_arg] = False
        t1 = Tokenizer(**args)
        text = 'see you s00n'
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == text

        args[tested_arg] = True
        t1 = Tokenizer(**args)
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == 'see you'

    def test_replace_emails(self):
        tested_arg = 'replace_emails'
        args = deepcopy(neagative_initalization)
        args[tested_arg] = False
        t1 = Tokenizer(**args)
        text = 'my email is a@gmail.com'
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == text

        args[tested_arg] = True
        t1 = Tokenizer(**args)
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == 'my email is {}'.format(t1.email_pattern)

    def test_replace_urls(self):
        tested_arg = 'replace_urls'
        args = deepcopy(neagative_initalization)
        args[tested_arg] = False
        t1 = Tokenizer(**args)
        text = 'my url is www.google.com'
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == text

        args[tested_arg] = True
        t1 = Tokenizer(**args)
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == 'my url is {}'.format(t1.url_pattern)

    def test_replace_numbers(self):
        tested_arg = 'replace_numbers'
        args = deepcopy(neagative_initalization)
        args[tested_arg] = False
        t1 = Tokenizer(**args)
        text = 'i am 3 years old'
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == text

        args[tested_arg] = True
        t1 = Tokenizer(**args)
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == 'i am {} years old'.format(t1.number_pattern)

    def test_lemma(self):
        tested_arg = 'lemma'
        args = deepcopy(neagative_initalization)
        args[tested_arg] = False
        t1 = Tokenizer(**args)
        text = 'this tokenization method is exceeding my expectations'
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == text

        args[tested_arg] = True
        t1 = Tokenizer(**args)
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == 'this tokenization method be exceed my expectation'

    def test_max_test_length(self):
        text = 'example sentence'
        list_text = [text] * 2
        args = deepcopy(neagative_initalization)
        t1 = Tokenizer(**args)
        t1.max_text_length = len(text) + 1
        res1 = t1.word_tokenize(list_text)
        assert all(res1[i]['tokenizedText'] == text for i in range(len(list_text)))

        t1.max_text_length = len(text) - 1
        res1 = t1.word_tokenize(list_text)
        assert all(res1[i]['tokenizedText'] == '' for i in range(len(list_text)))

    def test_tokenization_methold(self):
        tokenization_method = 'byWords'
        language = 'fake language'
        args = deepcopy(neagative_initalization)
        args['tokenization_method'] = tokenization_method
        args['language'] = language
        t1 = Tokenizer(**args)
        text = 'example sentence.'
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == ''.join(c for c in text if c not in string.punctuation)

        tokenization_method = 'byLetters'
        args['tokenization_method'] = tokenization_method
        t1 = Tokenizer(**args)
        text = 'example sentence'
        res1 = t1.word_tokenize(text)
        assert res1['tokenizedText'] == ' '.join(c for c in text if c != ' ')

    def test_original_words_to_tokens(self):
        t1 = Tokenizer(**neagative_initalization)
        text = "I'm 29 years old and I don't live in Petach Tikva"
        res1 = t1.word_tokenize(text)
        expected = {"I'm": ['i', "'m"], '29': ['29'], 'years': ['years'], 'old': ['old'], 'and': ['and'], 'I': ['i'],
                    "don't": ['do', "n't"], 'live': ['live'], 'in': ['in'], 'Petach': ['petach'], 'Tikva': ['tikva']}
        assert res1['originalWordsToTokens'] == expected


def test_read_file(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input_json_file_test'})
    obj = read_file('231342@343', 'json')
    assert len(obj) >= 1
    with open('./TestData/input_json_file_test', 'r') as f:
        obj = read_file(f.read(), 'json_string')
        assert len(obj) >= 1

    with open('./TestData/input_pickle_file_test', 'wb') as f:
        f.write(pickle.dumps(obj))
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input_pickle_file_test'})
    obj_from_pickle = read_file('./TestData/input_pickle_file_test', 'pickle')
    assert len(obj_from_pickle) >= 1

    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input_json_file_test'})
    with open('./TestData/input_json_file_test', 'r') as f:
        obj = read_file(f.read(), 'json_string')
        df = pd.DataFrame.from_dict(obj)
        df.to_csv("./TestData/test.csv", index=False)
        mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/test.csv'})
        obj2 = read_file('231342@343', 'csv')
        assert len(obj2) == len(obj)

    with open('./TestData/input_json_file_test', 'r') as f:
        b64_input = base64.b64encode(f.read().encode('utf-8'))
        obj = read_file(b64_input, 'json_b64_string')
        assert len(obj) >= 1
