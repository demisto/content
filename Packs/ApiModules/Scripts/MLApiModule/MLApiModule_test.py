import string

from MLApiModule import Tokenizer
from copy import deepcopy
import re

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


def test_clean_html():
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


def test_number_pattern():
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


def test_remove_new_lines():
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


def test_hash_seed():
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


def test_remove_stop_words():
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


def test_remove_punct():
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


def test_remove_non_alpha():
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


def test_replace_emails():
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


def test_replace_urls():
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


def test_replace_numbers():
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


def test_lemma():
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


def test_max_test_length():
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


def test_tokenization_methold():
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


def test_original_words_to_tokens():
    t1 = Tokenizer(**neagative_initalization)
    text = "I'm 29 years old and I don't live in Petach Tikva"
    res1 = t1.word_tokenize(text)
    expected = {"I'm": ['i', "'m"], '29': ['29'], 'years': ['years'], 'old': ['old'], 'and': ['and'], 'I': ['i'],
                "don't": ['do', "n't"], 'live': ['live'], 'in': ['in'], 'Petach': ['petach'], 'Tikva': ['tikva']}
    assert res1['originalWordsToTokens'] == expected
