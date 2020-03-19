from collections import defaultdict

import demistomock


def get_args():
    args = defaultdict(lambda: "yes")
    args['encoding'] = 'utf8'
    args['removeNonEnglishWords'] = 'no'
    args['hashWordWithSeed'] = "5381"
    return args


demistomock.args = get_args

from WordTokenizer import remove_line_breaks, clean_html, tokenize_text, word_tokenize,\
    remove_multiple_whitespaces, map_indices_to_words  # noqa


def test_remove_line_breaks():
    text = """this text
    with line break
    """
    assert remove_multiple_whitespaces(remove_line_breaks(text)) == "this text with line break"


def test_clean_html():
    text = """<html>hello</html>"""
    assert clean_html(text) == "hello"


def test_tokenize_text():
    text = "test@demisto.com is 100 going to http://google.com bla bla"
    assert "EMAIL_PATTERN NUMBER_PATTERN go URL_PATTERN bla bla" == tokenize_text(text)[0]


def test_word_tokenize():
    text = "test@demisto.com is 100 going to http://google.com bla bla"
    entry = word_tokenize(text)
    assert "EMAIL_PATTERN NUMBER_PATTERN go URL_PATTERN bla bla" == entry['Contents']['tokenizedText']
    assert "2074773130 1320446219 5863419 1810208405 193487380 193487380" == entry['Contents'][
        'hashedTokenizedText']


def test_word_tokenize_words_to_tokens():
    words = ["let\'s", "gonna", "ain't", "we'll", "shouldn't", "will\\won't"]
    words_to_tokens = {w: tokenize_text(w)[0].split() for w in words}
    tokenized_text, _, original_words_to_tokens, _ = tokenize_text(' '.join(words_to_tokens))
    for w, tokens_list in words_to_tokens.items():
        if w not in original_words_to_tokens:
            continue
        tokens_list_output = original_words_to_tokens[w]
        assert all(t in tokens_list_output for t in tokens_list) and all(t in tokens_list for t in tokens_list_output)


def test_inclusion():
    text = 'a aa  aaa'
    indices_to_words = map_indices_to_words(text)
    assert indices_to_words == {0: 'a', 2: 'aa', 3: 'aa', 6: 'aaa', 7: 'aaa', 8: 'aaa'}
