import demistomock
from collections import defaultdict


def get_args():
    args = defaultdict(lambda: "yes")
    args['encoding'] = 'utf8'
    args['encoding'] = 'utf8'
    args['removeNonEnglishWords'] = 'no'
    return args


demistomock.args = get_args

from WordTokenizer import remove_line_breaks, clean_html, tokenize_text, word_tokenize  # noqa


def test_remove_line_breaks():
    text = """this text
    with line break
    """
    assert remove_line_breaks(text) == "this text with line break"


def test_clean_html():
    text = """<html>hello</html>"""
    assert clean_html(text) == "hello"


def test_tokenize_text():
    text = "test@demisto.com is 100 going to http://google.com bla bla"
    assert "EMAIL_PATTERN NUMBER_PATTERN go URL_PATTERN bla bla" == tokenize_text(text)


def test_word_tokenize():
    text = "test@demisto.com is 100 going to http://google.com bla bla"
    assert "EMAIL_PATTERN NUMBER_PATTERN go URL_PATTERN bla bla" == word_tokenize(text)['Contents']
