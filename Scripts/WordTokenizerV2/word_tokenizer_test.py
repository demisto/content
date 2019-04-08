import demistomock
from collections import defaultdict


def get_args():
    return defaultdict(lambda: "yes")


demistomock.args = get_args

from WordTokenizer import remove_line_breaks, clean_html, tokenize_text  # noqa


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
    assert "EMAIL_PATTERN NUMBER_PATTERN go URL_PATTERN" == tokenize_text(text)
