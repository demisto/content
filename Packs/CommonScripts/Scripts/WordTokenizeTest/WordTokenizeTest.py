import demistomock as demisto
from CommonServerPython import *
import nltk
import re
from html.parser import HTMLParser
from html import unescape
html_parser = HTMLParser()

CLEAN_HTML = (demisto.args().get('cleanHtml', 'yes') == 'yes')
REMOVE_LINE_BREAKS = (demisto.args().get('removeLineBreaks', 'yes') == 'yes')
TOKENIZE_TYPE = demisto.args().get('type', 'word')
TEXT_ENCODE = demisto.args().get('zencoding', 'utf-8')
HASH_SEED = demisto.args().get('hashWordWithSeed')

REMOVE_HTML_PATTERNS = [
    re.compile(r"(?is)<(script|style).*?>.*?(</\1>)"),
    re.compile(r"(?s)<!--(.*?)-->[\n]?"),
    re.compile(r"(?s)<.*?>"),
    re.compile(r"&nbsp;"),
    re.compile(r" +")
]


def clean_html(text):
    if not CLEAN_HTML:
        return text

    cleaned = text
    for pattern in REMOVE_HTML_PATTERNS:
        cleaned = pattern.sub(" ", cleaned)
    return unescape(cleaned).strip()


def tokenize_text(text):
    if not text:
        return ''
    text = text.lower()
    if TOKENIZE_TYPE == 'word':
        word_tokens = nltk.word_tokenize(text)
    elif TOKENIZE_TYPE == 'punkt':
        word_tokens = nltk.wordpunct_tokenize(text)
    else:
        raise Exception("Unsupported tokenize type: %s" % TOKENIZE_TYPE)
    if HASH_SEED:
        word_tokens = map(str, map(lambda x: hash_djb2(x, int(HASH_SEED)), word_tokens))
    return (' '.join(word_tokens)).strip()


def remove_line_breaks(text):
    if not REMOVE_LINE_BREAKS:
        return text

    return text.replace("\r", "").replace("\n", "")


def main():
    text = demisto.args()['value']

    if type(text) is not list:
        text = [text]
    result = list(map(remove_line_breaks, map(tokenize_text, map(clean_html, text))))

    if len(result) == 1:
        result = result[0]

    demisto.results({
        'Contents': result,
        'ContentsFormat': formats['json'] if type(result) is list else formats['text'],
        'EntryContext': {
            'WordTokenizeOutput': result
        }
    })


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
