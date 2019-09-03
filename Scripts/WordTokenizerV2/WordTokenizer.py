import demistomock as demisto
from CommonServerPython import *

import spacy
import re
import json
from HTMLParser import HTMLParser

CLEAN_HTML = (demisto.args()['cleanHtml'] == 'yes')
REMOVE_LINE_BREAKS = (demisto.args()['removeLineBreaks'] == 'yes')
TEXT_ENCODE = demisto.args()['encoding']
HASH_SEED = demisto.args().get('hashWordWithSeed')

FILTER_ENGLISH_WORDS = demisto.args()['removeNonEnglishWords'] == 'yes'
REMOVE_STOP_WORDS = demisto.args()['removeStopWords'] == 'yes'
REMOVE_PUNCT = demisto.args()['removePunctuation'] == 'yes'
REMOVE_NON_ALPHA = demisto.args()['removeNonAlphaWords'] == 'yes'
REPLACE_EMAIL = demisto.args()['replaceEmails'] == 'yes'
REPLACE_URLS = demisto.args()['replaceUrls'] == 'yes'
REPLACE_NUMBERS = demisto.args()['replaceNumbers'] == 'yes'
LEMMATIZER = demisto.args()['useLemmatization'] == 'yes'
VALUE_IS_JSON = demisto.args()['isValueJson'] == 'yes'

HTML_PATTERNS = [
    re.compile(r"(?is)<(script|style).*?>.*?(</\1>)"),
    re.compile(r"(?s)<!--(.*?)-->[\n]?"),
    re.compile(r"(?s)<.*?>"),
    re.compile(r"&nbsp;"),
    re.compile(r" +")
]

# define global parsers
html_parser = HTMLParser()
nlp = spacy.load('en_core_web_sm')


def clean_html(text):
    if not CLEAN_HTML:
        return text

    cleaned = text
    for pattern in HTML_PATTERNS:
        cleaned = pattern.sub(" ", cleaned)
    return html_parser.unescape(cleaned).strip()


def remove_line_breaks(text):
    if not REMOVE_LINE_BREAKS:
        return text

    return re.sub(r"\s+", " ", text.replace("\r", " ").replace("\n", " ")).strip()


def hash_word(word):
    return str(hash_djb2(word, int(HASH_SEED)))


def tokenize_text(text):
    try:
        unicode_text = unicode(text)
    except Exception:
        unicode_text = text
    doc = nlp(unicode(unicode_text))
    words = []
    for token in doc:
        if token.is_space:
            continue
        elif REMOVE_STOP_WORDS and token.is_stop:
            continue
        elif REMOVE_PUNCT and token.is_punct:
            continue
        elif REPLACE_EMAIL and '@' in token.text:
            words.append("EMAIL_PATTERN")
        elif REPLACE_URLS and token.like_url:
            words.append("URL_PATTERN")
        elif REPLACE_NUMBERS and (token.like_num or token.pos_ == 'NUM'):
            words.append("NUMBER_PATTERN")
        elif REMOVE_NON_ALPHA and not token.is_alpha:
            continue
        elif FILTER_ENGLISH_WORDS and token.text not in nlp.vocab:
            continue
        else:
            if LEMMATIZER and token.lemma_ != '-PRON-':
                words.append(token.lemma_)
            else:
                words.append(token.lower_)
    hashed_words = []
    if HASH_SEED:
        for word in words:
            word_hashed = hash_word(word)
            hashed_words.append(word_hashed)

    return ' '.join(words).encode(TEXT_ENCODE).strip(), ' '.join(hashed_words) if len(hashed_words) > 0 else None


def word_tokenize(text):
    if VALUE_IS_JSON:
        try:
            text = json.loads(text)
        except Exception:
            pass

    if not isinstance(text, list):
        text = [text]

    result = []
    for t in text:
        original_text = t
        t = remove_line_breaks(t)
        t = clean_html(t)
        tokenized_text, hash_tokenized_text = tokenize_text(t)
        text_result = {
            'originalText': original_text,
            'tokenizedText': tokenized_text,
        }
        if hash_tokenized_text:
            text_result['hashedTokenizedText'] = hash_tokenized_text

        result.append(text_result)
    if len(result) == 1:
        result = result[0]  # type: ignore
    return {
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('Tokenized Text', result, headers=['tokenizedText']),
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': {
            'WordTokenizeNLPOutput': result
        }
    }


demisto.results(word_tokenize(demisto.args()['value']))
