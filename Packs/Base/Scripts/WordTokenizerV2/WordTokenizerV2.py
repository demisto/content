import spacy
import string
from HTMLParser import HTMLParser
from re import compile as _Re

from CommonServerPython import *
import sys
reload(sys)
sys.setdefaultencoding('utf-8')  # pylint: disable=no-member

MAX_TEXT_LENGTH = 10 ** 5

NUMBER_PATTERN = "NUMBER_PATTERN"
URL_PATTERN = "URL_PATTERN"
EMAIL_PATTERN = "EMAIL_PATTERN"
reserved_tokens = set([NUMBER_PATTERN, URL_PATTERN, EMAIL_PATTERN])

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
LANGUAGES_TO_MODEL_NAMES = {'English': 'en_core_web_sm',
                            'German': 'de_core_news_sm',
                            'French': 'fr_core_news_sm',
                            'Spanish': 'es_core_news_sm',
                            'Portuguese': 'pt_core_news_sm',
                            'Italian': 'it_core_news_sm',
                            'Dutch': 'nl_core_news_sm'
                            }

_unicode_chr_splitter = _Re('(?s)((?:[\ud800-\udbff][\udc00-\udfff])|.)').split
nlp = None


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
    return text.replace("\r", " ").replace("\n", " ")


def remove_multiple_whitespaces(text):
    return re.sub(r"\s+", " ", text).strip()


def hash_word(word):
    return str(hash_djb2(word, int(HASH_SEED)))


def tokenize_text(text):
    try:
        unicode_text = unicode(text)
    except Exception:
        unicode_text = text
    language = demisto.args()['language']
    if language in LANGUAGES_TO_MODEL_NAMES:
        original_words_to_tokens, tokens_list = tokenize_text_spacy(unicode_text, language)
    else:
        original_words_to_tokens, tokens_list = tokenize_text_other(unicode_text)
    hashed_tokens_list = []
    if HASH_SEED:
        for word in tokens_list:
            word_hashed = hash_word(word)
            hashed_tokens_list.append(word_hashed)
        hashed_words_to_tokens = {word: [hash_word(t) for t in tokens_list] for word, tokens_list in
                                  original_words_to_tokens.items()}
    else:
        hashed_words_to_tokens = {}
    return ' '.join(tokens_list).strip(), ' '.join(hashed_tokens_list) if len(
        hashed_tokens_list) > 0 else None, original_words_to_tokens, hashed_words_to_tokens


def tokenize_text_other(unicode_text):
    tokens_list = []
    tokenization_method = demisto.args()['tokenizationMethod']
    if tokenization_method == 'byWords':
        original_words_to_tokens = {}
        for t in unicode_text.split():
            token_without_punct = ''.join([c for c in t if c not in string.punctuation])
            if len(token_without_punct) > 0:
                tokens_list.append(token_without_punct)
                original_words_to_tokens[token_without_punct] = t
    elif tokenization_method == 'byLetters':
        for t in unicode_text:
            tokens_list += [chr for chr in _unicode_chr_splitter(t) if chr]
            original_words_to_tokens = {c: t for c in tokens_list}
    else:
        return_error('Unsupported tokenization method: when language is "Other" ({})'.format(tokenization_method))
    return original_words_to_tokens, tokens_list


def tokenize_text_spacy(unicode_text, language):
    global nlp
    if nlp is None:
        nlp = spacy.load(LANGUAGES_TO_MODEL_NAMES[language], disable=['tagger', 'parser', 'ner', 'textcat'])
    doc = nlp(unicode(unicode_text))
    original_text_indices_to_words = map_indices_to_words(unicode_text)
    tokens_list = []
    original_words_to_tokens = {}  # type: ignore
    for word in doc:
        if word.is_space:
            continue
        elif REMOVE_STOP_WORDS and word.is_stop:
            continue
        elif REMOVE_PUNCT and word.is_punct:
            continue
        elif REPLACE_EMAIL and '@' in word.text:
            tokens_list.append(EMAIL_PATTERN)
        elif REPLACE_URLS and word.like_url:
            tokens_list.append(URL_PATTERN)
        elif REPLACE_NUMBERS and (word.like_num or word.pos_ == 'NUM'):
            tokens_list.append(NUMBER_PATTERN)
        elif REMOVE_NON_ALPHA and not word.is_alpha:
            continue
        elif FILTER_ENGLISH_WORDS and word.text not in nlp.vocab:
            continue
        else:
            if LEMMATIZER and word.lemma_ != '-PRON-':
                token_to_add = word.lemma_
            else:
                token_to_add = word.lower_
            tokens_list.append(token_to_add)
            original_word = original_text_indices_to_words[word.idx]
            if original_word not in original_words_to_tokens:
                original_words_to_tokens[original_word] = []
            original_words_to_tokens[original_word].append(token_to_add)
    return original_words_to_tokens, tokens_list


def map_indices_to_words(unicode_text):
    original_text_indices_to_words = {}
    word_start = 0
    while word_start < len(unicode_text) and unicode_text[word_start].isspace():
        word_start += 1
    for word in unicode_text.split():
        for char_idx, char in enumerate(word):
            original_text_indices_to_words[word_start + char_idx] = word
        # find beginning of next word
        word_start += len(word)
        while word_start < len(unicode_text) and unicode_text[word_start].isspace():
            word_start += 1
    return original_text_indices_to_words


def handle_long_text(t, input_length):
    if input_length == 1:
        return_error("Input text length ({}) exceeds the legal maximum length for preprocessing".format(len(t)))
    else:
        return '', '', {}, {}


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
        t = remove_multiple_whitespaces(t)
        if len(t) < MAX_TEXT_LENGTH:
            tokenized_text, hash_tokenized_text, original_words_to_tokens, words_to_hashed_tokens = tokenize_text(t)
        else:
            tokenized_text, hash_tokenized_text, original_words_to_tokens, words_to_hashed_tokens =\
                handle_long_text(t, input_length=len(text))
        text_result = {
            'originalText': original_text,
            'tokenizedText': tokenized_text,
            'originalWordsToTokens': original_words_to_tokens,
        }
        if hash_tokenized_text:
            text_result['hashedTokenizedText'] = hash_tokenized_text
            text_result['wordsToHashedTokens'] = words_to_hashed_tokens
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


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(word_tokenize(demisto.args()['value']))
