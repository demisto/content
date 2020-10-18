import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import spacy
import string
from html.parser import HTMLParser
from html import unescape
from re import compile as _Re


def handle_long_text(t, input_length):
    if input_length == 1:
        return_error("Input text length ({}) exceeds the legal maximum length for preprocessing".format(len(t)))
    else:
        return '', '', {}, {}


def map_indices_to_words(text):
    original_text_indices_to_words = {}
    word_start = 0
    while word_start < len(text) and text[word_start].isspace():
        word_start += 1
    for word in text.split():
        for char_idx, char in enumerate(word):
            original_text_indices_to_words[word_start + char_idx] = word
        # find beginning of next word
        word_start += len(word)
        while word_start < len(text) and text[word_start].isspace():
            word_start += 1
    return original_text_indices_to_words


def remove_line_breaks(text):
    return text.replace("\r", " ").replace("\n", " ")


def remove_multiple_whitespaces(text):
    return re.sub(r"\s+", " ", text).strip()


def hash_word(word, hash_seed):
    return str(hash_djb2(word, int(hash_seed)))


class Tokenizer:
    def __init__(self, clean_html=True, removeLineBreaks=True, hashWordWithSeed=None, removeNonEnglishWords=True,
                 removeStopWords=True, removePunctuation=True, removeNonAlphaWords=True, replaceEmails=True,
                 replaceNumbers=True, useLemmatization=True, replaceUrls=True,
                 isValueJson=True, language='English', tokenizationMethod='byWords'):
        self.NUMBER_PATTERN = "NUMBER_PATTERN"
        self.URL_PATTERN = "URL_PATTERN"
        self.EMAIL_PATTERN = "EMAIL_PATTERN"
        self.reserved_tokens = set([self.NUMBER_PATTERN, self.URL_PATTERN, self.EMAIL_PATTERN])
        self.cleanHtml = clean_html
        self.removeLineBreaks = removeLineBreaks
        self.hashWordWithSeed = hashWordWithSeed
        self.removeNonEnglishWords = removeNonEnglishWords
        self.removeStopWords = removeStopWords
        self.removePunctuation = removePunctuation
        self.removeNonAlphaWords = removeNonAlphaWords
        self.replaceEmails = replaceEmails
        self.replaceUrls = replaceUrls
        self.replaceNumbers = replaceNumbers
        self.useLemmatization = useLemmatization
        self.isValueJson = isValueJson
        self.language = language
        self.tokenizationMethod = tokenizationMethod
        self.MAX_TEXT_LENGTH = 10 ** 5
        self.HTML_PATTERNS = [
            re.compile(r"(?is)<(script|style).*?>.*?(</\1>)"),
            re.compile(r"(?s)<!--(.*?)-->[\n]?"),
            re.compile(r"(?s)<.*?>"),
            re.compile(r"&nbsp;"),
            re.compile(r" +")
        ]
        self.nlp = None
        self.html_parser = HTMLParser()
        self._unicode_chr_splitter = _Re('(?s)((?:[\ud800-\udbff][\udc00-\udfff])|.)').split
        self.LANGUAGES_TO_MODEL_NAMES = {'English': 'en_core_web_sm',
                                         'German': 'de_core_news_sm',
                                         'French': 'fr_core_news_sm',
                                         'Spanish': 'es_core_news_sm',
                                         'Portuguese': 'pt_core_news_sm',
                                         'Italian': 'it_core_news_sm',
                                         'Dutch': 'nl_core_news_sm'
                                         }
        self.spacy_count = 0
        self.spacy_reset_count = 500

    def clean_html(self, text):
        cleaned = text
        for pattern in self.HTML_PATTERNS:
            cleaned = pattern.sub(" ", cleaned)
        return unescape(cleaned).strip()

    def tokenize_text(self, text):
        language = self.language
        if language in self.LANGUAGES_TO_MODEL_NAMES:
            original_words_to_tokens, tokens_list = self.tokenize_text_spacy(text)
        else:
            original_words_to_tokens, tokens_list = self.tokenize_text_other(text)
        hashed_tokens_list = []
        if self.hashWordWithSeed is not None:
            seed = self.hashWordWithSeed
            for word in tokens_list:
                word_hashed = hash_word(word)
                hashed_tokens_list.append(word_hashed)
            hashed_words_to_tokens = {word: [hash_word(t, seed) for t in tokens_list] for word, tokens_list in
                                      original_words_to_tokens.items()}
        else:
            hashed_words_to_tokens = {}
        return ' '.join(tokens_list).strip(), ' '.join(hashed_tokens_list) if len(
            hashed_tokens_list) > 0 else None, original_words_to_tokens, hashed_words_to_tokens

    def tokenize_text_other(self, text):
        tokens_list = []
        tokenization_method = self.tokenizationMethod
        if tokenization_method == 'byWords':
            original_words_to_tokens = {}
            for t in text.split():
                token_without_punct = ''.join([c for c in t if c not in string.punctuation])
                if len(token_without_punct) > 0:
                    tokens_list.append(token_without_punct)
                    original_words_to_tokens[token_without_punct] = t
        elif tokenization_method == 'byLetters':
            for t in text:
                tokens_list += [chr for chr in self._unicode_chr_splitter(t) if chr]
                original_words_to_tokens = {c: t for c in tokens_list}
        else:
            return_error('Unsupported tokenization method: when language is "Other" ({})'.format(tokenization_method))
        return original_words_to_tokens, tokens_list

    def tokenize_text_spacy(self, text):
        if self.nlp is None or self.spacy_count % self.spacy_reset_count == 0:
            self.init_spacy_model(self.language)
        doc = self.nlp(text)
        self.spacy_count += 1
        original_text_indices_to_words = map_indices_to_words(text)
        tokens_list = []
        original_words_to_tokens = {}  # type: ignore
        for word in doc:
            if word.is_space:
                continue
            elif self.removeStopWords and word.is_stop:
                continue
            elif self.removePunctuation and word.is_punct:
                continue
            elif self.replaceEmails and '@' in word.text:
                tokens_list.append(self.EMAIL_PATTERN)
            elif self.replaceUrls and word.like_url:
                tokens_list.append(self.URL_PATTERN)
            elif self.replaceNumbers and (word.like_num or word.pos_ == 'NUM'):
                tokens_list.append(self.NUMBER_PATTERN)
            elif self.removeNonAlphaWords and not word.is_alpha:
                continue
            elif self.removeNonEnglishWords and word.text not in self.nlp.vocab:
                continue
            else:
                if self.useLemmatization and word.lemma_ != '-PRON-':
                    token_to_add = word.lemma_
                else:
                    token_to_add = word.lower_
                tokens_list.append(token_to_add)
                original_word = original_text_indices_to_words[word.idx]
                if original_word not in original_words_to_tokens:
                    original_words_to_tokens[original_word] = []
                original_words_to_tokens[original_word].append(token_to_add)
        return original_words_to_tokens, tokens_list

    def init_spacy_model(self, language):
        self.nlp = spacy.load(self.LANGUAGES_TO_MODEL_NAMES[language], disable=['tagger', 'parser', 'ner', 'textcat'])

    def word_tokenize(self, text):
        if self.isValueJson:
            try:
                text = json.loads(text)
            except Exception:
                pass
        if not isinstance(text, list):
            text = [text]

        result = []
        for t in text:
            original_text = t
            if self.removeLineBreaks:
                t = remove_line_breaks(t)
            if self.cleanHtml:
                t = self.clean_html(t)
            t = remove_multiple_whitespaces(t)
            if len(t) < self.MAX_TEXT_LENGTH:
                tokenized_text, hash_tokenized_text, original_words_to_tokens, words_to_hashed_tokens = \
                    self.tokenize_text(t)
            else:
                tokenized_text, hash_tokenized_text, original_words_to_tokens, words_to_hashed_tokens = \
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
        return result
