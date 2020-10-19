from CommonServerPython import *
from CommonServerUserPython import *
import spacy
import string
from html.parser import HTMLParser
from html import unescape
from re import compile as _Re
import pandas as pd


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
    def __init__(self, clean_html=True, remove_new_lines=True, hash_seed=None, remove_non_english=True,
                 remove_stop_words=True, remove_punct=True, remove_non_alpha=True, replace_emails=True,
                 replace_numbers=True, lemma=True, replace_urls=True,
                 is_json=True, language='English', tokenization_method='byWords'):
        self.number_pattern = "NUMBER_PATTERN"
        self.url_pattern = "URL_PATTERN"
        self.email_pattern = "EMAIL_PATTERN"
        self.reserved_tokens = set([self.number_pattern, self.url_pattern, self.email_pattern])
        self.clean_html = clean_html
        self.remove_new_lines = remove_new_lines
        self.hash_seed = hash_seed
        self.remove_non_english = remove_non_english
        self.remove_stop_words = remove_stop_words
        self.remove_punct = remove_punct
        self.remove_non_alpha = remove_non_alpha
        self.replace_emails = replace_emails
        self.replace_urls = replace_urls
        self.replace_numbers = replace_numbers
        self.lemma = lemma
        self.is_json = is_json
        self.language = language
        self.tokenization_method = tokenization_method
        self.max_text_length = 10 ** 5
        self.html_patterns = [
            re.compile(r"(?is)<(script|style).*?>.*?(</\1>)"),
            re.compile(r"(?s)<!--(.*?)-->[\n]?"),
            re.compile(r"(?s)<.*?>"),
            re.compile(r"&nbsp;"),
            re.compile(r" +")
        ]
        self.nlp = None
        self.html_parser = HTMLParser()
        self._unicode_chr_splitter = _Re('(?s)((?:[\ud800-\udbff][\udc00-\udfff])|.)').split
        self.languages_to_model_names = {'English': 'en_core_web_sm',
                                         'German': 'de_core_news_sm',
                                         'French': 'fr_core_news_sm',
                                         'Spanish': 'es_core_news_sm',
                                         'Portuguese': 'pt_core_news_sm',
                                         'Italian': 'it_core_news_sm',
                                         'Dutch': 'nl_core_news_sm'
                                         }
        self.spacy_count = 0
        self.spacy_reset_count = 500

    def clean_html_from_text(self, text):
        cleaned = text
        for pattern in self.html_patterns:
            cleaned = pattern.sub(" ", cleaned)
        return unescape(cleaned).strip()

    def tokenize_text(self, text):
        language = self.language
        if language in self.languages_to_model_names:
            original_words_to_tokens, tokens_list = self.tokenize_text_spacy(text)
        else:
            original_words_to_tokens, tokens_list = self.tokenize_text_other(text)
        hashed_tokens_list = []
        if self.hash_seed is not None:
            seed = self.hash_seed
            for word in tokens_list:
                word_hashed = hash_word(word, seed)
                hashed_tokens_list.append(word_hashed)
            hashed_words_to_tokens = {word: [hash_word(t, seed) for t in tokens_list] for word, tokens_list in
                                      original_words_to_tokens.items()}
        else:
            hashed_words_to_tokens = {}
        return ' '.join(tokens_list).strip(), ' '.join(hashed_tokens_list) if len(
            hashed_tokens_list) > 0 else None, original_words_to_tokens, hashed_words_to_tokens

    def tokenize_text_other(self, text):
        tokens_list = []
        tokenization_method = self.tokenization_method
        if tokenization_method == 'byWords':
            original_words_to_tokens = {}
            for t in text.split():
                token_without_punct = ''.join([c for c in t if c not in string.punctuation])
                if len(token_without_punct) > 0:
                    tokens_list.append(token_without_punct)
                    original_words_to_tokens[token_without_punct] = t
        elif tokenization_method == 'byLetters':
            for t in text:
                tokens_list += [chr for chr in self._unicode_chr_splitter(t) if chr and chr != ' ']
                original_words_to_tokens = {c: t for c in tokens_list}
        else:
            return_error('Unsupported tokenization method: when language is "Other" ({})'.format(tokenization_method))
        return original_words_to_tokens, tokens_list

    def tokenize_text_spacy(self, text):
        if self.nlp is None or self.spacy_count % self.spacy_reset_count == 0:
            self.init_spacy_model(self.language)
        doc = self.nlp(text)  # type: ignore
        self.spacy_count += 1
        original_text_indices_to_words = map_indices_to_words(text)
        tokens_list = []
        original_words_to_tokens = {}  # type: ignore
        for word in doc:
            if word.is_space:
                continue
            elif self.remove_stop_words and word.is_stop:
                continue
            elif self.remove_punct and word.is_punct:
                continue
            elif self.replace_emails and '@' in word.text:
                tokens_list.append(self.email_pattern)
            elif self.replace_urls and word.like_url:
                tokens_list.append(self.url_pattern)
            elif self.replace_numbers and (word.like_num or word.pos_ == 'NUM'):
                tokens_list.append(self.number_pattern)
            elif self.remove_non_alpha and not word.is_alpha:
                continue
            elif self.remove_non_english and word.text not in self.nlp.vocab:  # type: ignore
                continue
            else:
                if self.lemma and word.lemma_ != '-PRON-':
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
        self.nlp = spacy.load(self.languages_to_model_names[language], disable=['tagger', 'parser', 'ner', 'textcat'])

    def word_tokenize(self, text):
        if self.is_json:
            try:
                text = json.loads(text)
            except Exception:
                pass
        if not isinstance(text, list):
            text = [text]

        result = []
        for t in text:
            original_text = t
            if self.remove_new_lines:
                t = remove_line_breaks(t)
            if self.clean_html:
                t = self.clean_html_from_text(t)
            t = remove_multiple_whitespaces(t)
            if len(t) < self.max_text_length:
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


class FileReader:
    @staticmethod
    def read_file(input_data, input_type):
        data = []  # type: ignore
        if not input_data:
            return data
        if input_type.endswith("string"):
            if 'b64' in input_type:
                input_data = base64.b64decode(input_data)
                file_content = input_data.decode("utf-8")
            else:
                file_content = input_data
        else:
            res = demisto.getFilePath(input_data)
            if not res:
                return_error("Entry {} not found".format(input_data))
            file_path = res['path']
            if input_type.startswith('json'):
                with open(file_path, 'r') as f:
                    file_content = f.read()
        if input_type.startswith('csv'):
            return pd.read_csv(file_path).fillna('').to_dict(orient='records')
        elif input_type.startswith('json'):
            return json.loads(file_content)
        elif input_type.startswith('pickle'):
            return pd.read_pickle(file_path, compression=None)
        else:
            return_error("Unsupported file type %s" % input_type)
