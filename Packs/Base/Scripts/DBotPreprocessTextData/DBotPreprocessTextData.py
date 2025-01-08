# pylint: disable=no-member
from collections import Counter
from CommonServerUserPython import *
from CommonServerPython import *
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle
import uuid
import spacy
import string
from html.parser import HTMLParser
from html import unescape
from re import compile as _Re
import pandas as pd
from langdetect import detect
from langdetect.lang_detect_exception import LangDetectException

ANY_LANGUAGE = 'Any'
OTHER_LANGUAGE = 'Other'


def hash_word(word, hash_seed):
    return str(hash_djb2(word, int(hash_seed)))


CODES_TO_LANGUAGES = {'en': 'English',
                      'de': 'German',
                      'fr': 'French',
                      'es': 'Spanish',
                      'pt': 'Portuguese',
                      'it': 'Italian',
                      'nl': 'Dutch',
                      }

html_patterns = [
    re.compile(r"(?is)<(script|style).*?>.*?(</\1>)"),
    re.compile(r"(?s)<!--(.*?)-->[\n]?"),
    re.compile(r"(?s)<.*?>"),
    re.compile(r"&nbsp;"),
    re.compile(r" +")
]

LANGUAGE_KEY = 'language'


def create_text_result(original_text, tokenized_text, original_words_to_tokens, hash_seed=None):
    text_result = {
        'originalText': original_text,
        'tokenizedText': tokenized_text,
        'originalWordsToTokens': original_words_to_tokens,
    }
    if hash_seed is not None:
        hash_tokenized_text = ' '.join(hash_word(word, hash_seed) for word in tokenized_text.split())
        words_to_hashed_tokens = {word: [hash_word(t, hash_seed) for t in tokens_list] for word, tokens_list in
                                  original_words_to_tokens.items()}

        text_result['hashedTokenizedText'] = hash_tokenized_text
        text_result['wordsToHashedTokens'] = words_to_hashed_tokens
    return text_result


def clean_html_from_text(text):
    cleaned = text
    for pattern in html_patterns:
        cleaned = pattern.sub(" ", cleaned)
    return unescape(cleaned).strip()


class Tokenizer:
    def __init__(self, clean_html=True, remove_new_lines=True, hash_seed=None, remove_non_english=True,
                 remove_stop_words=True, remove_punct=True, remove_non_alpha=True, replace_emails=True,
                 replace_numbers=True, lemma=True, replace_urls=True, language=ANY_LANGUAGE,
                 tokenization_method='tokenizer'):
        self.number_pattern = "NUMBER_PATTERN"
        self.url_pattern = "URL_PATTERN"
        self.email_pattern = "EMAIL_PATTERN"
        self.reserved_tokens = {self.number_pattern, self.url_pattern, self.email_pattern}
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
        self.language = language
        self.tokenization_method = tokenization_method
        self.max_text_length = 10 ** 5

        self.nlp = None
        self.html_parser = HTMLParser()
        self._unicode_chr_splitter = _Re('(?s)((?:[\ud800-\udbff][\udc00-\udfff])|.)').split
        self.spacy_count = 0
        self.spacy_reset_count = 500

    def handle_long_text(self):
        return '', ''

    def map_indices_to_words(self, text):
        original_text_indices_to_words = {}
        word_start = 0
        while word_start < len(text) and text[word_start].isspace():
            word_start += 1
        for word in text.split():
            for char_idx, _char in enumerate(word):
                original_text_indices_to_words[word_start + char_idx] = word
            # find beginning of next word
            word_start += len(word)
            while word_start < len(text) and text[word_start].isspace():
                word_start += 1
        return original_text_indices_to_words

    def remove_line_breaks(self, text):
        return text.replace("\r", " ").replace("\n", " ")

    def remove_multiple_whitespaces(self, text):
        return re.sub(r"\s+", " ", text).strip()

    def handle_tokenizaion_method(self, text):
        if self.tokenization_method == 'tokenizer':
            tokens_list, original_words_to_tokens = self.tokenize_text_spacy(text)
        else:
            tokens_list, original_words_to_tokens = self.tokenize_text_other(text)
        tokenized_text = ' '.join(tokens_list).strip()
        return tokenized_text, original_words_to_tokens

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
            return_error(f'Unsupported tokenization method: when language is "Other" ({tokenization_method})')
        return tokens_list, original_words_to_tokens

    def tokenize_text_spacy(self, text):
        if self.nlp is None or self.spacy_count % self.spacy_reset_count == 0:
            self.init_spacy_model()
        doc = self.nlp(text)  # type: ignore
        self.spacy_count += 1
        original_text_indices_to_words = self.map_indices_to_words(text)
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
        return tokens_list, original_words_to_tokens

    def init_spacy_model(self):
        self.nlp = spacy.load('en_core_web_sm', disable=['parser', 'ner', 'textcat'])

    def word_tokenize(self, text):
        if not isinstance(text, list):
            text = [text]
        result = []
        for t in text:
            original_text = t
            if self.remove_new_lines:
                t = self.remove_line_breaks(t)
            if self.clean_html:
                t = clean_html_from_text(t)
                original_text = t
            t = self.remove_multiple_whitespaces(t)
            if len(t) < self.max_text_length:
                tokenized_text, original_words_to_tokens = self.handle_tokenizaion_method(t)
            else:
                tokenized_text, original_words_to_tokens = self.handle_long_text()
            text_result = create_text_result(original_text, tokenized_text, original_words_to_tokens,
                                             hash_seed=self.hash_seed)
            result.append(text_result)
        if len(result) == 1:
            result = result[0]  # type: ignore
        return result


# define global parsers
DBOT_TEXT_FIELD = 'dbot_text'
DBOT_PROCESSED_TEXT_FIELD = 'dbot_processed_text'
CONTEXT_KEY = 'DBotPreProcessTextData'
HTML_PATTERNS = [
    re.compile(r"(?is)<(script|style).*?>.*?(</\1>)"),
    re.compile(r"(?s)<!--(.*?)-->[\n]?"),
    re.compile(r"(?s)<.*?>"),
    re.compile(r"&nbsp;"),
    re.compile(r" +")
]
html_parser = HTMLParser()
tokenizer = None


def read_file(input_data, input_type):
    data = []  # type: ignore
    file_path, file_content = '', ''
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
            return_error(f"Entry {input_data} not found")
        file_path = res['path']
        if input_type.startswith('json'):
            with open(file_path) as f:
                file_content = f.read()
    if input_type.startswith('csv'):
        return pd.read_csv(file_path).fillna('').to_dict(orient='records')
    elif input_type.startswith('json'):
        return json.loads(file_content)
    elif input_type.startswith('pickle'):
        return pd.read_pickle(file_path, compression=None)
    else:
        return_error("Unsupported file type %s" % input_type)
        return None


def concat_text_fields(data, target_field, text_fields):
    for d in data:
        text = ''
        for fields in text_fields:
            for field in fields.strip().split("|"):
                field = field.strip()
                if "." in field:
                    value = demisto.dt(d, field)
                    if type(value) is list and len(value) > 0:
                        value = value[0]
                else:
                    value = d.get(field) or d.get(field.lower(), '')
                if value and isinstance(value, str):
                    text += value
                    text += ' '
                    break
        text = text.strip()
        d[target_field] = text
    return data


def remove_line_breaks(text):
    return re.sub(r"\s+", " ", text.replace("\r", " ").replace("\n", " ")).strip()


def clean_text_of_single_text(text, remove_html_tags):
    if remove_html_tags:
        text = clean_html_from_text(text)
    return remove_line_breaks(text)


def clean_text_of_incidents_list(data, source_text_field, remove_html_tags):
    for inc in data:
        inc[source_text_field] = clean_text_of_single_text(inc[source_text_field], remove_html_tags)
    return data


def pre_process_batch(data, source_text_field, target_text_field, pre_process_type, hash_seed):
    raw_text_data = [x[source_text_field] for x in data]
    tokenized_text_data = []
    for raw_text in raw_text_data:
        tokenized_text = pre_process_single_text(raw_text, hash_seed, pre_process_type)
        if hash_seed is None:
            tokenized_text_data.append(tokenized_text['tokenizedText'])
        else:
            tokenized_text_data.append(tokenized_text['hashedTokenizedText'])
    for d, tokenized_text in zip(data, tokenized_text_data):
        d[target_text_field] = tokenized_text
    return data


def pre_process_single_text(raw_text, hash_seed, pre_process_type):
    pre_process_func = PRE_PROCESS_TYPES[pre_process_type]
    tokenized_text = pre_process_func(raw_text, hash_seed)
    return tokenized_text


def pre_process_tokenizer(text, seed):
    global tokenizer
    if tokenizer is None:
        tokenizer = Tokenizer(tokenization_method=demisto.args()['tokenizationMethod'],
                              language=demisto.args()['language'], hash_seed=seed)
    processed_text = tokenizer.word_tokenize(text)
    return processed_text


def pre_process_none(text, seed):
    cleaned_text = clean_html_from_text(text)
    tokenized_text = text
    original_words_to_tokens = {x: x for x in cleaned_text.split()}
    return create_text_result(original_text=cleaned_text,
                              tokenized_text=tokenized_text,
                              original_words_to_tokens=original_words_to_tokens,
                              hash_seed=seed)


PRE_PROCESS_TYPES = {
    'none': pre_process_none,
    'nlp': pre_process_tokenizer,
}


def remove_short_text(data, text_field, target_text_field, remove_short_threshold):
    description = ""
    before_count = len(data)
    data = [x for x in data if len(x[text_field].split(" ")) > remove_short_threshold
            and len(x[target_text_field]) > remove_short_threshold]
    after_count = len(data)
    dropped_count = before_count - after_count
    if dropped_count > 0:
        description += "Dropped %d samples shorter than %d words" % (dropped_count, remove_short_threshold) + "\n"
    return data, description


def remove_foreign_language(data, text_field, language):
    description = ""
    for inc in data:
        is_correct_lang, actual_language = is_text_in_input_language(inc[text_field], language)
        inc['is_correct_lang'] = is_correct_lang
        inc[LANGUAGE_KEY] = actual_language
    filtered_data = [inc for inc in data if inc['is_correct_lang']]
    dropped_count = len(data) - len(filtered_data)
    if dropped_count > 0:
        lang_counter = Counter(inc[LANGUAGE_KEY] for inc in data).most_common()
        description += "Dropped %d sample(s) that were detected as being in foreign languages. " % dropped_count
        description += 'Found language counts: {}'.format(', '.join([f'{lang}:{count}' for lang, count
                                                                     in lang_counter]))
        description += "\n"
    return filtered_data, description


def is_text_in_input_language(text, input_language):
    if input_language in [ANY_LANGUAGE, OTHER_LANGUAGE]:
        return True, 'UNK'
    if '<html' in text:
        text = clean_html_from_text(text)
    try:
        actual_language = detect(text)
    except LangDetectException:
        return True, 'UNK'
    is_correct_lang = actual_language in CODES_TO_LANGUAGES and CODES_TO_LANGUAGES[actual_language] == input_language
    return is_correct_lang, actual_language


def get_tf_idf_similarity_arr(documents):
    tfidf = TfidfVectorizer(stop_words="english", min_df=1).fit_transform(documents)
    pairwise_similarity = tfidf * tfidf.T
    return pairwise_similarity.toarray()


def find_duplicate_indices(texts, dedup_threshold):
    similarity_arr = get_tf_idf_similarity_arr(texts)
    indices_to_remove = []
    for i in range(similarity_arr.shape[0]):
        for j in range(similarity_arr.shape[1]):
            if j > i and similarity_arr[i][j] > dedup_threshold:
                indices_to_remove.append(j)
    return set(indices_to_remove)


def remove_duplicate_by_indices(data, duplicate_indices):
    description = ""
    data = [x for i, x in enumerate(data) if i not in duplicate_indices]
    dropped_count = len(duplicate_indices)
    if dropped_count > 0:
        description += "Dropped %d samples duplicate to other samples" % dropped_count + "\n"
    return data, description


def whitelist_dict_fields(data, fields):
    fields = [x.strip() for x in fields] + [x.strip().lower() for x in fields]
    new_data = []
    for d in data:
        new_data.append({k: v for k, v in d.items() if k in fields})
    return new_data


def main():
    text_fields = demisto.args()['textFields'].split(",")
    input = demisto.args().get('input')
    input_type = demisto.args()['inputType']
    hash_seed = int(demisto.args().get('hashSeed')) if demisto.args().get('hashSeed') else None
    remove_short_threshold = int(demisto.args().get('removeShortTextThreshold', 1))
    de_dup_threshold = float(demisto.args()['dedupThreshold'])
    pre_process_type = demisto.args()['preProcessType']
    remove_html_tags = demisto.args()['cleanHTML'] == 'true'
    whitelist_fields = demisto.args().get('whitelistFields').split(",") if demisto.args().get(
        'whitelistFields') else None
    language = demisto.args().get('language', ANY_LANGUAGE)
    # if input is a snigle string (from DbotPredictPhishingWords):
    if input_type == 'string':
        input_str = demisto.args().get('input')
        input_str = clean_text_of_single_text(input_str, remove_html_tags)
        is_correct_lang, actual_language = is_text_in_input_language(input_str, language)
        if not is_correct_lang:
            return_error("Input text was detected as as being in a different language from {} ('{}' found)."
                         .format(language, actual_language))
        res = pre_process_single_text(raw_text=input_str,
                                      hash_seed=hash_seed, pre_process_type=pre_process_type)
        return res
    output_original_text_fields = demisto.args().get('outputOriginalTextFields', 'false') == 'true'
    description = ""
    # read data
    data = read_file(input, input_type)
    # concat text fields
    concat_text_fields(data, DBOT_TEXT_FIELD, text_fields)
    description += "Read initial %d samples" % len(data) + "\n"

    # clean text
    if pre_process_type not in PRE_PROCESS_TYPES:
        return_error(f'Pre-process type {pre_process_type} is not supported')

    # clean html and new lines
    data = clean_text_of_incidents_list(data, DBOT_TEXT_FIELD, remove_html_tags)
    # filter incidents not in specified languages
    data, desc = remove_foreign_language(data, DBOT_TEXT_FIELD, language)
    description += desc

    # apply tokenizer
    data = pre_process_batch(data, DBOT_TEXT_FIELD, DBOT_PROCESSED_TEXT_FIELD, pre_process_type,
                             hash_seed)

    # remove short emails
    data, desc = remove_short_text(data, DBOT_TEXT_FIELD, DBOT_PROCESSED_TEXT_FIELD, remove_short_threshold)
    description += desc

    # remove duplicates
    try:
        if 0 < de_dup_threshold < 1:
            duplicate_indices = find_duplicate_indices([x[DBOT_PROCESSED_TEXT_FIELD] for x in data], de_dup_threshold)
            data, desc = remove_duplicate_by_indices(data, duplicate_indices)
            description += desc
    except Exception:
        pass

    if output_original_text_fields:
        for field in text_fields:
            whitelist_fields += [x.strip() for x in field.split('|')]  # type: ignore[operator]
    if whitelist_fields and len(whitelist_fields) > 0:
        whitelist_fields.append(DBOT_PROCESSED_TEXT_FIELD)
        data = whitelist_dict_fields(data, whitelist_fields)

    description += "Done processing: %d samples" % len(data) + "\n"
    # output
    file_name = str(uuid.uuid4())
    output_format = demisto.args()['outputFormat']
    data_encoded = None
    if output_format == 'pickle':
        data_encoded = pickle.dumps(data, protocol=2)
    elif output_format == 'json':
        data_encoded = json.dumps(data, default=str)  # type: ignore
    else:
        return_error("Invalid output format: %s" % output_format)
    entry = fileResult(file_name, data_encoded)
    entry['Contents'] = data
    entry['HumanReadable'] = description
    entry['EntryContext'] = {
        CONTEXT_KEY: {
            'Filename': file_name,
            'FileFormat': output_format,
            'TextField': DBOT_TEXT_FIELD,
            'TextFieldProcessed': DBOT_PROCESSED_TEXT_FIELD,
        }
    }
    return entry


if __name__ in ['builtins', '__main__']:
    entry = main()
    demisto.results(entry)
