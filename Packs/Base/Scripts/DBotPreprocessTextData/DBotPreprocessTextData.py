# pylint: disable=no-member
from sklearn.feature_extraction.text import TfidfVectorizer

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import pickle
import uuid
from html.parser import HTMLParser
from html import unescape
import pandas as pd
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
# define global parsers
html_parser = HTMLParser()


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


def clean_html(text):
    cleaned = text
    for pattern in HTML_PATTERNS:
        cleaned = pattern.sub(" ", cleaned)
    return unescape(cleaned).strip()


def remove_line_breaks(text):
    return re.sub(r"\s+", " ", text.replace("\r", " ").replace("\n", " ")).strip()


def hash_word(word, seed):
    return str(hash_djb2(word, seed))


def pre_process(data, source_text_field, target_text_field, remove_html_tags, pre_process_type, hash_seed):
    tokenized_text_data = [x[source_text_field] for x in data]
    if remove_html_tags:
        tokenized_text_data = [clean_html(x) for x in tokenized_text_data]
    tokenized_text_data = [remove_line_breaks(x) for x in tokenized_text_data]
    pre_process_func = PRE_PROCESS_TYPES[pre_process_type]
    tokenized_text_data = pre_process_func(tokenized_text_data)
    for d, tokenized_text_data in zip(data, tokenized_text_data):
        if hash_seed:
            tokenized_text_data = " ".join([hash_word(word, hash_seed) for word in tokenized_text_data.split(" ")])
        d[target_text_field] = tokenized_text_data
    return data


def pre_process_nlp(text_data):
    res = demisto.executeCommand('WordTokenizerNLP', {
        'value': json.dumps(text_data),
        'isValueJson': 'yes',
        'tokenizationMethod': demisto.args()['tokenizationMethod'],
        'language': demisto.args()['language']
    })

    if is_error(res):
        return_error(get_error(res))
    processed_text_data = res[0]['Contents']
    if not isinstance(processed_text_data, list):
        processed_text_data = [processed_text_data]
    tokenized_text_data = map(lambda x: x.get('tokenizedText'), processed_text_data)
    return tokenized_text_data


PRE_PROCESS_TYPES = {
    'none': lambda x: x,
    'nlp': pre_process_nlp,
}


def remove_short_text(data, text_field, target_text_field, remove_short_threshold):
    description = ""
    before_count = len(data)
    data = [x for x in data if len(x[text_field].split(" ")) > remove_short_threshold and len(x[target_text_field]) > 0]
    after_count = len(data)
    dropped_count = before_count - after_count
    if dropped_count > 0:
        description += "Dropped %d samples shorter than %d words" % (dropped_count, remove_short_threshold) + "\n"
    return data, description


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
    output_original_text_fields = demisto.args().get('outputOriginalTextFields', 'false') == 'true'
    description = ""
    # read data
    data = read_file(input, input_type)

    # concat text fields
    concat_text_fields(data, DBOT_TEXT_FIELD, text_fields)
    description += "Read initial %d samples" % len(data) + "\n"

    # clean text
    if pre_process_type not in PRE_PROCESS_TYPES:
        return_error('Pre-process type {} is not supported'.format(pre_process_type))
    data = pre_process(data, DBOT_TEXT_FIELD, DBOT_PROCESSED_TEXT_FIELD, remove_html_tags, pre_process_type, hash_seed)

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
            whitelist_fields += [x.strip() for x in field.split('|')]
    if whitelist_fields and len(whitelist_fields) > 0:
        whitelist_fields.append(DBOT_PROCESSED_TEXT_FIELD)
        data = whitelist_dict_fields(data, whitelist_fields)

    description += "Done processing: %d samples" % len(data) + "\n"
    # output
    file_name = str(uuid.uuid4())
    output_format = demisto.args()['outputFormat']
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
