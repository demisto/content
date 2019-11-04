# pylint: disable=no-member
from CommonServerPython import *
import uuid
import pickle
from HTMLParser import HTMLParser
from io import BytesIO, StringIO

import demisto_ml
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


def clean_html(text):
    cleaned = text
    for pattern in HTML_PATTERNS:
        cleaned = pattern.sub(" ", cleaned)
    return html_parser.unescape(cleaned).strip()


def remove_line_breaks(text):
    return re.sub(r"\s+", " ", text.replace("\r", " ").replace("\n", " ")).strip()


def hash_word(word, seed):
    return str(hash_djb2(word, seed))


def pre_process_nlp(text_data):
    res = demisto.executeCommand('WordTokenizerNLP', {
        'value': json.dumps(text_data),
        'isValueJson': 'yes',
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


def read_file(input_entry_or_string, file_type):
    data = []  # type: List[Dict[str,str]]
    if not input_entry_or_string:
        return data
    if file_type.endswith("string"):
        if 'b64' in file_type:
            input_entry_or_string = base64.b64decode(input_entry_or_string)
        if isinstance(input_entry_or_string, str):
            file_content = BytesIO(input_entry_or_string)
        elif isinstance(input_entry_or_string, unicode):
            file_content = StringIO(input_entry_or_string)  # type: ignore
    else:
        res = demisto.getFilePath(input_entry_or_string)
        if not res:
            return_error("Entry {} not found".format(input_entry_or_string))
        file_path = res['path']
        with open(file_path, 'rb') as f:
            file_content = BytesIO(f.read())
    if file_type.startswith('csv'):
        return json.loads(pd.read_csv(file_content).fillna('').to_json(orient='records'))
    elif file_type.startswith('json'):
        return json.loads(file_content.getvalue())
    elif file_type.startswith('pickle'):
        return pd.read_pickle(file_content, compression=None)
    else:
        return_error("Unsupported file type %s" % file_type)


def pre_process(data, source_text_field, target_text_field, remove_html_tags, pre_process_type, hash_seed):
    tokenized_text_data = map(lambda x: x[source_text_field], data)
    if remove_html_tags:
        tokenized_text_data = map(clean_html, tokenized_text_data)
    tokenized_text_data = map(remove_line_breaks, tokenized_text_data)
    pre_process_func = PRE_PROCESS_TYPES[pre_process_type]
    tokenized_text_data = pre_process_func(tokenized_text_data)
    for d, tokenized_text_data in zip(data, tokenized_text_data):
        if hash_seed:
            tokenized_text_data = " ".join(map(lambda word: hash_word(word, hash_seed), tokenized_text_data.split(" ")))
        d[target_text_field] = tokenized_text_data
    return data


def concat_text_fields(data, target_field, text_fields):
    for d in data:
        text = u''
        for fields in text_fields:
            for field in fields.strip().split("|"):
                field = field.strip()
                if "." in field:
                    value = demisto.dt(d, field)
                    if type(value) is list and len(value) > 0:
                        value = value[0]
                else:
                    value = d.get(field) or d.get(field.lower(), '')
                if isinstance(value, str):
                    value = unicode(value, "utf-8")
                if value and isinstance(value, unicode):
                    text += value
                    text += ' '
                    break
        text = text.strip()
        d[target_field] = text
    return data


def whitelist_dict_fields(data, fields):
    fields = map(lambda x: x.strip(), fields)
    fields += map(lambda x: x.lower(), fields)
    new_data = []
    for d in data:
        new_data.append({k: v for k, v in d.items() if k in fields})
    return new_data


def remove_short_text(data, text_field, remove_short_threshold):
    description = ""
    before_count = len(data)
    data = filter(lambda x: len(x[text_field].split(" ")) > remove_short_threshold, data)
    after_count = len(data)
    dropped_count = before_count - after_count
    if dropped_count > 0:
        description += "Dropped %d samples shorted then %d words" % (dropped_count, remove_short_threshold) + "\n"
    return data, description


def remove_duplicate_by_indices(data, duplicate_indices):
    description = ""
    data = [x for i, x in enumerate(data) if i not in duplicate_indices]
    dropped_count = len(duplicate_indices)
    if dropped_count > 0:
        description += "Dropped %d samples duplicate to other samples" % dropped_count + "\n"
    return data, description


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
    output_format = demisto.args()['outputFormat']

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
    data, desc = remove_short_text(data, DBOT_TEXT_FIELD, remove_short_threshold)
    description += desc

    # remove duplicates
    try:
        if 0 < de_dup_threshold < 1:

            duplicate_indices = demisto_ml.find_duplicate_indices(map(lambda x: x[DBOT_PROCESSED_TEXT_FIELD], data),
                                                                  de_dup_threshold)
            data, desc = remove_duplicate_by_indices(data, duplicate_indices)
            description += desc
    except Exception:
        pass

    if whitelist_fields and len(whitelist_fields) > 0:
        whitelist_fields.append(DBOT_PROCESSED_TEXT_FIELD)
        data = whitelist_dict_fields(data, whitelist_fields)

    description += "Done processing: %d samples" % len(data) + "\n"
    # output
    file_name = str(uuid.uuid4())
    output_format = demisto.args()['outputFormat']
    if output_format == 'pickle':
        data_encoded = pickle.dumps(data)
    elif output_format == 'json':
        data_encoded = json.dumps(data, default=str)
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


if __name__ in ['__builtin__', '__main__']:
    entry = main()
    demisto.results(entry)
