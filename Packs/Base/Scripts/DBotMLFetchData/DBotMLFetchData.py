from itertools import combinations

import dateutil

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import pickle
import re
from nltk.tokenize import word_tokenize, sent_tokenize
import string
from bs4 import BeautifulSoup
from collections import Counter
import pandas as pd
import signal
import numpy as np
import zlib
from base64 import b64encode
from nltk import ngrams
from datetime import datetime
import tldextract
from email.utils import parseaddr

NO_FETCH_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)
NON_POSITIVE_VALIDATION_VALUES = set(['none', 'fail', 'softfail'])

VALIDATION_OTHER = 'other'

VALIDATION_NA = 'na'

CHARACTERS_TO_COUNT = list(string.printable) + ['$', '€', '£', '¥', '₪', '₽']

MIN_TEXT_LENGTH = 20

MODIFIED_QUERY_TIMEFORMAT = '%Y-%m-%d %H:%M:%S'
EMAIL_BODY_FIELD = 'emailbody'
EMAIL_SUBJECT_FIELD = 'emailsubject'
EMAIL_HTML_FIELD = 'emailbodyhtml'
EMAIL_HEADERS_FIELD = 'emailheaders'
EMAIL_ATTACHMENT_FIELD = 'attachment'

GLOVE_50_PATH = '/var/glove_50_top_20k.p'
GLOVE_100_PATH = '/var/glove_100_top_20k.p'
FASTTEXT_PATH = '/var/fasttext_top_20k.p'
DOMAIN_TO_RANK_PATH = '/var/domain_to_rank.p'
WORD_TO_NGRAM_PATH = '/var/word_to_ngram.p'
WORD_TO_REGEX_PATH = '/var/word_to_regex.p'

EMBEDDING_DICT_GLOVE_50 = None
EMBEDDING_DICT_GLOVE_100 = None
EMBEDDING_DICT_FASTTEXT = None
DOMAIN_TO_RANK = None
WORD_TO_REGEX = None
WORD_TO_NGRAMS = None

FETCH_DATA_VERSION = '1.0'
LAST_EXECUTION_LIST_NAME = 'FETCH_DATA_ML_LAST_EXECUTION'
MAX_INCIDENTS_TO_FETCH_PERIODIC_EXECUTION = 500
MAX_INCIDENTS_TO_FETCH_FIRST_EXECUTION = 3000
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'

IMG_FORMATS = ['.jpeg', '.gif', '.bmp', '.png', '.jfif', '.tiff', '.eps', '.indd', '.jpg']

RECEIVED_SERVER_REGEX = r'(?<=from )[a-zA-Z0-9_.+-]+'
ENVELOP_FROM_REGEX = r'(?<=envelope-from )<?[a-zA-Z0-9@_\.\+\-]+>?'

IP_DOMAIN_TOKEN = 'IP_DOMAIN'

'''
Define time out functionality
'''


class TimeoutException(Exception):  # Custom exception class
    pass


def timeout_handler(signum, frame):  # Custom signal handler
    if signum or frame:
        pass
    raise TimeoutException


# Change the behavior of SIGALRM
signal.signal(signal.SIGALRM, timeout_handler)

'''
Define heuristics for finding label field
'''
LABEL_FIELDS_BLACKLIST = set(['CustomFields', 'ShardID', 'account', 'activated', 'attachment', 'autime', 'canvases',
                              'category', 'closeNotes', 'closed', 'closingUserId', 'created', 'criticalassets',
                              'dbotCreatedBy', 'details', 'detectionsla', 'droppedCount', 'dueDate', 'emailbody',
                              'emailheaders', 'emailsubject', 'hasRole', 'id', 'investigationId', 'isPlayground',
                              'labels', 'lastJobRunTime', 'lastOpen', 'linkedCount', 'linkedIncidents', 'modified',
                              'name', 'notifyTime', 'occurred', 'openDuration', 'owner', 'parent', 'phase',
                              'playbookId', 'previousRoles', 'rawCategory', 'rawCloseReason', 'rawJSON', 'rawName',
                              'rawPhase', 'rawType', 'reason', 'remediationsla', 'reminder', 'roles', 'runStatus',
                              'severity', 'sla', 'sortValues', 'sourceBrand', 'sourceInstance',
                              'status', 'timetoassignment', 'type', 'urlsslverification', 'version'])
LABEL_VALUES_KEYWORDS = ['spam', 'malicious', 'legit', 'false', 'positive', 'phishing', 'fraud', 'internal', 'test',
                         'fp', 'tp', 'resolve', 'credentials', 'spear', 'malware', 'whaling', 'catphishing',
                         'catfishing', 'social', 'sextortion', 'blackmail', 'spyware', 'adware']
LABEL_FIELD_KEYWORDS = ['classifi', 'type', 'resolution', 'reason', 'categor', 'disposition', 'severity', 'malicious',
                        'tag', 'close', 'phish', 'phishing']

'''
Define html tags to count
'''
HTML_TAGS = ["a", "abbr", "acronym", "address", "area", "b", "base", "bdo", "big", "blockquote", "body", "br", "button",
             "caption", "cite", "code", "col", "colgroup", "dd", "del", "dfn", "div", "dl", "DOCTYPE", "dt", "em",
             "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "html",
             "hr", "i", "img", "input", "ins", "invalidtag", "kbd", "label", "legend", "li", "link", "map", "meta",
             "noscript", "object", "ol", "optgroup", "option", "p", "param", "pre", "q", "samp", "script", "section",
             "select", "small", "span", "strong", "style", "sub", "sup", "table", "tbody", "td", "textarea", "tfoot",
             "th", "thead", "title", "tr", "tt", "ul", "var"]
HTML_TAGS = set(HTML_TAGS)

'''
Define known shortened and drive domains
'''

DRIVE_URL_KEYWORDS = ['drive', 'transfer', 'formplus', 'dropbox', 'sendspace', 'onedrive', 'box', 'pcloud', 'icloud',
                      'mega', 'spideroak', 'sharepoint']
SHORTENED_DOMAINS = set(
    ["adf.ly", "t.co", "goo.gl", "adbooth.net", "adfoc.us", "bc.vc", "bit.ly", "j.gs", "seomafia.net", "adlock.in",
     "adbooth.com", "cutt.us", "is.gd", "cf.ly", "ity.im", "tiny.cc", "adfa.st", "budurl.com", "soo.gd",
     "prettylinkpro.com", "shrinkonce.com", "ad7.biz", "2tag.nl", "1o2.ir", "hotshorturl.com", "onelink.ir", "dai3.net",
     "9en.us", "kaaf.com", "rlu.ru", "awe.sm", "4ks.net", "s2r.co", "4u2bn.com", "multiurl.com", "tab.bz", "dstats.net",
     "iiiii.in", "nicbit.com", "l1nks.org", "at5.us", "bizz.cc", "fur.ly", "clicky.me", "magiclinker.com",
     "miniurl.com", "bit.do", "adurl.biz", "omani.ac", "1y.lt", "1click.im", "1dl.us", "4zip.in", "ad4.us", "adfro.gs",
     "adnld.com", "adshor.tk", "adspl.us", "adzip.us", "articleshrine.com", "asso.in", "b2s.me", "bih.cc", "biturl.net",
     "buraga.org", "cc.cr", "cf6.co", "dollarfalls.info", "domainonair.com", "gooplu.com", "hide4.me", "ik.my",
     "ilikear.ch", "infovak.com", "itz.bz", "jetzt-hier-klicken.de", "kly.so", "lst.bz", "mrte.ch",
     "multiurlscript.com", "nowlinks.net", "nsyed.com", "ooze.us", "ozn.st", "scriptzon.com", "short2.in",
     "shortxlink.com", "shr.tn", "shrt.in", "sitereview.me", "sk.gy", "snpurl.biz", "socialcampaign.com", "swyze.com",
     "theminiurl.com", "tinylord.com", "tinyurl.ms", "tip.pe", "ty.by"])


def find_label_fields_candidates(incidents_df):
    candidates = [col for col in list(incidents_df) if
                  sum(isinstance(x, str) or isinstance(x, bool) for x in incidents_df[col]) > 0.3 * len(incidents_df)]
    candidates = [col for col in candidates if col not in LABEL_FIELDS_BLACKLIST]

    candidate_to_values = {col: incidents_df[col].unique() for col in candidates}
    candidate_to_values = {col: values for col, values in candidate_to_values.items() if
                           sum(not (isinstance(v, str) or isinstance(v, bool)) for v in values) <= 1}

    # filter columns by unique values count
    candidate_to_values = {col: values for col, values in candidate_to_values.items() if 0 < len(values) < 15}
    candidate_to_values = {col: [v.lower() if isinstance(v, str) else v for v in values]
                           for col, values in candidate_to_values.items()}
    candidate_to_score = {col: 0 for col in candidate_to_values}
    for col, values in candidate_to_values.items():
        for v in values:
            if any(isinstance(v, str) and w in v for w in LABEL_VALUES_KEYWORDS):
                candidate_to_score[col] += 1
        if any(w in col.lower() for w in LABEL_FIELD_KEYWORDS):
            candidate_to_score[col] += 1
    return [k for k, v in sorted(candidate_to_score.items(), key=lambda item: item[1], reverse=True)]


def get_text_from_html(html):
    soup = BeautifulSoup(html)
    # kill all script and style elements
    for script in soup(["script", "style"]):
        script.extract()  # rip it out
    # get text
    text = soup.get_text()
    # break into lines and remove leading and trailing space on each
    lines = (line.strip() for line in text.splitlines())
    # break multi-headlines into a line each
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    # drop blank lines
    text = '\n'.join(chunk for chunk in chunks if chunk)
    return text


def get_ngrams_features(text, ngrams_counter):
    global WORD_TO_NGRAMS, WORD_TO_REGEX
    ngrams_features = {}
    for w, regex in WORD_TO_REGEX.items():  # type: ignore
        count = len(re.findall(regex, text))
        if count > 0:
            ngrams_features[w] = count
    for w, ngram in WORD_TO_NGRAMS.items():  # type: ignore
        count = ngrams_counter[ngram] if ngram in ngrams_counter else 0
        if count > 0:
            ngrams_features[w] = count
    return ngrams_features


def get_lexical_features(email_subject, email_body, email_body_word_tokenized, email_subject_word_tokenized):
    words = [w for w in email_body_word_tokenized if any(c.isalnum() for c in w)]
    num_of_words = len(words)
    avg_word_length = 0 if len(words) == 0 else float(sum([len(w) for w in words])) / len(words)
    sentences = sent_tokenize(email_body)
    num_of_sentences = len(sentences)
    avg_sentence_length = 0 if len(sentences) == 0 else float(sum([len(s) for s in sentences])) / len(sentences)
    text_length = len(email_body)
    subject_length = len(email_subject)
    number_of_lines = email_body.count('\n') + 1
    word_subject = [w for w in email_subject_word_tokenized if any(c.isalnum() for c in w)]
    num_of_words_subject = len(word_subject)
    ending_dots = len([s for s in sentences if s.strip().endswith('.')])
    ending_explanation = len([s for s in sentences if s.strip().endswith('!')])
    ending_question = len([s for s in sentences if s.strip().endswith('?')])

    return {'num_of_words': num_of_words,
            'avg_word_length': avg_word_length,
            'num_of_sentences': num_of_sentences,
            'avg_sentence_length': avg_sentence_length,
            'avg_number_of_words_in_sentence': float(num_of_words) / num_of_sentences if num_of_sentences > 0 else 0,
            'text_length': text_length,
            'num_of_words_subject': num_of_words_subject,
            'subject_length': subject_length,
            'ending_dots': ending_dots,
            'ending_explanation': ending_explanation,
            'ending_question': ending_question,
            'number_of_lines': number_of_lines
            }


def get_characters_features(text):
    characters_count = {}
    for c in CHARACTERS_TO_COUNT:
        if c in ['[', ']', '<']:
            continue
        count = text.count(c)
        if count > 0:
            characters_count[c] = count
    return characters_count


def get_url_features(email_body, email_html, soup):
    url_regex = r'(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+[-\w\d]+(?::\d+)?' \
                r'(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?'
    embedded_urls = []
    for a in soup.findAll('a'):
        if a.has_attr('href'):
            if a['href'] not in a.get_text():
                embedded_urls.append(a['href'])
    plain_urls = re.findall(url_regex, email_body)
    all_urls = plain_urls + embedded_urls
    all_urls_lengths = [len(u) for u in all_urls]
    average_url_length = 0 if len(all_urls) == 0 else sum(all_urls_lengths) / len(all_urls)
    min_url_length = 0 if len(all_urls_lengths) == 0 else min(all_urls_lengths)
    max_url_length = 0 if len(all_urls_lengths) == 0 else max(all_urls_lengths)
    shortened_urls_count = len([u for u in all_urls if any(shortened_u in u for shortened_u in SHORTENED_DOMAINS)])
    drive_count = len([u for u in all_urls if any(drive in u for drive in DRIVE_URL_KEYWORDS)])
    return {
        'http_urls_count': sum(url.startswith('http') and not url.startswith('https') for url in plain_urls),
        'https_urls_count': sum(url.startswith('https')for url in plain_urls),
        'embedded_urls_count': len(embedded_urls),
        'all_urls_count': len(all_urls),
        'average_url_length': average_url_length,
        'min_url_length': min_url_length,
        'max_url_length': max_url_length,
        'shortened_urls_count': shortened_urls_count,
        'drive_count': drive_count
    }


def get_html_features(soup):
    global HTML_TAGS
    html_counter = Counter([tag.name for tag in soup.find_all()])
    for t in HTML_TAGS:
        if t in html_counter:
            html_counter[t] = html_counter[t]
    html_counter = {k: v for k, v in html_counter.items() if k in HTML_TAGS}
    return html_counter


def load_external_resources():
    global EMBEDDING_DICT_GLOVE_50, EMBEDDING_DICT_GLOVE_50, EMBEDDING_DICT_GLOVE_100, EMBEDDING_DICT_FASTTEXT,\
        DOMAIN_TO_RANK, DOMAIN_TO_RANK_PATH, WORD_TO_NGRAMS, WORD_TO_REGEX
    with open(GLOVE_50_PATH, 'rb') as file:
        EMBEDDING_DICT_GLOVE_50 = pickle.load(file)
    with open(GLOVE_100_PATH, 'rb') as file:
        EMBEDDING_DICT_GLOVE_100 = pickle.load(file)
    with open(FASTTEXT_PATH, 'rb') as file:
        EMBEDDING_DICT_FASTTEXT = pickle.load(file)
    with open(DOMAIN_TO_RANK_PATH, 'rb') as file:
        DOMAIN_TO_RANK = pickle.load(file)
    with open(WORD_TO_NGRAM_PATH, 'rb') as file:
        WORD_TO_NGRAMS = pickle.load(file)
    with open(WORD_TO_REGEX_PATH, 'rb') as file:
        WORD_TO_REGEX = pickle.load(file)


def get_avg_embedding_vector_for_text(tokenized_text, embedding_dict, size, prefix):
    vectors = [embedding_dict[w] for w in tokenized_text if w in embedding_dict]
    if len(vectors) == 0:
        mean_vector = np.zeros(size)
    else:
        mean_vector = np.mean(vectors, axis=0)
    res = {'{}_{}'.format(prefix, str(i)): mean_vector[i].item() for i in range(len(mean_vector))}
    return res


def get_embedding_features(tokenized_text):
    res_glove_50 = get_avg_embedding_vector_for_text(tokenized_text, EMBEDDING_DICT_GLOVE_50, 50, 'glove50')
    res_glove_100 = get_avg_embedding_vector_for_text(tokenized_text, EMBEDDING_DICT_GLOVE_100, 100, 'glove100')
    res_fasttext = get_avg_embedding_vector_for_text(tokenized_text, EMBEDDING_DICT_FASTTEXT, 300, 'fasttext')
    return {**res_glove_50, **res_glove_100, **res_fasttext}


def get_header_value(email_headers, header_name, index=0, ignore_case=False):
    if ignore_case:
        header_name = header_name.lower()
        headers_with_name = [header_dict for header_dict in email_headers if header_dict['headername'].lower() == header_name]
    else:
        headers_with_name = [header_dict for header_dict in email_headers if header_dict['headername'] == header_name]
    if len(headers_with_name) == 0:
        return None
    else:
        return headers_with_name[index]['headervalue']


def parse_email_header(email_headers, header_name):
    global NO_FETCH_EXTRACT
    header_value = get_header_value(email_headers, header_name=header_name)
    if header_value is None:
        email_address = email_domain = email_suffix = None
    else:
        email_address = parseaddr(header_value)[1]
        ext = NO_FETCH_EXTRACT(email_address)
        email_domain = ext.domain
        email_suffix = ext.suffix

    return {'name': header_name, 'address': email_address, 'domain': email_domain, 'suffix': email_suffix}


def extract_server_address(received_value):
    global RECEIVED_SERVER_REGEX, NO_FETCH_EXTRACT, IP_DOMAIN_TOKEN
    server_address_list = re.findall(RECEIVED_SERVER_REGEX, received_value)
    if len(server_address_list) == 0:
        server_domain = IP_DOMAIN_TOKEN
        server_suffix = None
    else:
        server_address = server_address_list[0]
        ext = NO_FETCH_EXTRACT(server_address)
        server_domain = ext.domain
        server_suffix = ext.suffix
    return server_domain, server_suffix


def extract_envelop_from_address(received_value):
    global ENVELOP_FROM_REGEX, NO_FETCH_EXTRACT
    from_envelop_address_list = re.findall(ENVELOP_FROM_REGEX, received_value)
    if len(from_envelop_address_list) == 0:
        from_envelop_address = from_envelop_domain = from_envelop_suffix = None
    else:
        from_envelop_address = from_envelop_address_list[0]
        from_envelop_address = parseaddr(from_envelop_address)[1]
        ext = NO_FETCH_EXTRACT(from_envelop_address)
        from_envelop_domain = ext.domain
        from_envelop_suffix = ext.suffix
    return from_envelop_address, from_envelop_domain, from_envelop_suffix


def parse_single_received_value(received_headers, index, name):
    if len(received_headers) >= index:
        received_value = received_headers[-index]['headervalue']
        server_domain, server_suffix = extract_server_address(received_value)
        from_envelop_address, from_envelop_domain, from_envelop_suffix = extract_envelop_from_address(received_value)
    else:
        server_domain = server_suffix = from_envelop_domain = from_envelop_address = from_envelop_suffix = None
    server_info = {'name': '{}-Server'.format(name), 'domain': server_domain, 'suffix': server_suffix}
    envelop_info = {'name': '{}-Envelope'.format(name), 'address': from_envelop_address, 'domain': from_envelop_domain,
                    'suffix': from_envelop_suffix}
    return server_info, envelop_info


def parse_received_headers(email_headers):
    received_headers = [header_dict for header_dict in email_headers if header_dict['headername'] == 'Received']
    n_received_headers = len(received_headers)
    first_server_info, first_envelop_info = parse_single_received_value(received_headers, 1, 'First-Received')
    second_server_info, second_envelop_info = parse_single_received_value(received_headers, 2, 'Second-Received')
    return n_received_headers, [first_server_info, first_envelop_info, second_server_info, second_envelop_info]


def get_rank_address(address):
    global DOMAIN_TO_RANK
    if address is None:
        return float('nan')
    if '@' in address:
        full_domain = address.split('@')[1]
    else:
        full_domain = address
    if full_domain in DOMAIN_TO_RANK:  # type: ignore
        return DOMAIN_TO_RANK[full_domain]  # type: ignore
    else:
        return -1


def compare_values(v1, v2):
    if v1 is None or v2 is None:
        return float('nan')
    return v1 == v2


def get_headers_features(email_headers):
    spf_result = get_header_value(email_headers, header_name='Received-SPF')
    if spf_result is not None:
        spf_result = spf_result.split()[0].lower()
    else:
        spf_result = VALIDATION_NA
    res_spf = {k: 0 for k in ['none', 'neutral', 'pass', 'fail', 'softfail', 'temperror', 'permerror', VALIDATION_NA]}
    if spf_result in res_spf:
        res_spf[spf_result] += 1
    else:
        res_spf[VALIDATION_OTHER] = 1
    res_spf['non-positive'] = spf_result in NON_POSITIVE_VALIDATION_VALUES
    authentication_results = get_header_value(email_headers, header_name='Authentication-Results')
    if authentication_results is not None:
        if 'dkim=' in authentication_results:
            dkim_result = authentication_results.split('dkim=')[-1].split()[0].lower().strip()
        else:
            dkim_result = VALIDATION_NA
    else:
        dkim_result = VALIDATION_NA
    res_dkim = {k: 0 for k in ['none', 'neutral', 'pass', 'fail', 'softfail', 'temperror', 'permerror', VALIDATION_NA]}
    if dkim_result in res_dkim:
        res_dkim[dkim_result] += 1
    else:
        res_dkim[VALIDATION_OTHER] = 1
    res_dkim['non-positive'] = spf_result in NON_POSITIVE_VALIDATION_VALUES
    list_unsubscribe = get_header_value(email_headers, header_name='List-Unsubscribe')
    unsubscribe_post = get_header_value(email_headers, header_name='List-Unsubscribe-Post-SPF')
    res_unsubscribe = 1 if list_unsubscribe is not None or unsubscribe_post is not None else 0
    from_dict = parse_email_header(email_headers, header_name='From')
    return_path_dict = parse_email_header(email_headers, header_name='Return-Path')
    reply_to_dict = parse_email_header(email_headers, header_name='Reply-To')
    n_received_headers, received_dicts_list = parse_received_headers(email_headers)
    all_addresses_dicts = received_dicts_list + [from_dict, return_path_dict, reply_to_dict]
    addresses_res = {}
    for a in all_addresses_dicts:
        addresses_res['{}::Exists'.format(a['name'])] = a['domain'] is not None
        if 'address' in a:
            addresses_res['{}::Rank'.format(a['name'])] = get_rank_address(a['address'])
        if 'Received' in a['name'] and 'Server' in a['name']:
            addresses_res['{}::IP_DOMAIN'.format(a['name'])] = a['domain'] == IP_DOMAIN_TOKEN
        addresses_res['{}::Suffix'.format(a['name'])] = a['suffix'] if a['suffix'] is not None else float('nan')

    for a1, a2 in combinations(all_addresses_dicts, 2):
        if 'address' in a1 and 'address' in a2:
            addresses_res['{}.Address=={}.Addres'.format(a1['name'], a2['name'])] = compare_values(a1['address'],
                                                                                                   a2['address'])
        addresses_res['{}.Domain=={}.Domain'.format(a1['name'], a2['name'])] = compare_values(a1['domain'],
                                                                                              a2['domain'])

    addresses_res['count_received'] = n_received_headers
    content_type_value = get_header_value(email_headers, header_name='Content-Type', index=0, ignore_case=True)
    if content_type_value is not None and ';' in content_type_value:
        content_type_value = content_type_value.split(';')[0]

    res = {}
    for k, v in res_spf.items():
        res['spf::{}'.format(k)] = v
    for k, v in res_dkim.items():
        res['dkim::{}'.format(k)] = v
    res['unsubscribe_headers'] = res_unsubscribe
    for k, v in addresses_res.items():
        res[k] = v  # type: ignore
    res['content-type'] = content_type_value
    return res


def get_attachments_features(email_attachments):
    res = {}
    res['number_of_attachments'] = len(email_attachments)
    all_attachments_names = []
    for a in email_attachments:
        attachment_name = a['name']
        if attachment_name is not None:
            all_attachments_names.append(attachment_name.lower())
    all_attachments_names_lengths = [len(name) for name in all_attachments_names]
    res['min_attachment_name_length'] = min(all_attachments_names_lengths) if len(
        all_attachments_names_lengths) > 0 else 0
    res['max_attachment_name_length'] = max(all_attachments_names_lengths) if len(
        all_attachments_names_lengths) > 0 else 0
    res['avg_attachment_name_length'] = float(sum(all_attachments_names_lengths)) / len(  # type: ignore
        all_attachments_names_lengths) if len(all_attachments_names_lengths) > 0 else 0  # type: ignore
    res['image_extension'] = 0
    res['raw_extensions'] = [name.split('.')[-1] for name in all_attachments_names]  # type: ignore
    for image_format in IMG_FORMATS:
        res['image_extension'] += sum([name.endswith(image_format) for name in all_attachments_names])
    res['txt_extension'] = sum([name.endswith('.txt') for name in all_attachments_names])
    res['exe_extension'] = sum([name.endswith('.exe') for name in all_attachments_names])
    res['archives_extension'] = sum(
        [name.endswith('.zip') or name.endswith('.rar') or name.endswith('.lzh') or name.endswith('.7z') for name in
         all_attachments_names])
    res['pdf_extension'] = sum([name.endswith('.pdf') for name in all_attachments_names])
    res['disk_img_extension'] = sum([name.endswith('.iso') or name.endswith('.img') for name in all_attachments_names])
    res['other_executables_extension'] = sum(
        [any(name.endswith(ext) for ext in ['.jar', '.bat', '.psc1', '.vb', '.vbs', '.msi', '.cmd', '.reg', '.wsf']) for
         name in all_attachments_names])

    res['office_extension'] = 0
    for offic_format in ['.doc', '.xls', '.ppt', 'xlsx', 'xlsm']:
        res['office_extension'] += sum([name.endswith(offic_format) for name in all_attachments_names])
    return res


def transform_text_to_ngrams_counter(email_body_word_tokenized, email_subject_word_tokenized):
    text_ngram = []
    for n in range(1, 4):
        text_ngram += list(ngrams(email_body_word_tokenized, n))
        text_ngram += list(ngrams(email_subject_word_tokenized, n))
    text_ngrams = Counter(text_ngram)
    return text_ngrams


def extract_features_from_incident(row):
    global EMAIL_BODY_FIELD, EMAIL_SUBJECT_FIELD, EMAIL_HTML_FIELD, EMAIL_ATTACHMENT_FIELD, EMAIL_HEADERS_FIELD
    email_body = row[EMAIL_BODY_FIELD] if EMAIL_BODY_FIELD in row else ''
    email_subject = row[EMAIL_SUBJECT_FIELD] if EMAIL_SUBJECT_FIELD in row else ''
    email_html = row[EMAIL_HTML_FIELD] if EMAIL_HTML_FIELD in row and isinstance(row[EMAIL_HTML_FIELD], str) else ''
    email_headers = row[EMAIL_HEADERS_FIELD] if EMAIL_HEADERS_FIELD in row else {}
    email_attachments = row[EMAIL_ATTACHMENT_FIELD] if EMAIL_ATTACHMENT_FIELD in row else []
    email_attachments = email_attachments if email_attachments is not None else []
    if isinstance(email_html, float):
        email_html = ''
    if email_body is None or isinstance(email_body, float) or email_body.strip() == '':
        email_body = get_text_from_html(email_html)
    if isinstance(email_subject, float):
        email_subject = ''
    email_body, email_subject = email_body.strip().lower(), email_subject.strip().lower()
    text = email_subject + ' ' + email_body
    if len(text) < MIN_TEXT_LENGTH:
        raise ValueError('Text length is shorter than allowed minimum of: {}'.format(MIN_TEXT_LENGTH))
    email_body_word_tokenized = word_tokenize(email_body)
    email_subject_word_tokenized = word_tokenize(email_subject)
    text_ngrams = transform_text_to_ngrams_counter(email_body_word_tokenized, email_subject_word_tokenized)
    ngrams_features = get_ngrams_features(text, text_ngrams)
    soup = BeautifulSoup(email_html, "html.parser")

    lexical_features = get_lexical_features(email_subject, email_body, email_body_word_tokenized,
                                            email_subject_word_tokenized)
    characters_features = get_characters_features(text)
    html_feature = get_html_features(soup)
    ml_features = get_embedding_features(email_body_word_tokenized + email_subject_word_tokenized)
    headers_features = get_headers_features(email_headers)
    url_feautres = get_url_features(email_body=email_body, email_html=email_html, soup=soup)
    attachments_features = get_attachments_features(email_attachments=email_attachments)

    return {
        'ngrams_features': ngrams_features,
        'lexical_features': lexical_features,
        'characters_features': characters_features,
        'html_feature': html_feature,
        'ml_features': ml_features,
        'headers_features': headers_features,
        'url_features': url_feautres,
        'attachments_features': attachments_features
    }


def extract_features_from_all_incidents(incidents_df):
    X = {  # type: ignore
        'ngrams_features': [],
        'lexical_features': [],
        'characters_features': [],
        'html_feature': [],
        'ml_features': [],
        'headers_features': [],
        'url_features': [],
        'attachments_features': []
    }   # type: ignore
    exceptions_log = []
    exception_indices = set()
    timeout_indices = set()
    durations = []
    for index, row in incidents_df.iterrows():
        signal.alarm(5)
        try:
            start = time.time()
            X_i = extract_features_from_incident(row)
            end = time.time()
            for k, v in X_i.items():
                X[k].append(v)
            durations.append(end - start)
        except TimeoutException:
            timeout_indices.add(index)
        except Exception:
            exception_indices.add(index)
            exceptions_log.append(traceback.format_exc())
        finally:
            signal.alarm(0)
    n_fetched_incidents = len(incidents_df) - len(exception_indices) - len(timeout_indices)
    return X, n_fetched_incidents, exceptions_log, exception_indices, timeout_indices, durations


def extract_data_from_incidents(incidents):
    incidents_df = pd.DataFrame(incidents)
    if 'created' in incidents_df:
        incidents_df['created'] = incidents_df['created'].apply(lambda x: dateutil.parser.parse(x))   # type: ignore
        incidents_df.sort_values(by='created', inplace=True, ascending=False)
        incidents_df_for_finding_labels_fields_candidates = incidents_df.head(500)
    else:
        incidents_df_for_finding_labels_fields_candidates = incidents_df
    label_fields = find_label_fields_candidates(incidents_df_for_finding_labels_fields_candidates)
    for label in label_fields:
        incidents_df[label].replace('', float('nan'), regex=True, inplace=True)
    incidents_df.dropna(how='all', subset=label_fields, inplace=True)
    y = []
    for i, label in enumerate(label_fields):
        y.append({'field_name': label,
                  'rank': '#{}'.format(i + 1),
                  'values': incidents_df[label].tolist()})
    load_external_resources()
    X, n_fetched_incidents, exceptions_log, exception_indices, timeout_indices, durations\
        = extract_features_from_all_incidents(incidents_df)
    indices_to_drop = exception_indices.union(timeout_indices)
    for label_dict in y:
        label_dict['values'] = [l for i, l in enumerate(label_dict['values']) if i not in indices_to_drop]
    return {'X': X,
            'n_fetched_incidents': n_fetched_incidents,
            'y': y,
            'log':
                {'exceptions': exceptions_log,
                 'n_timout': len(timeout_indices),
                 'n_other_exceptions': len(exception_indices),
                 'durations': durations}
            }


def return_json_entry(obj):
    entry = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": obj,
    }
    demisto.results(entry)


def get_args_based_on_last_execution():
    lst = demisto.executeCommand('getList', {'listName': LAST_EXECUTION_LIST_NAME})
    if isError(lst):  # if first execution
        return {'limit': MAX_INCIDENTS_TO_FETCH_FIRST_EXECUTION}
    else:
        last_execution_datetime = datetime.strptime(lst[0]['Contents'], DATETIME_FORMAT)
        try:
            query = 'modified:>="{}"'.format(datetime.strftime(last_execution_datetime, MODIFIED_QUERY_TIMEFORMAT))
        except Exception:
            query = None  # type: ignore
        finally:
            res = {'limit': MAX_INCIDENTS_TO_FETCH_PERIODIC_EXECUTION}
            if query is not None:
                res['query'] = query  # type: ignore
            return res


def update_last_execution_time():
    execution_datetime_str = datetime.strftime(datetime.now(), DATETIME_FORMAT)
    res = demisto.executeCommand("createList", {"listName": LAST_EXECUTION_LIST_NAME, "listData": execution_datetime_str})
    if is_error(res):
        demisto.results(res)


def main():
    incidents_query_args = demisto.args()
    args = get_args_based_on_last_execution()
    if 'query' in incidents_query_args and 'query' in args:
        incidents_query_args['query'] = '({}) and ({}) and (status:Closed)'.format(incidents_query_args['query'], args['query'])
    elif 'query' in args:
        incidents_query_args['query'] = '({}) and (status:Closed)'.format(args['query'])
    elif 'query' in incidents_query_args:
        incidents_query_args['query'] = '({}) and (status:Closed)'.format(incidents_query_args['query'])
    else:
        incidents_query_args['query'] = '(status:Closed)'
    if 'limit' in args:
        incidents_query_args['limit'] = args['limit']
    incidents_query_res = demisto.executeCommand('GetIncidentsByQuery', incidents_query_args)
    if is_error(incidents_query_res):
        return_error(get_error(incidents_query_res))
    incidents = json.loads(incidents_query_res[-1]['Contents'])
    if len(incidents) == 0:
        demisto.results('No results were found')
    else:
        data = extract_data_from_incidents(incidents)
        encoded_data = json.dumps(data).encode('utf-8', errors='ignore')
        compressed_data = zlib.compress(encoded_data, 4)
        compressed_hr_data = b64encode(compressed_data).decode('utf-8')
        res = {'PayloadVersion': FETCH_DATA_VERSION, 'PayloadData': compressed_hr_data,
               'Execution Time': datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}
        return_json_entry(res)
    update_last_execution_time()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
