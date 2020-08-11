from CommonServerPython import *

import itertools
import numbers
import re
import socket
from collections import Counter
from collections import OrderedDict
from datetime import datetime, timedelta

INCIDENT_FIELD_NAME = "name"
INCIDENT_FIELD_MACHINE_NAME = "cliName"

SAMPLES_INCOMING = 'incomingSamples'
SAMPLES_SCHEME = 'scheme'
SAMPLES_OUTGOING = 'outgoingSamples'

COUNT_KEYWORD = "count"

SIEM_FIELDS = {'Account ID': {'aliases': ['accountid', 'account id'],
                              'validators': []},
               'Account Name': {'aliases': ['accountname', 'account name'],
                                'validators': ['validate_alphanumeric_with_common_punct']},
               'Account Type': {'aliases': ['accounttype', 'account type'],
                                'validators': ['validate_alphanumeric_with_common_punct']},

               'Agent ID': {'aliases': ['agentid', 'agent id', 'sensor id', 'tenant id'],
                            'validators': []},

               'Tenant Name': {'aliases': ['tenant name', 'tenant name'],
                               'validators': ['validate_alphanumeric_with_common_punct']},

               'App': {'aliases': ['app', 'app'], 'validators': ['validate_alphanumeric_with_common_punct']},

               'Attachment Name': {'aliases': ['attachmentname', 'attachment name'],
                                   'validators': ['validate_alphanumeric_with_common_punct']},

               'Blocked Action': {'aliases': ['blockedaction', 'blocked action', 'prevention mode'],
                                  'validators': ['validate_alphanumeric_with_common_punct']},

               'City': {'aliases': ['city'], 'validators': ['validate_alphanumeric_with_common_punct']},

               'Command Line': {'aliases': ['commandline', 'command line', 'cmdline', 'cmd line', 'process file name',
                                            'process file path',
                                            'process full path', 'process full path', 'cmd'],
                                'validators': ['validate_file_full_path']},

               'Event ID': {'aliases': ['eventid', 'event id', 'alert id', 'offense id'],
                            'validators': ['validate_alphanumeric_with_common_punct']},
               'Event Type': {'aliases': ['eventtype', 'event type', 'alert type'],
                              'validators': ['validate_alphanumeric_with_common_punct']},

               'Company Name': {'aliases': ['companyname',
                                            'company name',
                                            'company',
                                            'customer'],
                                'validators': ['validate_alphanumeric_with_common_punct']},

               'Country': {'aliases': ['country', 'country name'],
                           'validators': ['validate_alphanumeric_with_common_punct']},

               'Critical Assets': {'aliases': ['criticalassets', 'critical assets'],
                                   'validators': ['validate_alphanumeric_with_common_punct']},

               'Description': {'aliases': ['description'], 'validators': ['validate_alphanumeric_with_common_punct']},

               'Destination IP': {'aliases': ['destinationip',
                                              'destination ip',
                                              'destination address',
                                              'dest ip',
                                              'dest address',
                                              'target address',
                                              'dst'],
                                  'validators': ['validate_ip']},
               'Destination Port': {'aliases': ['destinationport',
                                                'destination port',
                                                'dst port',
                                                'dest port'],
                                    'validators': ['validate_number']},

               'Email BCC': {'aliases': ['emailbcc', 'email bcc', 'bcc recipient', 'bcc'],
                             'validators': ['validate_email']},

               'Email Body': {'aliases': ['emailbody', 'email body', 'body'],
                              'validators': []},
               'Email Body Format': {'aliases': ['emailbodyformat',
                                                 'email body format',
                                                 'body type',
                                                 'body content type'],
                                     'validators': []},
               'Email Body HTML': {'aliases': ['emailbodyhtml', 'email body html'],
                                   'validators': []},

               'Email CC': {'aliases': ['emailcc', 'email cc', 'cc recipient', 'cc'],
                            'validators': ['validate_email']},

               'Email From': {'aliases': ['emailfrom', 'email from', 'from'],
                              'validators': ['validate_email']},

               'Email HTML': {'aliases': ['emailhtml', 'email html'], 'validators': []},

               'Email Headers': {'aliases': ['emailheaders', 'email headers', 'headers', 'message headers',
                                             'internet message header'],
                                 'validators': ['']},

               'Email In Reply To': {'aliases': ['emailinreplyto', 'email in reply to'],
                                     'validators': []},

               'Email Received': {'aliases': ['emailreceived',
                                              'email received',
                                              'received date time',
                                              'received time'],
                                  'validators': ['validate_date']},

               'Email Reply To': {'aliases': ['emailreplyto', 'email replay to', 'reply to'],
                                  'validators': []},

               'Email Sender IP': {'aliases': ['emailsenderip', 'email sender ip'],
                                   'validators': ['validate_ip']},

               'Email Size': {'aliases': ['emailsize', 'email size'], 'validators': ['validate_number']},

               'Email Subject': {'aliases': ['emailsubject', 'email subject', 'subject'],
                                 'validators': []},

               'Email To': {'aliases': ['emailto',
                                        'email to',
                                        'to recipients',
                                        'recipients',
                                        'recipient'],
                            'validators': ['validate_email']},

               'File Hash': {'aliases': ['filehash', 'file hash', 'event file hash', 'md5', 'sha1', 'sha256'],
                             'validators': ['validate_hash']},
               'File Name': {'aliases': ['filename', 'file name'], 'validators': []},
               'File Path': {'aliases': ['filepath', 'file path', 'full path', 'full path'],
                             'validators': ['validate_file_full_path']},
               'File Size': {'aliases': ['filesize', 'file size'], 'validators': ['validate_number']},

               'File Type': {'aliases': ['filetype', 'file type'],
                             'validators': ['validate_alphanumeric_with_common_punct']},

               'Source Hostname': {
                   'aliases': ['source hostname', 'source host name', 'src hostname', 'src host name'],
                   'validators': ['validate_hostname']},

               'Destination Hostname': {
                   'aliases': ['destination hostname', 'destination host name',
                               'dest hostname', 'dest host name', 'dst hostname', 'dst host name',
                               'target hostname', 'target host name'],
                   'validators': ['validate_hostname']},

               'Source Network': {'aliases': ['source network', 'sourcenetwork', 'src network'],
                                  'validators': ['validate_alphanumeric_with_common_punct']},
               'Destination Network': {'aliases': ['destination network', 'destinationnetwork',
                                                   'dest network', 'dst network', 'target netwrok'],
                                       'validators': ['validate_alphanumeric_with_common_punct']},

               'Device Name': {
                   'aliases': ['devicename', 'device name', 'endpoint name', 'end point name'],
                   'validators': ['validate_alphanumeric_with_common_punct']},


               'MAC Address': {'aliases': ['macaddress', 'mac address', 'mac', 'src mac', 'source mac'],
                               'validators': ['validate_mac']},

               'PID': {'aliases': ['pid', 'process pid', 'parent process pid', 'target process pid'],
                       'validators': ['validate_number']},
               'Parent Process ID': {'aliases': ['parentprocessid', 'parent process id'],
                                     'validators': ['validate_number']},

               'Region': {'aliases': ['region', 'region'], 'validators': ['validate_alphanumeric_with_common_punct']},

               'Signature': {'aliases': ['signature', 'signature'], 'validators': []},

               'Source IP': {
                   'aliases': ['sourceip', 'source ip', 'src ip', 'src address', 'source address', 'computer ip',
                               'device ip',
                               'attacker address', 'attacker ip', 'sender ip', 'sender address', 'offense source',
                               'agent ip'],
                   'validators': ['validate_ip']},

               'Source Port': {'aliases': ['sourceport',
                                           'source port',
                                           'src port'],
                               'validators': ['validate_number']},

               'OS': {'aliases': ['operating system', 'os type', 'os version', 'os'],
                      'validators': []},

               'Subtype': {'aliases': ['subtype', 'subtype'],
                           'validators': ['validate_alphanumeric_with_common_punct']},

               'Terminated Action': {'aliases': ['terminatedaction', 'terminated action'],
                                     'validators': []},

               'Traps ID': {'aliases': ['trapsid', 'traps id', 'trap id'], 'validators': []},

               'Source Username': {'aliases': ['username', 'username', 'user name', 'src user name',
                                               'src username', 'source username', 'source user name'],
                                   'validators': ['validate_alphanumeric_with_common_punct']},
               'Destination Username': {'aliases': ['destination username', 'destination user name',
                                                    'dest username', 'dest user name', 'dst username', 'dst user name',
                                                    'target user name', 'target username'],
                                        'validators': ['validate_alphanumeric_with_common_punct']},

               'Detection URL': {'aliases': ['detection url'],
                                 'validators': ['validate_url']},

               'Vendor ID': {'aliases': ['vendorid', 'vendor id'], 'validators': []},
               'Vendor Product': {'aliases': ['vendorproduct', 'vendor product'],
                                  'validators': ['validate_alphanumeric_with_common_punct']},
               'category': {'aliases': ['category', 'category'],
                            'validators': ['validate_alphanumeric_with_common_punct']},
               'details': {'aliases': ['details', 'description'],
                           'validators': ['validate_alphanumeric_with_common_punct']},
               'name': {'aliases': ['name', 'Name', 'alert name', 'event name', 'rule name', 'title'],
                        'validators': ['validate_alphanumeric_with_common_punct', 'extact_name_math']},
               'occurred': {'aliases': ['occurred', 'occured', 'occurred time', 'event start time', 'event at',
                                        'event time', 'start time',
                                        'create time', 'timestamp', 'unix time', 'click time'],
                            'validators': ['validate_date']},

               'owner': {'aliases': ['owner'], 'validators': []},

               'severity': {'aliases': ['event severity', 'severity', 'event priority', 'priority', 'urgency'],
                            'validators': []},

               'Log Source': {'aliases': ['log source', 'log sources', 'logsource'], 'validators': []},

               'Protocol': {'aliases': ['protocol'], 'validators': []},

               }

suffix_mapping = {
    'ing': '',
    'ly': '',
    'ed': '',
    'ious': '',
    'ies': 'y',
    'ive': '',
    'es': '',
    's': ''
}


class DateValidator:

    def __init__(self):
        year_options = ['%y', '%Y']
        months_options = ['%m', '%B']
        day_options = ['%d']
        delimeters_options = [".", "-", "/", "\\"]
        self.common_separators = [' ', 'T', ',']

        date_formats_options = []  # type: List[tuple]
        for delimeter in delimeters_options:
            delimeters = [delimeter]
            date_formats_options += list(
                itertools.product(year_options, delimeters, months_options, delimeters, day_options))
            date_formats_options += list(
                itertools.product(year_options, delimeters, day_options, delimeters, months_options))
            date_formats_options += list(
                itertools.product(day_options, delimeters, months_options, delimeters, year_options))
            date_formats_options += list(
                itertools.product(day_options, delimeters, months_options, delimeters, year_options))

        self.date_formats_options = map(lambda x: "".join(x), date_formats_options)

    def try_parsing_date(self, text):
        for fmt in self.date_formats_options:
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                pass
        return None

    def has_valid_date(self, text):
        parts = []  # type: List[str]
        for sep in self.common_separators:
            parts += text.split(sep)
        return any(map(lambda x: self.try_parsing_date(x) is not None, parts))

    @staticmethod
    def is_datetime_last_years(d, number_of_years=3):
        if d is not None:
            now = datetime.now()
            return now - timedelta(days=365 * number_of_years) <= d <= now + timedelta(days=365 * number_of_years)
        return False

    @staticmethod
    def safe_parse_timestamp(value):
        try:
            d = datetime.fromtimestamp(int(value))
            return d
        except Exception:
            return None

    def is_unix_timestamp(self, value):
        try:
            value = int(value)
            return self.is_datetime_last_years(self.safe_parse_timestamp(value)) or self.is_datetime_last_years(
                self.safe_parse_timestamp(value / 1000))
        except Exception:
            return False


class Validator:

    def __init__(self):
        self.EMAIL_REGEX = re.compile('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$')
        self.NUMBER_REGEX = re.compile('^([0-9]+)$')
        self.SHA256_REGEX = re.compile('^[A-Fa-f0-9]{64}$')
        self.MD5_REGEX = re.compile('^[a-fA-F0-9]{32}$')
        self.HASH_REGEX = re.compile('^[a-fA-F0-9]+$')
        self.MAC_REGEX = re.compile('^[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$', re.IGNORECASE)
        self.URL_REGEX = re.compile(
            r'^(?:http|ftp|hxxp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        self.COMMON_NAME_CHARECTERS = re.compile('^[0-9a-zA-Z"\s_\-\'.]+$')
        self.HOSTNAME_PART_REGEX = re.compile('(?!-)[A-Z\d-]{1,63}(?<!-)$')
        self.FULL_FILE_PATH_REGEX = re.compile('^((?:/[^/\n]+)*|.*(\\\\.*))$')
        self.date_validator = DateValidator()

    def validate_regex(self, pattern, value, json_field_name=None):
        if isinstance(value, basestring):
            return pattern.match(value) is not None
        return False

    def validate_ip(self, field_name, value, json_field_name=None):
        try:
            socket.inet_aton(value)
            return True
        except socket.error:
            return False

    def validate_url(self, field_name, value, json_field_name=None):
        return self.validate_regex(self.URL_REGEX, value)

    def validate_email(self, field_name, value, json_field_name=None):
        return self.validate_regex(self.EMAIL_REGEX, value)

    def validate_number(self, field_name, value, json_field_name=None):
        if isinstance(value, numbers.Number):
            return True
        else:
            return self.validate_regex(self.NUMBER_REGEX, value, json_field_name=None)

    def validate_not_count(self, field_name, value):
        is_count = COUNT_KEYWORD in field_name.lower() and self.validate_number(field_name, value)
        return not is_count

    def validate_sha256(self, field_name, value, json_field_name=None):
        return self.validate_regex(self.SHA256_REGEX, value)

    def validate_md5(self, field_name, value, json_field_name=None):
        return self.validate_regex(self.MD5_REGEX, value)

    def validate_hash(self, field_name, value, json_field_name=None):
        return self.validate_regex(self.HASH_REGEX, value) and len(value) % 2 == 0

    def validate_mac(self, field_name, value, json_field_name=None):
        return self.validate_regex(self.MAC_REGEX, value)

    def validate_hostname(self, field_name, hostname, json_field_name=None):
        if not isinstance(hostname, basestring) or len(hostname) > 255:  # type: ignore
            return False
        if hostname[-1] == ".":  # type: ignore
            hostname = hostname[:-1]  # type: ignore
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    def validate_date(self, field_name, value, json_field_name=None):
        if self.validate_number("", value):
            return self.date_validator.is_unix_timestamp(value)
        else:
            return self.date_validator.has_valid_date(value)

    def validate_alphanumeric_with_common_punct(self, field_name, value, json_field_name=None):
        return self.validate_regex(self.COMMON_NAME_CHARECTERS, value)

    def validate_file_full_path(self, field_name, value, json_field_name=None):
        return self.validate_regex(self.FULL_FILE_PATH_REGEX, value)

    def extact_name_math(self, field_name, value, json_field_name=None):
        return field_name == json_field_name

    def validate(self, validator_name, field_name, value, json_field_name=None):
        validate_func = getattr(self, validator_name)
        return validate_func(field_name, value, json_field_name)


def is_sublist_of_list(s, lst):
    sub_set = False
    if s == []:
        sub_set = True
    elif s == lst:
        sub_set = True
    elif len(s) > len(lst):
        sub_set = False
    else:
        for i in range(len(lst)):
            if lst[i] == s[0]:
                n = 1
                while (n < len(s)) and (i + n) < len(lst) and (lst[i + n] == s[n]):
                    n += 1

                if n == len(s):
                    sub_set = True

    return sub_set


def lemma_word(word):
    for suffix in suffix_mapping:
        if word.endswith(suffix):
            candidate = word[:-len(suffix)] + suffix_mapping[suffix]
            if candidate in ALL_POSSIBLE_TERMS_SET or candidate.lower() in ALL_POSSIBLE_TERMS_SET:
                return candidate.lower()
    return word.lower()


def remove_dups(seq):
    return list(OrderedDict.fromkeys(seq))


def split_by_non_alpha_numeric(_string):
    return filter(lambda x: x, re.split('[^a-zA-Z0-9]', _string))


def camel_case_split(identifier):
    matches = re.finditer('.+?(?:(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|$)', identifier)
    return [m.group(0) for m in matches]


def flatten_json(y):
    out = {}
    has_more_than_one_value = []
    delimeter = '.'

    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + delimeter)
        elif type(x) is list and len(x) > 0 and type(x) is not dict:
            i = 0
            for a in x:
                flatten(a, name + "[" + str(i) + "]" + delimeter)
                i += 1
            if i > 1:
                has_more_than_one_value.append(name[:-1])
        else:
            out[name[:-1]] = x

    flatten(y)
    return out, has_more_than_one_value


def number_of_terms(value):
    return len(value.split(" "))


def normilize(value):
    parts = []  # type: List[str]
    for part in split_by_non_alpha_numeric(value):
        parts += camel_case_split(part)
    terms = map(lemma_word, parts)
    return remove_dups(terms)


def validate_value_with_validator(alias, value, json_field_name=None):
    field_name = ALIASING_MAP[alias]
    validators = SIEM_FIELDS[field_name]['validators']  # type: ignore
    validators = [v for v in validators if v]
    if len(validators) == 0:
        return True
    validator_results = []
    for validator_name in validators:
        validator_results.append(VALIDATOR.validate(validator_name, alias, value, json_field_name))
    return all(validator_results)


def get_candidates(json_field_name):
    json_field_terms = normilize(json_field_name)
    aliases_terms = ALIASING_TERMS_MAP.items()
    match_terms = map(lambda x: x[0],
                      filter(lambda alias_terms: is_sublist_of_list(alias_terms[1], json_field_terms), aliases_terms))
    return sorted(match_terms, reverse=True, key=number_of_terms)


def suggest_field_with_alias(json_field_name, json_field_value=None):
    norm_json_field_name = " ".join(normilize(json_field_name))
    candidates = get_candidates(json_field_name)
    if json_field_value is not None:
        candidates = filter(lambda c: validate_value_with_validator(c, json_field_value, norm_json_field_name),
                            candidates)
    if len(candidates) > 0:
        alias = candidates[0]
        return ALIASING_MAP[alias], alias
    return None, None


def suggest_field(json_field_name, json_field_value=None):
    return suggest_field_with_alias(json_field_name, json_field_value)[0]


def get_aliasing(siem_fields):
    aliasing_map = {}
    aliases_terms_map = {}
    for field, data in siem_fields.items():
        for alias in data['aliases']:
            aliasing_map[alias] = field
            aliases_terms_map[alias] = alias.split(" ")
    return aliasing_map, aliases_terms_map


def is_value_substring_of_one_values(value, all_values):
    return any(map(lambda field: value in field, all_values))


def get_alias_index(field_name, alias):
    return SIEM_FIELDS[field_name]['aliases'].index(alias)  # type: ignore


def get_most_relevant(field_name, field_mappings):
    candidates = sorted(field_mappings, key=lambda x: get_alias_index(field_name, x[1]))
    return candidates[0]


def match_for_incident(incident_to_match):
    flat_incident, more_than_one_field_items = flatten_json(incident_to_match)
    incident = {k: v for k, v in flat_incident.items()
                if not is_value_substring_of_one_values(k, more_than_one_field_items)}
    if SCHEME_ONLY:
        incident = {k: v for k, v in incident.items() if not k.endswith(COUNT_KEYWORD)}
    else:
        incident = {k: v for k, v in incident.items() if v is not None and VALIDATOR.validate_not_count(k, v)}

    mapping = {}  # type: ignore
    for json_field_name, json_field_value in incident.items():
        if SCHEME_ONLY or json_field_value:
            suggestion, alias = suggest_field_with_alias(json_field_name, json_field_value)
            if suggestion:
                if suggestion not in mapping:
                    mapping[suggestion] = []
                mapping[suggestion].append((json_field_name, alias))
    return {k: get_most_relevant(k, v)[0] for k, v in mapping.items()}


def jaccard_similarity(list1, list2):
    intersection = len(list(set(list1).intersection(list2)))
    union = (len(list1) + len(list2)) - intersection
    return float(intersection) / union


def jaccard_similarity_for_string_terms(str1, str2):
    return jaccard_similarity(normilize(str1), normilize(str2))


def get_most_relevant_match_for_field(field_name, cnt):
    # return exact match
    if field_name in cnt:
        return field_name

    suggestions_with_jaccard_score = [(suggestion, jaccard_similarity_for_string_terms(field_name, suggestion)) for
                                      suggestion in cnt.keys()]
    suggestions_with_jaccard_score = sorted(suggestions_with_jaccard_score, key=lambda x: x[1], reverse=True)

    # check for extact terms
    if suggestions_with_jaccard_score[0][1] == 1:
        return suggestions_with_jaccard_score[0][0]

    # if we have only scheme or all the values are the same
    if SCHEME_ONLY or len(set(cnt.values())) == 1:
        return suggestions_with_jaccard_score[0][0]

    return cnt.most_common()[0][0]


def match_for_incidents(incidents_to_match):
    fields_cnt = {}  # type: Dict[str, Counter]
    for flat_incident in incidents_to_match:
        for k, v in match_for_incident(flat_incident).items():
            if k not in fields_cnt:
                fields_cnt[k] = Counter()
            fields_cnt[k][v] += 1
    mapping_result = {field_name: get_most_relevant_match_for_field(field_name, field_cnt) for field_name, field_cnt in
                      fields_cnt.items()}
    return mapping_result


def format_value_to_mapper(json_field):
    parts = json_field.split('.', 1)
    root = parts[0]
    accessor = ""
    if len(parts) > 1:
        accessor = parts[1]
    res = {
        "simple": "",
        "complex": {
            "root": root,
            "accessor": accessor,
            "filters": [],
            "transformers": []
        }
    }
    return res


def format_incident_field_to_mapper(incident_field_name, field_name_to_machine_name):
    res = {
        "simple": "",
        "complex": {
            "root": field_name_to_machine_name[incident_field_name],
            "accessor": "",
            "filters": [],
            "transformers": []
        }
    }
    return res


def verify_non_empty_values_in_incidents(expression, incidents):
    for incident in incidents:
        res = demisto.dt(incident, expression)
        if res:
            return True
    return False


def get_complex_value_key(complex_value):
    if 'complex' in complex_value:
        complex_value = complex_value['complex']
    readable_value = complex_value.get('root')
    if complex_value.get('accessor'):
        readable_value += "." + complex_value.get('accessor')
    return readable_value


def combine_mappers(original_mapper, new_mapper, incidents):
    mapper = new_mapper
    if original_mapper:
        mapper.update(original_mapper)
    return mapper


def filter_by_dict_by_keys(_dict, keys):
    return {k: v for k, v in _dict.items() if k in keys}


def parse_incident_sample(sample):
    if type(sample) is dict and 'rawJSON' in sample:
        incident = json.loads(sample['rawJSON'])
    else:
        try:
            incident = json.loads(sample)
        except Exception:
            incident = sample
    return incident


SCHEME_ONLY = False
VALIDATOR = Validator()
ALIASING_MAP, ALIASING_TERMS_MAP, FIELD_NAME_TO_CLI_NAME = {}, {}, {}
ALL_POSSIBLE_TERMS_SET = set()


def init():
    global SCHEME_ONLY, VALIDATOR, \
        ALIASING_MAP, ALIASING_TERMS_MAP, \
        ALL_POSSIBLE_TERMS_SET, SIEM_FIELDS, FIELD_NAME_TO_CLI_NAME

    SCHEME_ONLY = demisto.args().get('incidentSamplesType') in [SAMPLES_OUTGOING, SAMPLES_SCHEME]

    fields = demisto.args().get('incidentFields', {})
    if fields and len(fields) > 0:
        fields_names = map(lambda x: x['name'], fields)
        SIEM_FIELDS = filter_by_dict_by_keys(SIEM_FIELDS, fields_names)

    FIELD_NAME_TO_CLI_NAME = {field[INCIDENT_FIELD_NAME]: field[INCIDENT_FIELD_MACHINE_NAME] for field in fields}

    ALIASING_MAP, ALIASING_TERMS_MAP = get_aliasing(SIEM_FIELDS)

    terms = []  # type: List[str]
    for field in SIEM_FIELDS.values():
        for alias in field['aliases']:  # type: ignore
            terms += alias.split(" ")
    ALL_POSSIBLE_TERMS_SET = set(terms)


def main():
    init()
    incidents_samples = demisto.args().get('incidentSamples')
    if incidents_samples:
        if isinstance(incidents_samples, basestring):
            incidents_samples = json.loads(incidents_samples)  # type: ignore
        incidents = map(parse_incident_sample, incidents_samples)
    else:
        return_error("Could not parse incident samples")

    original_mapper = demisto.args().get('currentMapper')
    if type(original_mapper) is not dict or len(original_mapper) == 0:
        original_mapper = None

    matches = match_for_incidents(incidents)
    if demisto.args().get('incidentSamplesType') == SAMPLES_OUTGOING:
        mapper = {v: format_incident_field_to_mapper(k, FIELD_NAME_TO_CLI_NAME) for k, v in matches.items() if
                  k in FIELD_NAME_TO_CLI_NAME}
    else:
        mapper = {k: format_value_to_mapper(v) for k, v in matches.items()}
    mapper = combine_mappers(original_mapper, mapper, incidents)

    return mapper


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
