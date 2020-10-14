import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pandas as pd
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from numpy import dot
from numpy.linalg import norm
from email.utils import parseaddr
import tldextract

no_fetch_extract = tldextract.TLDExtract(suffix_list_urls=None)
pd.options.mode.chained_assignment = None  # default='warn'

SIMILARITY_THRESHOLD = 0.99

EMAIL_BODY_FIELD = 'emailbody'
EMAIL_SUBJECT_FIELD = 'emailsubject'
EMAIL_HTML_FIELD = 'emailbodyhtml'
CREATED_FIELD = 'created'
FROM_FIELD = 'emailfrom'
FROM_DOMAIN_FIELD = 'fromdomain'
MERGED_TEXT_FIELD = 'mereged_text'
MIN_TEXT_LENGTH = 50
DEFAULT_ARGS = {
    'limit': '1000',
    'incidentTypes': 'Phishing',
    'exsitingIncidentsLookback': '100 days ago',
}
FROM_POLICY_TEXT_ONLY = 'TextOnly'
FROM_POLICY_EXACT = 'Exact'
FROM_POLICY_DOMAIN = 'Domain'

FROM_POLICY = FROM_POLICY_TEXT_ONLY


def get_existing_incidents(input_args):
    global DEFAULT_ARGS
    get_incidents_args = {}
    for arg in ['incidentTypes', 'query', 'limit']:
        if arg in input_args:
            get_incidents_args[arg] = input_args[arg]
        elif arg in DEFAULT_ARGS:
            get_incidents_args[arg] = DEFAULT_ARGS[arg]
    if 'exsitingIncidentsLookback' in input_args:
        get_incidents_args['fromDate'] = input_args['exsitingIncidentsLookback']
    elif 'exsitingIncidentsLookback' in DEFAULT_ARGS:
        get_incidents_args['fromDate'] = DEFAULT_ARGS['exsitingIncidentsLookback']
    status_scope = input_args.get('statusScope', 'All')
    if status_scope == 'ClosedOnly':
        if 'query' in get_incidents_args:
            get_incidents_args['query'] = '({}) and (status:Closed)'.format(get_incidents_args['query'])
        else:
            get_incidents_args['query'] = 'status:Closed'
    elif status_scope == 'NonClosedOnly':
        if 'query' in get_incidents_args:
            get_incidents_args['query'] = '({}) and (-status:Closed)'.format(get_incidents_args['query'])
        else:
            get_incidents_args['query'] = '-status:Closed'
    incidents_query_res = demisto.executeCommand('GetIncidentsByQuery', get_incidents_args)
    if is_error(incidents_query_res):
        return_error(get_error(incidents_query_res))
    incidents = json.loads(incidents_query_res[-1]['Contents'])
    return incidents


def extract_domain(address):
    global no_fetch_extract
    if address == '':
        return ''
    email_address = parseaddr(address)[1]
    ext = no_fetch_extract(email_address)
    return ext.domain


def get_text_from_html(html):
    # todo: change to docker which supports
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


def preprocess_text_fields(incident):
    email_body = email_subject = email_html = ''
    if EMAIL_BODY_FIELD in incident:
        email_body = incident[EMAIL_BODY_FIELD]
    if EMAIL_HTML_FIELD in incident:
        email_html = incident[EMAIL_HTML_FIELD]
    if EMAIL_SUBJECT_FIELD in incident:
        email_subject = incident[EMAIL_SUBJECT_FIELD]
    if isinstance(email_html, float):
        email_html = ''
    if email_body is None or isinstance(email_body, float) or email_body.strip() == '':
        email_body = get_text_from_html(email_html)
    if isinstance(email_subject, float):
        email_subject = ''
    return email_subject + ' ' + email_body


def preprocess_incidents_df(existing_incidents):
    global MERGED_TEXT_FIELD, FROM_FIELD, FROM_DOMAIN_FIELD
    incidents_df = pd.DataFrame(existing_incidents)
    incidents_df['CustomFields'] = incidents_df['CustomFields'].fillna(value={})
    custom_fields_df = incidents_df['CustomFields'].apply(pd.Series)
    unique_keys = [k for k in custom_fields_df if k not in incidents_df]
    custom_fields_df = custom_fields_df[unique_keys]
    incidents_df = pd.concat([incidents_df.drop('CustomFields', axis=1),
                              custom_fields_df], axis=1).reset_index()
    incidents_df[MERGED_TEXT_FIELD] = incidents_df.apply(lambda x: preprocess_text_fields(x), axis=1)
    incidents_df = incidents_df[incidents_df[MERGED_TEXT_FIELD].str.len() >= MIN_TEXT_LENGTH]
    incidents_df.reset_index(inplace=True)
    if FROM_FIELD in incidents_df:
        incidents_df[FROM_FIELD] = incidents_df[FROM_FIELD].fillna(value='')
    else:
        incidents_df[FROM_FIELD] = ''
    incidents_df[FROM_FIELD] = incidents_df[FROM_FIELD].apply(lambda x: x.strip())
    incidents_df[FROM_DOMAIN_FIELD] = incidents_df[FROM_FIELD].apply(lambda address: extract_domain(address))
    return incidents_df


def filter_out_new_incident(existing_incidents_df, new_incident):
    same_id_mask = existing_incidents_df['id'] == new_incident['id']
    existing_incidents_df = existing_incidents_df[~same_id_mask]
    return existing_incidents_df


def vectorize(text, vectorizer):
    return vectorizer.transform([text]).toarray()[0]


def cosine_sim(a, b):
    return dot(a, b) / (norm(a) * norm(b))


def find_duplicate_incidents(new_incident, existing_incidents_df):
    global MERGED_TEXT_FIELD, FROM_POLICY
    new_incident_text = new_incident[MERGED_TEXT_FIELD]
    text = [new_incident_text] + existing_incidents_df[MERGED_TEXT_FIELD].tolist()
    vectorizer = TfidfVectorizer(token_pattern=r"(?u)\b\w\w+\b|!|\?|\"|\'").fit(text)
    new_incident_vector = vectorize(new_incident_text, vectorizer)
    existing_incidents_df['vector'] = existing_incidents_df[MERGED_TEXT_FIELD].apply(lambda x: vectorize(x, vectorizer))
    existing_incidents_df['similarity'] = existing_incidents_df['vector'].apply(
        lambda x: cosine_sim(x, new_incident_vector))
    if FROM_POLICY == FROM_POLICY_DOMAIN:
        mask = (existing_incidents_df[FROM_DOMAIN_FIELD] != '') & \
               (existing_incidents_df[FROM_DOMAIN_FIELD] == new_incident[FROM_DOMAIN_FIELD])
        existing_incidents_df = existing_incidents_df[mask]
    elif FROM_POLICY == FROM_POLICY_EXACT:
        mask = (existing_incidents_df[FROM_FIELD] != '') & \
               (existing_incidents_df[FROM_FIELD] == new_incident[FROM_FIELD])
        existing_incidents_df = existing_incidents_df[mask]
    existing_incidents_df.sort_values(by='similarity', ascending=False, inplace=True)
    if len(existing_incidents_df) > 0:
        return existing_incidents_df.iloc[0], existing_incidents_df.iloc[0]['similarity']
    else:
        return None, None


def close_new_incident_and_link_to_existing(new_incident, existing_incident, similarity):
    entries = []
    hr_incident = {}
    for field in [EMAIL_SUBJECT_FIELD, EMAIL_BODY_FIELD, EMAIL_HTML_FIELD, FROM_FIELD, CREATED_FIELD, 'name', 'id']:
        if field in new_incident:
            hr_incident[field] = new_incident[field]
    hr = tableToMarkdown('Duplicate Incident Details', hr_incident)
    entries.append({'Contents': "Duplicate incident: " + new_incident['name']})
    entries.append({"Type": entryTypes['note'],
                    "ContentsFormat": "json",
                    "Contents": hr_incident,
                    "HumanReadable": hr,
                    })
    entries_str = json.dumps(entries)
    demisto.executeCommand("addEntries", {"id": existing_incident["id"], "entries": entries_str})
    res = demisto.executeCommand("linkIncidents", {
        'linkedIncidentIDs': new_incident['id'],
        'incidentId': existing_incident['id']})
    if is_error(res):
        return_error(res)
    demisto.results('Duplicate incident found: {}, {} with similarity of {:.1f}%.'.format(new_incident['id'],
                                                                                          existing_incident['id'],
                                                                                          similarity * 100))


def create_new_incident():
    demisto.results('No duplicate incident found')


def main():
    global EMAIL_BODY_FIELD, EMAIL_SUBJECT_FIELD, EMAIL_HTML_FIELD, FROM_FIELD, MIN_TEXT_LENGTH, FROM_POLICY
    input_args = demisto.args()
    EMAIL_BODY_FIELD = input_args.get('emailBody', EMAIL_BODY_FIELD)
    EMAIL_SUBJECT_FIELD = input_args.get('emailSubject', EMAIL_SUBJECT_FIELD)
    EMAIL_HTML_FIELD = input_args.get('emailBodyHTML', EMAIL_HTML_FIELD)
    FROM_FIELD = input_args.get('emailFrom', FROM_FIELD)
    FROM_POLICY = input_args.get('fromPolicy', FROM_POLICY)
    existing_incidents = get_existing_incidents(input_args)
    if len(existing_incidents) == 0:
        create_new_incident()
        return
    new_incident = demisto.incidents()[0]
    new_incident_df = preprocess_incidents_df([new_incident])
    existing_incidents_df = preprocess_incidents_df(existing_incidents)
    existing_incidents_df = filter_out_new_incident(existing_incidents_df, new_incident)

    if len(existing_incidents_df) == 0 or len(
            new_incident_df) == 0:  # len(new_incident_df)==0 means new incident is too short
        create_new_incident()
        return
    new_incident_preprocessed = new_incident_df.iloc[0].to_dict()
    duplicate_incident_row, similarity = find_duplicate_incidents(new_incident_preprocessed,
                                                                  existing_incidents_df)
    if duplicate_incident_row is None or similarity < SIMILARITY_THRESHOLD:
        create_new_incident()
    else:
        return close_new_incident_and_link_to_existing(new_incident_df.iloc[0], duplicate_incident_row, similarity)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
