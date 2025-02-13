import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import itertools
from collections import Counter

import dateutil
from nltk import sent_tokenize, word_tokenize
from CommonServerUserPython import *
import pandas as pd
import numpy as np
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import CountVectorizer
from numpy import dot
from numpy.linalg import norm
from email.utils import parseaddr
import tldextract
import pytz


no_fetch_extract = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=False)  # type: ignore[arg-type]
utc = pytz.UTC

SELF_IN_CONTEXT = False
EMAIL_BODY_FIELD = 'emailbody'
EMAIL_SUBJECT_FIELD = 'emailsubject'
EMAIL_HTML_FIELD = 'emailbodyhtml'
FROM_FIELD = 'emailfrom'
FROM_DOMAIN_FIELD = 'fromdomain'
PREPROCESSED_EMAIL_BODY = 'preprocessedemailbody'
PREPROCESSED_EMAIL_SUBJECT = 'preprocessedemailsubject'
MERGED_TEXT_FIELD = 'mereged_text'
EMAIL_TO_FIELD = 'emailto'
EMAIL_CC_FIELD = 'emailcc'
EMAIL_BCC_FIELD = 'emailbcc'
RECIPIENTS_COLUMNS = [EMAIL_TO_FIELD, EMAIL_CC_FIELD, EMAIL_BCC_FIELD]
MIN_CAMPAIGN_SIZE = int(demisto.args().get("minIncidentsForCampaign", 3))
MIN_UNIQUE_RECIPIENTS = int(demisto.args().get("minUniqueRecipients", 2))
DUPLICATE_SENTENCE_THRESHOLD = 0.95
TO_PLOT_CANVAS = demisto.args().get("plotCanvas", 'false') == 'true'
MAX_INCIDENTS_FOR_CANVAS_PLOTTING = 6
MAX_INDICATORS_FOR_CANVAS_PLOTTING = 10
KEYWORDS = ['#1', '100%', 'access', 'accordance', 'account', 'act', 'action', 'activate', 'ad', 'affordable', 'amazed',
            'amazing', 'apply', 'asap', 'asked', 'attach', 'attached', 'attachment', 'attachments', 'attention',
            'authorize', 'authorizing', 'avoid', 'bank', 'bargain', 'billing', 'bonus', 'boss', 'bucks', 'bulk', 'buy',
            "can't", 'cancel', 'candidate', 'capacity', 'card', 'cards', 'cash', 'casino', 'caution', 'cents',
            'certified', 'chance', 'charges', 'claim', 'claims', 'clearance', 'click', 'collect', 'confidentiality',
            'confirm', 'confirmation', 'confirmed', 'congratulations', 'consideration', 'consolidate', 'consultation',
            'contact', 'contract', 'credentials', 'credit', 'day', 'days', 'deadline', 'deal', 'deals', 'dear', 'debt',
            'delivered', 'delivery', 'deposit', 'detected', 'dhl', 'disabled', 'discount', 'discounts', 'document',
            'documents', 'dollar', 'dollars', 'dropbox', 'drugs', 'due', 'earn', 'earnings', 'enlarge', 'enlargement',
            'equity', 'erection', 'erections', 'exclusive', 'expire', 'expires', 'fedex', 'fees', 'file', 'finance',
            'financial', 'fraud', 'free', 'friend', 'from', 'funds', 'gas', 'gift', 'gimmick', 'giveaway', 'great',
            'growth', 'guarantee', 'guaranteed', 'hack', 'hacked', 'hacker', 'hormone', 'hosting', 'hours', 'hurry',
            'immediate', 'immediately', 'important', 'income', 'increase', 'instant', 'interest', 'investment',
            'invoice', 'kindly', 'last', 'lender', 'lenders', 'lifetime', 'limited', 'loan', 'loans', 'login', 'lose',
            'loss', 'luxury', 'market', 'marketing', 'mass', 'mastrubate', 'mastrubating', 'med', 'medications',
            'medicine', 'meds', 'member', 'membership', 'million', 'millions', 'miracle', 'money', 'monthly',
            'months', 'mortgage', 'newsletter', 'notification', 'notify', 'obligation', 'offer', 'offers', 'oil',
            'only', 'open', 'opt', 'order', 'package', 'paid', 'parcel', 'partners', 'password', 'passwords',
            'payment', 'payments', 'paypal', 'payroll', 'pdf', 'penis', 'pennies', 'permanently', 'pharmacy', 'pics',
            'pictures', 'pill', 'pills', 'porn', 'porno', 'postal', 'potential', 'pre-approved', 'presently',
            'preview', 'price', 'prize', 'profit', 'promise', 'promotion', 'purchase', 'pure', 'qualifies', 'qualify',
            'quote', 'rates', 'receipt', 'record', 'recorded', 'recording', 'refund', 'request', 'requested',
            'requires', 'reserve', 'reserves', 'review', 'risk', 'sales', 'satisfactin', 'satisfaction', 'satisfied',
            'save', 'scam', 'security', 'sensitive', 'sex', 'share', 'shared', 'sharing', 'shipment', 'shipping',
            'sir', 'spam', 'special', 'spend', 'spending', 'started', 'starting', 'stock', 'success', 'supplies',
            'supply', 'suspended', 'temporarily', 'terms', 'trader', 'trading', 'traffic', 'transaction', 'transfer',
            'trial', 'unlimited', 'unsecured', 'unsolicited', 'unsubscribe', 'update', 'ups', 'urgent', 'user', 'usps',
            'valium', 'verification', 'verify', 'viagra', 'vicodin', 'videos', 'vids', 'viedo', 'virus', 'waiting',
            'wallet', 'warranty', 'web', 'weight', 'win', 'winner', 'winning', 'wire', 'xanax']

STATUS_DICT = {
    0: "Pending",
    1: "Active",
    2: "Closed",
    3: "Archive",
}

INVALID_KEY_WARNING = 'Warning: the fields {fields} was not found in the phishing incidents. Please make sure that ' \
                      'you\'ve specified the machine-name of the fields. The machine name can be found in the ' \
                      'settings of the incident field you are trying to search.'

INCIDENTS_CONTEXT_TD = 'incidents(obj.id == val.id)'


def return_outputs_custom(readable_output, outputs=None, tag=None):
    return_entry = {
        "Type": entryTypes["note"],
        "HumanReadable": readable_output,
        "ContentsFormat": formats['json'],
        "Contents": outputs,
        "EntryContext": outputs,
    }
    if tag is not None:
        return_entry["Tags"] = [f'campaign_{tag}']
    demisto.results(return_entry)


def add_context_key(entry_context):
    new_context = {}
    for k, v in entry_context.items():
        new_context['{}.{}'.format('EmailCampaign', k)] = v
    return new_context


def get_recipients(row):
    global RECIPIENTS_COLUMNS
    return list(itertools.chain(*[row[col] for col in RECIPIENTS_COLUMNS]))


def extract_domain(address):
    global no_fetch_extract
    if address == '':
        return ''
    email_address = parseaddr(address)[1]
    ext = no_fetch_extract(email_address)
    return f'{ext.domain}.{ext.suffix}'


def extract_domain_from_recipients(row):
    domains_list = []
    for address in row['recipients']:
        try:
            domain = extract_domain(address)
        except Exception:
            domain = ''
        domains_list.append(domain)
    return domains_list


def create_context_for_campaign_details(campaign_found=False, incidents_df=None,
                                        additional_context_fields: list = None):
    if not campaign_found:
        return {
            'isCampaignFound': campaign_found,
        }
    else:
        incident_id = demisto.incident()['id']
        incidents_df['recipients'] = incidents_df.apply(lambda row: get_recipients(row), axis=1)
        incidents_df['recipientsdomain'] = incidents_df.apply(lambda row: extract_domain_from_recipients(row), axis=1)
        if 'removedfromcampaigns' not in incidents_df.columns.tolist():
            incidents_df['removedfromcampaigns'] = pd.NA

        incidents_df['removedfromcampaigns'] = incidents_df['removedfromcampaigns'].apply(lambda x: [] if pd.isna(x) else x)
        context_keys = {'id', 'similarity', FROM_FIELD, FROM_DOMAIN_FIELD, 'recipients', 'recipientsdomain',
                        'removedfromcampaigns'}
        invalid_context_keys = set()
        if additional_context_fields is not None:
            for key in additional_context_fields:
                if key in incidents_df.columns:
                    context_keys.add(key)
                else:
                    invalid_context_keys.add(key)

        if invalid_context_keys:
            return_warning(INVALID_KEY_WARNING.format(fields=invalid_context_keys))

        incidents_context_df = incidents_df.copy(deep=True)
        incident_df = incidents_context_df[list(context_keys)]  # lgtm [py/hash-unhashable-value]
        if not SELF_IN_CONTEXT:
            incident_df = incident_df[incident_df['id'] != incident_id]

        incident_df = incident_df.rename({FROM_DOMAIN_FIELD: 'emailfromdomain'}, axis=1)
        incidents_context = incident_df.fillna(1).to_dict(orient='records')
        datetimes: pd.DataFrame = incidents_context_df['created_dt'].dropna()
        min_datetime = min(datetimes).isoformat()
        return {
            'isCampaignFound': campaign_found,
            'involvedIncidentsCount': len(incidents_context_df) if incidents_context_df is not None else 0,
            'firstIncidentDate': min_datetime,
            'fieldsToDisplay': additional_context_fields,
            INCIDENTS_CONTEXT_TD: incidents_context
        }


def create_context_for_indicators(indicators_df=None):
    if indicators_df is None:
        indicators_context = []
    else:
        indicators_df = indicators_df.rename({'Value': 'value'}, axis=1)
        indicators_df = indicators_df[['id', 'value']]
        indicators_context = indicators_df.to_dict(orient='records')
    return {'indicators': indicators_context}


def create_empty_context():
    context = create_context_for_campaign_details(campaign_found=False)
    context = add_context_key(context)
    return context


def is_number_of_incidents_too_low(res, incidents):
    if not res["EntryContext"]['isDuplicateIncidentFound'] or \
            len(incidents) < MIN_CAMPAIGN_SIZE:
        return_outputs_custom('No possible campaign was detected', create_empty_context())
        return True
    return False


def is_number_of_unique_recipients_is_too_low(incidents):
    unique_recipients = Counter([str(i.get(EMAIL_TO_FIELD, 'None')) for i in incidents])
    unique_recipients += Counter([str(i[EMAIL_CC_FIELD]) for i in incidents if EMAIL_CC_FIELD in i])
    unique_recipients += Counter([str(i[EMAIL_BCC_FIELD]) for i in incidents if EMAIL_BCC_FIELD in i])
    missing_recipients = unique_recipients['None']
    unique_recipients.pop('None', None)
    if (len(unique_recipients) < MIN_UNIQUE_RECIPIENTS and missing_recipients == 0) or \
            (0 < len(unique_recipients) < MIN_UNIQUE_RECIPIENTS and missing_recipients > 0):
        msg = 'Similar emails were found, but the number of their unique recipients is too low to consider them as ' \
              'campaign.\n '
        msg += 'If you wish to consider similar emails as campaign even with low number of unique recipients, ' \
               'please change *minUniqueRecipients* argument\'s value.\n'
        msg += 'Details:\n'
        msg += f'* Found {len(incidents)} similar incidents.\n'
        msg += f'* Those incidents have {len(unique_recipients)} unique recipients'
        msg += ' ({}).\n'.format(', '.join(unique_recipients))
        msg += '* The minimum number of unique recipients for similar emails as campaign: ' \
               '{}\n'.format(MIN_UNIQUE_RECIPIENTS)
        if missing_recipients > 0:
            msg += '* Could not find email recipient for {}/{} incidents ' \
                   '(*Email To* field is empty)'.format(missing_recipients, len(incidents))

        return_outputs_custom(msg, create_empty_context())
        return True
    return False


def get_str_representation_top_n_values(values_list, counter_tuples_list, top_n):
    domains_counter_top = counter_tuples_list[:top_n]
    if len(counter_tuples_list) > top_n:
        domains_counter_top += [('Other', len(values_list) - sum(x[1] for x in domains_counter_top))]
    return ', '.join(f'{domain} ({count})' for domain, count in domains_counter_top)


def standardize_recipients_column(df, column):
    if column not in df.columns:
        df[column] = [[] for _ in range(len(df))]
        return df
    df[column] = df[column].apply(argToList)
    df[column] = df[column].apply(lambda x: [value.strip() for value in x if isinstance(value, str)])
    df[column] = df[column].apply(lambda x: [value for value in x if '@' in value])
    return df


def calculate_campaign_details_table(incidents_df, fields_to_display):
    global RECIPIENTS_COLUMNS
    n_incidents = len(incidents_df)
    similarities = incidents_df['similarity'].dropna().to_list()
    max_similarity = max(similarities)
    min_similarity = min(similarities)
    headers = []
    contents = []
    headers.append('Details')
    contents.append(f'Found possible campaign of {n_incidents} similar emails')
    if max_similarity > min_similarity + 10 ** -3:
        headers.append('Similarity range')
        contents.append("{:.1f}%-{:.1f}%".format(min_similarity * 100, max_similarity * 100))
    else:
        headers.append('Similarity')
        contents.append("{:.1f}%".format(max_similarity * 100))
    incidents_df['created_dt'] = incidents_df['created'].apply(lambda x: dateutil.parser.parse(x))  # type: ignore
    datetimes = incidents_df['created_dt'].dropna()  # type: ignore
    min_datetime, max_datetime = min(datetimes), max(datetimes)
    if (max_datetime - min_datetime).days == 0:
        headers.append('Date')
        contents.append(max_datetime.strftime("%B %d, %Y"))
    else:
        headers.append('Date range')
        contents.append('{} - {}'.format(min_datetime.strftime("%B %d, %Y"), max_datetime.strftime("%B %d, %Y")))
    senders = incidents_df[FROM_FIELD].dropna().replace('', np.nan).tolist()
    senders_counter = Counter(senders).most_common()  # type: ignore
    senders_domain = incidents_df[FROM_DOMAIN_FIELD].replace('', np.nan).dropna().tolist()
    domains_counter = Counter(senders_domain).most_common()  # type: ignore
    for column in RECIPIENTS_COLUMNS:
        incidents_df = standardize_recipients_column(incidents_df, column)
    recipients = []
    for column in RECIPIENTS_COLUMNS:
        for incidents_recipient in incidents_df[column]:
            recipients += incidents_recipient
    recipients_counter = Counter(recipients).most_common()  # type: ignore
    if len(senders_counter) == 1:
        domain_header = "Sender domain"
        sender_header = "Sender address"
    elif len(senders_counter) > 1 and len(domains_counter) == 1:
        domain_header = "Senders domain"
        sender_header = "Senders addresses"
    else:
        domain_header = "Senders domains"
        sender_header = "Senders addresses"
    top_n = 3
    domain_value = get_str_representation_top_n_values(senders_domain, domains_counter, top_n)
    sender_value = get_str_representation_top_n_values(senders, senders_counter, top_n)
    recipients_value = get_str_representation_top_n_values(recipients, recipients_counter, len(recipients_counter))
    headers.append(domain_header)
    contents.append(domain_value)
    headers.append(sender_header)
    contents.append(sender_value)
    headers.append('Recipients')
    contents.append(recipients_value)
    for field in fields_to_display:
        if field in incidents_df.columns:
            field_values = get_non_na_empty_values(incidents_df, field)
            if len(field_values) > 0:
                if field in RECIPIENTS_COLUMNS:
                    field_values = [item for sublist in field_values for item in sublist]
                elif any(isinstance(field_value, list) for field_value in field_values):
                    flattened_list = []
                    for item in field_values:
                        if isinstance(item, list):
                            flattened_list.extend(item)
                        else:
                            flattened_list.append(item)
                    field_values = flattened_list
                field_values_counter = Counter(field_values).most_common()  # type: ignore
                field_value_str = get_str_representation_top_n_values(field_values, field_values_counter, top_n)
                headers.append(field)
                contents.append(field_value_str)
    hr = tableToMarkdown('Possible Campaign Detected', dict(zip(headers, contents)),
                         headers=headers)
    return hr


def get_non_na_empty_values(incidents_df, field):
    field_values = incidents_df[field].replace('', None).dropna().tolist()
    field_values = [x for x in field_values if len(str(x).strip()) > 0]
    return field_values


def cosine_sim(a, b):
    return dot(a, b) / (norm(a) * norm(b))


def summarize_email_body(body, subject, nb_sentences=3, subject_weight=1.5, keywords_weight=1.5):
    corpus: list[str] = sent_tokenize(body)
    cv = CountVectorizer(stop_words=list(stopwords.words('english')))
    body_arr = cv.fit_transform(corpus).toarray()
    subject_arr = cv.transform(sent_tokenize(subject)).toarray()
    word_list = cv.get_feature_names_out()
    count_list = body_arr.sum(axis=0) + subject_arr.sum(axis=0) * subject_weight
    duplicate_sentences = [i for i, arr in enumerate(body_arr) if
                           any(cosine_sim(arr, arr2) > DUPLICATE_SENTENCE_THRESHOLD
                               for arr2 in body_arr[:i])]

    word_frequency = dict(zip(word_list, count_list))
    val = sorted(word_frequency.values())

    max_frequency = val[-1]
    for word in word_frequency:
        word_frequency[word] = (word_frequency[word] / max_frequency)
    for word in KEYWORDS:
        if word in word_frequency:
            word_frequency[word] *= keywords_weight

    sentence_rank = [0] * len(corpus)
    for i, sent in enumerate(corpus):
        if i in duplicate_sentences:
            continue
        for word in word_tokenize(sent):
            if word.lower() in word_frequency:
                sentence_rank[i] += word_frequency[word.lower()]
        sentence_rank[i] = sentence_rank[i] / len(word_tokenize(sent))  # type: ignore
    top_sentences_indices: np.ndarray = np.argsort(sentence_rank)[::-1][:nb_sentences].tolist()  # type: ignore[assignment]
    summary = []
    for sent_i in sorted(top_sentences_indices):  # type: ignore
        sent = corpus[sent_i].strip().replace('\n', ' ')
        if sent_i == 0 and sent_i + 1 not in top_sentences_indices:
            sent = sent + ' ...'
        elif sent_i + 1 == len(corpus) and sent_i - 1 not in top_sentences_indices:
            sent = '... ' + sent
        elif sent_i - 1 not in top_sentences_indices and sent_i + 1 not in top_sentences_indices:
            sent = '... ' + sent + ' ...'
        summary.append(sent)
    return '\n'.join(summary)


def create_email_summary_hr(incidents_df, fields_to_display):
    clean_email_subject = incidents_df.iloc[0][PREPROCESSED_EMAIL_SUBJECT]
    email_summary = '*Subject*: ' + clean_email_subject.replace('\n', '') + ' |'
    clean_email_body = incidents_df.iloc[0][PREPROCESSED_EMAIL_BODY]
    email_summary += '\n*Body*: \n' + summarize_email_body(clean_email_body, clean_email_subject) + ' |'
    for word in KEYWORDS:
        for cased_word in [word.lower(), word.title(), word.upper()]:
            email_summary = re.sub(fr'(?<!\w)({cased_word})(?!\w)', f'**{cased_word}**', email_summary)
    hr_email_summary = '\n' + email_summary
    context = add_context_key(
        create_context_for_campaign_details(
            campaign_found=True,
            incidents_df=incidents_df,
            additional_context_fields=fields_to_display
        )
    )
    return context, hr_email_summary


def horizontal_to_vertical_md_table(horizontal_md_table: str) -> str:
    """
    convert the output of tableToMarkdown to be vertical.
    Args:
        horizontal_md_table: original tableToMarkdown output

    Returns: md string with rotated table
    """
    lines = horizontal_md_table.split('\n')
    headers_list = lines[1][1:-1].split('|')
    content_list = lines[3][1:-1].split('|')

    new_table = '\n| | |'
    new_table += '\n|---|---|'
    for header, content in zip(headers_list, content_list):
        new_table += f"\n|**{header}**|{content}|"

    return new_table


def return_campaign_details_entry(incidents_df, fields_to_display):
    hr_campaign_details = calculate_campaign_details_table(incidents_df, fields_to_display)
    context, hr_email_summary = create_email_summary_hr(incidents_df, fields_to_display)
    hr = '\n'.join([hr_campaign_details, hr_email_summary])
    vertical_hr_campaign_details = horizontal_to_vertical_md_table(hr_campaign_details)
    demisto.executeCommand('setIncident',
                           {'emailcampaignsummary': f"{vertical_hr_campaign_details}",
                            "emailcampaignsnippets": hr_email_summary})
    return return_outputs_custom(hr, context, tag='campaign_details')


def return_no_mututal_indicators_found_entry():
    hr = 'No mutual indicators were found.'

    demisto.executeCommand('setIncident', {'emailcampaignmutualindicators': hr})
    return_outputs_custom(hr, add_context_key(create_context_for_indicators()), tag='indicators')


def return_indicator_entry(incidents_df):
    indicators_query = 'investigationIDs:({})'.format(' '.join(f'"{id_}"' for id_ in incidents_df['id']))
    fields = ['id', 'indicator_type', 'investigationIDs', 'investigationsCount', 'score', 'value']
    search_indicators = IndicatorsSearcher(
        query=indicators_query,
        limit=150,
        size=500,
        filter_fields=','.join(fields)
    )
    indicators = []
    for res in search_indicators:
        indicators.extend(res.get('iocs', []))

    indicators_df = pd.DataFrame(data=indicators)
    if len(indicators_df) == 0:
        return_no_mututal_indicators_found_entry()
        return indicators_df
    indicators_df = indicators_df[indicators_df['relatedIncCount'] < 150]
    indicators_df['Involved Incidents Count'] = \
        indicators_df['investigationIDs'].apply(lambda x: sum(id_ in x for id_ in incidents_df['id']))
    indicators_df = indicators_df[indicators_df['Involved Incidents Count'] > 1]
    if len(indicators_df) == 0:
        return_no_mututal_indicators_found_entry()
        return indicators_df
    indicators_df['Id'] = indicators_df['id'].apply(lambda x: f"[{x}](#/indicator/{x})")
    indicators_df = indicators_df.sort_values(['score', 'Involved Incidents Count'], ascending=False)
    indicators_df['Reputation'] = indicators_df['score'].apply(scoreToReputation)
    indicators_df = indicators_df.rename({'value': 'Value', 'indicator_type': 'Type'}, axis=1)
    indicators_headers = ['Id', 'Value', 'Type', 'Reputation', 'Involved Incidents Count']

    hr = tableToMarkdown('Mutual Indicators', indicators_df.to_dict(orient='records'),
                         headers=indicators_headers)

    hr_no_title = '\n'.join(hr.split('\n')[1:])
    demisto.executeCommand('setIncident', {'emailcampaignmutualindicators': hr_no_title})  # without title
    return_outputs_custom(hr, add_context_key(create_context_for_indicators(indicators_df)), tag='indicators')
    return indicators_df


def get_comma_sep_list(value):
    res = [x.strip() for x in value.split(",")]
    return [x for x in res if x != '']


def get_reputation(id_, indicators_df):
    if len(indicators_df) == 0:
        max_reputation = 0
    else:
        relevant_indicators_df = indicators_df[indicators_df['investigationIDs'].apply(lambda x: id_ in x)]
        if len(relevant_indicators_df) > 0:
            max_reputation = max(relevant_indicators_df['score'])
        else:
            max_reputation = 0
    return scoreToReputation(max_reputation)


def return_involved_incidents_entry(incidents_df, indicators_df, fields_to_display):
    incidents_df['Id'] = incidents_df['id'].apply(lambda x: f"[{x}](#/Details/{x})")
    incidents_df = incidents_df.sort_values('created', ascending=False).reset_index(drop=True)
    incidents_df['created_dt'] = incidents_df['created'].apply(lambda x: dateutil.parser.parse(x))  # type: ignore
    incidents_df['Created'] = incidents_df['created_dt'].apply(lambda x: x.strftime("%B %d, %Y"))
    incidents_df['similarity'] = incidents_df['similarity'].fillna(1)
    incidents_df['similarity'] = incidents_df['similarity'].apply(lambda x: '{:.1f}%'.format(x * 100))
    current_incident_id = demisto.incident()['id']
    incidents_df['DBot Score'] = incidents_df['id'].apply(lambda id_: get_reputation(id_, indicators_df))
    # add a mark at current incident, at its similarity cell
    incidents_df['similarity'] = incidents_df.apply(
        lambda x: '{} (current)'.format(x['similarity']) if x['id'] == current_incident_id else x['similarity'], axis=1)
    incidents_df['status'] = incidents_df['status'].apply(lambda x: STATUS_DICT[x] if x in STATUS_DICT else '')
    incidents_df = incidents_df.rename({
        'name': 'Name',
        FROM_FIELD: 'Email From',
        'similarity': 'Similarity to Current Incident',
        'status': 'Status'},
        axis=1)
    incidents_headers = ['Id', 'Created', 'Name', 'Status', 'Email From', 'DBot Score',
                         'Similarity to Current Incident']
    if fields_to_display is not None:
        fields_to_display = [f for f in fields_to_display if f in incidents_df.columns]
        incidents_df[fields_to_display] = incidents_df[fields_to_display].fillna('')
        fields_to_display = [f for f in fields_to_display if len(get_non_na_empty_values(incidents_df, f)) > 0]
        incidents_headers += fields_to_display
    hr = '\n\n' + tableToMarkdown('Involved Incidents', incidents_df[incidents_headers].to_dict(orient='records'),
                                  headers=incidents_headers)
    return_outputs_custom(hr, tag='incidents')


def draw_canvas(incidents, indicators):
    incident_ids = {x['id'] for x in incidents}
    filtered_indicators = []
    for indicator in indicators:
        investigations = indicator.get('investigationIDs', [])
        mutual_incidents_in_canvas = len(set(investigations).intersection(incident_ids))
        if mutual_incidents_in_canvas >= 2:
            filtered_indicators.append(indicator)
    try:
        res = demisto.executeCommand('DrawRelatedIncidentsCanvas', {'relatedIncidentsIDs': list(incident_ids),
                                                                    'indicators': filtered_indicators,
                                                                    'overrideUserCanvas': 'true'
                                                                    })

        if not is_error(res):
            res[-1]['Tags'] = ['canvas']
        try:
            demisto.executeCommand('setIncident', {'emailcampaigncanvas': res[-1].get('HumanReadable', '').strip("#")})
        except Exception:
            pass
        demisto.results(res)
    except Exception:
        pass


def analyze_incidents_campaign(incidents, fields_to_display):
    global TO_PLOT_CANVAS, MAX_INCIDENTS_FOR_CANVAS_PLOTTING, MAX_INDICATORS_FOR_CANVAS_PLOTTING
    incidents_df = pd.DataFrame(incidents)
    return_campaign_details_entry(incidents_df, fields_to_display)
    indicators_df = return_indicator_entry(incidents_df)
    return_involved_incidents_entry(incidents_df, indicators_df, fields_to_display)
    if TO_PLOT_CANVAS and len(incidents_df) <= MAX_INCIDENTS_FOR_CANVAS_PLOTTING:
        draw_canvas(incidents, indicators_df.head(MAX_INDICATORS_FOR_CANVAS_PLOTTING).to_dict(orient='records'))


def split_non_content_entries(response: list) -> tuple[dict, list]:
    """
    Args:
        response: A response list from executeCommand.

    Return: (dict: The last content entry, list: non content entries)
    """
    content_entry = response[0]
    non_content_entries = []
    for res_entry in response:
        if res_entry.get('Contents'):
            content_entry = res_entry
        else:
            non_content_entries.append(res_entry)

    return content_entry, non_content_entries


def main():
    global EMAIL_BODY_FIELD, EMAIL_SUBJECT_FIELD, EMAIL_HTML_FIELD, FROM_FIELD, SELF_IN_CONTEXT

    input_args = demisto.args()
    EMAIL_BODY_FIELD = input_args.get('emailBody', EMAIL_BODY_FIELD)
    EMAIL_SUBJECT_FIELD = input_args.get('emailSubject', EMAIL_SUBJECT_FIELD)
    EMAIL_HTML_FIELD = input_args.get('emailBodyHTML', EMAIL_HTML_FIELD)
    FROM_FIELD = input_args.get('emailFrom', FROM_FIELD)
    fields_to_display = input_args.get('fieldsToDisplay')
    SELF_IN_CONTEXT = argToBoolean(input_args.get('includeSelf', 'false'))
    if fields_to_display is not None:
        input_args['populateFields'] = fields_to_display
        fields_to_display = get_comma_sep_list(fields_to_display)
    else:
        fields_to_display = []
    res = demisto.executeCommand('FindDuplicateEmailIncidents', input_args)
    if is_error(res):
        return_error(get_error(res))

    content_entry, non_content_entries = split_non_content_entries(res)
    incidents = json.loads(content_entry['Contents'])
    if incidents:
        skip_analysis = is_number_of_incidents_too_low(content_entry, incidents) or \
            is_number_of_unique_recipients_is_too_low(incidents)
        if not skip_analysis:
            analyze_incidents_campaign(incidents, fields_to_display)
    if non_content_entries:
        return_results(non_content_entries)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
