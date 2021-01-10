from collections import Counter

import dateutil
from nltk import sent_tokenize, word_tokenize
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pandas as pd
import numpy as np
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import CountVectorizer
from numpy import dot
from numpy.linalg import norm

EMAIL_BODY_FIELD = 'emailbody'
EMAIL_SUBJECT_FIELD = 'emailsubject'
EMAIL_HTML_FIELD = 'emailbodyhtml'
FROM_FIELD = 'emailfrom'
FROM_DOMAIN_FIELD = 'fromdomain'
PREPROCESSED_EMAIL_BODY = 'preprocessedemailbody'
PREPROCESSED_EMAIL_SUBJECT = 'preprocessedemailsubject'
MERGED_TEXT_FIELD = 'mereged_text'
MIN_CAMPAIGN_SIZE = int(demisto.args().get("minIncedentsForCampaign", 3))
MIN_UNIQUE_RECIPIENTS = int(demisto.args().get("minUniqueRecipients", 2))
DUPLICATE_SENTENCE_THRESHOLD = 0.95
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
            'medicine', 'meds', 'member', 'membership', 'message', 'million', 'millions', 'miracle', 'money', 'monthly',
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
            'wallet', 'warranty', 'we', 'web', 'weight', 'win', 'winner', 'winning', 'wire', 'xanax']


def add_context_key(entry_context):
    context = {
        'Campaign': entry_context
    }
    return context


def create_context_for_campaign_details(campaign_found=False, incidents_df=None):
    return {
        'isCampaignFound': campaign_found,
        'campaignIncidentsIds': incidents_df['id'].tolist() if incidents_df is not None else []
    }


def create_context_for_indicators(mutual_indicators=[]):
    return {'mutualIndicatorsIds': mutual_indicators}


CONTEXT_FUNCTIONS = [create_context_for_campaign_details, create_context_for_indicators, ]


def create_empty_context():
    context = {}
    for f in CONTEXT_FUNCTIONS:
        context = {**context, **f()}
    context = add_context_key(context)
    return context


def is_number_of_incidents_is_to_low(res, incidents):
    if not res["EntryContext"]['isDuplicateIncidentFound'] or \
            len(incidents) < MIN_CAMPAIGN_SIZE:
        return_outputs('No possible campaign was detected', create_empty_context())
        return True
    return False


def is_number_of_unique_recipients_is_too_low(incidents):
    unique_recipients = Counter([str(i.get('emailto', 'None')) for i in incidents])
    missing_recipients = unique_recipients['None']
    unique_recipients.pop('None', None)
    if (len(unique_recipients) < MIN_UNIQUE_RECIPIENTS and missing_recipients == 0) or \
            (0 < len(unique_recipients) < MIN_UNIQUE_RECIPIENTS and missing_recipients > 0):
        msg = 'Similar emails were found, but the number of their unique recipients is too low to consider them as ' \
              'campaign.\n '
        msg += 'If you wish to consider similar emails as campaign even with low number of unique recipients, ' \
               'please change *minUniqueRecipients* argument\'s value.\n'
        msg += 'Details:\n'
        msg += '* Found {} similar incidents.\n'.format(len(incidents))
        msg += '* Those incidents have {} unique recipients'.format(len(unique_recipients))
        msg += ' ({}).\n'.format(', '.join(unique_recipients))
        msg += '* The minimum number of unique recipients for similar emails as campaign: ' \
               '{}\n'.format(MIN_UNIQUE_RECIPIENTS)
        if missing_recipients > 0:
            msg += '* Could not find email recipient for {}/{} incidents ' \
                   '(*Email To* field is empty)'.format(missing_recipients, len(incidents))

        return_outputs(msg, create_empty_context())
        return True
    return False


def get_str_representation_top_n_values(values_list, counter_tuples_list, top_n):
    domains_counter_top = counter_tuples_list[:top_n]
    if len(counter_tuples_list) > top_n:
        domains_counter_top += [('Other', len(values_list) - sum(x[1] for x in domains_counter_top))]
    return ','.join('{} ({})'.format(domain, count) for domain, count in domains_counter_top)


def calculate_campaign_details_table(incidents_df):
    n_incidents = len(incidents_df)
    similarities = incidents_df['similarity'].dropna().to_list()
    max_similarity = max(similarities)
    min_similarity = min(similarities)
    headers = []
    contents = []
    headers.append('Details')
    contents.append('Found possible campaign of {} similar emails'.format(n_incidents))
    if max_similarity > min_similarity + 10 ** -2:
        headers.append('Similarity range')
        contents.append("{:.1f}%-{:.1f}%".format(min_similarity * 100, max_similarity * 100))
    else:
        headers.append('Similarity')
        contents.append("{:.1f}%".format(max_similarity * 100))
    incidents_df['created_dt'] = incidents_df['created'].apply(lambda x: dateutil.parser.parse(x))
    datetimes = incidents_df['created_dt'].dropna()  # type: ignore
    min_datetime, max_datetime = min(datetimes), max(datetimes)
    if (max_datetime - min_datetime).days == 0:
        headers.append('Date')
        contents.append(max_datetime.strftime("%B %d, %Y"))
    else:
        headers.append('Date range')
        contents.append('{} - {}'.format(min_datetime.strftime("%B %d, %Y"), max_datetime.strftime("%B %d, %Y")))
    senders = incidents_df[FROM_FIELD].dropna().replace('', np.nan).tolist()
    senders_counter = Counter(senders).most_common()
    senders_domain = incidents_df[FROM_DOMAIN_FIELD].replace('', np.nan).dropna().tolist()
    domains_counter = Counter(senders_domain).most_common()
    if len(senders_counter) == 1:
        domain_header = "Sender domain"
        sender_header = "Sender address"

    elif len(senders_counter) > 1 and len(domains_counter) == 1:
        domain_header = "Senders domain"
        sender_header = "Senders addresses"
    else:
        domain_header = "Senders domains"
        sender_header = "Senders addresses"
    top_n = 1
    domain_value = get_str_representation_top_n_values(senders_domain, domains_counter, top_n)
    sender_value = get_str_representation_top_n_values(senders, senders_counter, top_n)
    headers.append(domain_header)
    contents.append(domain_value)
    headers.append(sender_header)
    contents.append(sender_value)
    hr = tableToMarkdown('Possible Campaign Detected', {header: value for header, value in zip(headers, contents)},
                         headers=headers)
    return hr


def cosine_sim(a, b):
    return dot(a, b) / (norm(a) * norm(b))


def summarize_email_body(body, subject, nb_sentences=3):
    corpus = sent_tokenize(body)
    cv = CountVectorizer(stop_words=list(stopwords.words('english')))
    body_arr = cv.fit_transform(corpus).toarray()
    subject_arr = cv.transform(sent_tokenize(subject)).toarray()
    word_list = cv.get_feature_names()
    count_list = body_arr.sum(axis=0) + subject_arr.sum(axis=0) * 1.5
    duplicate_sentences = [i for i, arr in enumerate(body_arr) if
                           any(cosine_sim(arr, arr2) > DUPLICATE_SENTENCE_THRESHOLD
                               for arr2 in body_arr[:i])]

    """
    The zip(*iterables) function takes iterables as arguments and returns an iterator. 
    This iterator generates a series of tuples containing elements from each iterable. 
    Let's convert these tuples to {word:frequency} dictionary"""

    word_frequency = dict(zip(word_list, count_list))

    val = sorted(word_frequency.values())

    # gets relative frequencies of words
    max_frequency = val[-1]
    for word in word_frequency.keys():
        word_frequency[word] = (word_frequency[word] / max_frequency)
    for word in KEYWORDS:
        if word in word_frequency:
            word_frequency[word] *= 1.5

    # SENTENCE RANKING: the rank of sentences is based on the word frequencies
    sentence_rank = {}
    for i, sent in enumerate(corpus):
        if i in duplicate_sentences:
            continue
        sentence_rank[i] = 0
        for word in word_tokenize(sent):
            if word.lower() in word_frequency.keys():
                if i in sentence_rank.keys():
                    sentence_rank[i] += word_frequency[word.lower()]
        sentence_rank[i] = sentence_rank[i] / len(word_tokenize(sent))
    sorted_sentence_rank = sorted(sentence_rank.items(), key=lambda item: item[1], reverse=True)
    top_sentences_indices = [sent_i for sent_i, _ in sorted_sentence_rank[:nb_sentences]]
    # Mount summary
    summary = [corpus[sent_i].strip() for sent_i in sorted(top_sentences_indices)]

    # return orinal text and summary
    return '\n'.join(summary)


def create_email_summary_hr(incidents_df):
    hr_email_summary = ''
    clean_email_subject = incidents_df.iloc[0][PREPROCESSED_EMAIL_SUBJECT]
    email_summary = 'Subject: ' + clean_email_subject.replace('\n', '')
    clean_email_body = incidents_df.iloc[0][PREPROCESSED_EMAIL_BODY]
    email_summary += '\n' + summarize_email_body(clean_email_body, clean_email_subject)
    for word in KEYWORDS:
        email_summary = re.sub(r'(?<!\w)({})(?!\w)'.format(word), '**{}**'.format(word), email_summary,
                               flags=re.IGNORECASE)
    hr_email_summary += '\n\n' + '### Current Incident\'s Email Summary'
    hr_email_summary += '\n ##### ' + email_summary
    context = add_context_key(create_context_for_campaign_details(campaign_found=True, incidents_df=incidents_df))
    return context, hr_email_summary


def return_campaign_details_entry(incidents_df):
    hr_campaign_details = calculate_campaign_details_table(incidents_df)
    context, hr_email_summary = create_email_summary_hr(incidents_df)
    hr = '\n'.join([hr_campaign_details, hr_email_summary])
    return return_outputs(hr, context)


def return_no_mututal_indicators_found_entry():
    hr = '### Mutual Indicators' + '\n'
    hr += 'No mutual indicators were found.'
    return_outputs(hr, add_context_key(create_context_for_indicators()))


def return_indicator_entry(incidents_df):
    indicators_query = 'investigationIDs:({})'.format(' '.join('"{}"'.format(id_) for id_ in incidents_df['id']))
    fields = ['id', 'indicator_type', 'investigationIDs', 'relatedIncCount', 'score', 'value']
    indicators_args = {'query': indicators_query, 'limit': '150', 'populateFields': ','.join(fields)}
    res = demisto.executeCommand('GetIndicatorsByQuery', args=indicators_args)
    if is_error(res):
        return_error(res)
    indicators = res[0]['Contents']
    if len(indicators) == 0:
        return_no_mututal_indicators_found_entry()
        return
    indicators_df = pd.DataFrame(data=indicators)
    indicators_df = indicators_df[indicators_df['relatedIncCount'] < 150]
    indicators_df['Involved Incidents Count'] = \
        indicators_df['investigationIDs'].apply(lambda x: sum(id_ in x for id_ in incidents_df['id']))
    indicators_df = indicators_df[indicators_df['Involved Incidents Count'] > 1]
    if len(indicators_df) == 0:
        return_no_mututal_indicators_found_entry()
        return
    indicators_df['Id'] = indicators_df['id'].apply(lambda x: "[%s](#/indicator/%s)" % (x, x))
    indicators_df = indicators_df.sort_values(['score', 'Involved Incidents Count'], ascending=False)
    indicators_df['Reputation'] = indicators_df['score'].apply(scoreToReputation)
    indicators_df.rename({'value': 'Value', 'indicator_type': 'Type'}, axis=1, inplace=True)
    indicators_headers = ['Id', 'Value', 'Type', 'Reputation', 'Involved Incidents Count']

    hr = tableToMarkdown('Mutual Indicators', indicators_df.to_dict(orient='records'),
                         headers=indicators_headers)
    return_outputs(hr, add_context_key(create_context_for_indicators(indicators_df['id'].tolist())))


def return_involved_incdients_entry(incidents_df):
    incidents_df['Id'] = incidents_df['id'].apply(lambda x: "[%s](#/Details/%s)" % (x, x))
    incidents_df = incidents_df.sort_values('created', ascending=False).reset_index(drop=True)
    incidents_df['created_dt'] = incidents_df['created'].apply(lambda x: dateutil.parser.parse(x))
    incidents_df['Created'] = incidents_df['created_dt'].apply(lambda x: x.strftime("%B %d, %Y"))
    incidents_df['similarity'] = incidents_df['similarity'].fillna(1)
    incidents_df['similarity'] = incidents_df['similarity'].apply(lambda x: '{:.2f}%'.format(x * 100))
    current_incident_id = demisto.incident()['id']
    # add a mark at current incident, at its similarity cell
    incidents_df['similarity'] = incidents_df.apply(
        lambda x: '{} (current)'.format(x['similarity']) if x['id'] == current_incident_id else x['similarity'], axis=1)
    incidents_df.rename({
        'name': 'Name',
        FROM_FIELD: 'Email From',
        'similarity': 'Similarity to Current Incident'},
        axis=1, inplace=True)
    incidents_headers = ['Id', 'Created', 'Name', 'Email From', 'Similarity to Current Incident']
    hr = '\n\n' + tableToMarkdown('Involved Incidents', incidents_df[incidents_headers].to_dict(orient='records'),
                                  headers=incidents_headers)
    return_outputs(hr)


def analyze_incidents_campaign(incidents_df):
    return_campaign_details_entry(incidents_df)
    return_indicator_entry(incidents_df)
    return_involved_incdients_entry(incidents_df)


def main():
    global EMAIL_BODY_FIELD, EMAIL_SUBJECT_FIELD, EMAIL_HTML_FIELD, FROM_FIELD
    input_args = demisto.args()
    EMAIL_BODY_FIELD = input_args.get('emailBody', EMAIL_BODY_FIELD)
    EMAIL_SUBJECT_FIELD = input_args.get('emailSubject', EMAIL_SUBJECT_FIELD)
    EMAIL_HTML_FIELD = input_args.get('emailBodyHTML', EMAIL_HTML_FIELD)
    FROM_FIELD = input_args.get('emailFrom', FROM_FIELD)

    res = demisto.executeCommand('FindDuplicateEmailIncidents', input_args)
    if is_error(res):
        return_error(get_error(res))
    res = res[-1]
    incidents = json.loads(res['Contents'])
    if is_number_of_incidents_is_to_low(res, incidents):
        return
    if is_number_of_unique_recipients_is_too_low(incidents):
        return
    incidents_df = pd.DataFrame(incidents)
    analyze_incidents_campaign(incidents_df)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
