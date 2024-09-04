# from CommonServerPython import *
from FindEmailCampaign import *
import json
from datetime import datetime
import pandas as pd
import tldextract
from email.utils import parseaddr
import pytest

no_fetch_extract = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=False)


def extract_domain(address):
    global no_fetch_extract
    if address == '':
        return ''
    email_address = parseaddr(address)[1]
    ext = no_fetch_extract(email_address)
    return f'{ext.domain}.{ext.suffix}'


EXISTING_INCIDENTS = []

RESULTS = None
EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None

IDS_COUNTER = 57878

text = "Imagine there's no countries It isn't hard to do Nothing to kill or die for And no religion too " \
       "Imagine all the people Living life in peace"
text2 = "Love of my life, you've hurt me You've broken my heart and now you leave me Love of my life, can't you see?\
      Bring it back, bring it back Don't take it away from me, because you don't know What it means to me"

INCIDENTS_CONTEXT_KEY = 'EmailCampaign.' + INCIDENTS_CONTEXT_TD


def create_incident(subject=None, body=None, html=None, emailfrom=None, created=None, id_=None,
                    similarity=0, sender='a@phishing.com', emailto='a@paloaltonetwork.com', emailcc='',
                    emailbcc='', status=1, severity=1):
    global IDS_COUNTER
    dt_format = '%Y-%m-%d %H:%M:%S.%f %z'
    incident = {
        "id": id_ if id_ is not None else str(IDS_COUNTER),
        "name": ' '.join(str(x) for x in [subject, body, html, emailfrom]),
        'created': created.strftime(dt_format) if created is not None else datetime.now().strftime(dt_format),
        'type': 'Phishing',
        'similarity': similarity,
        'emailfrom': sender,
        PREPROCESSED_EMAIL_BODY: body,
        'emailbodyhtml': html,
        PREPROCESSED_EMAIL_SUBJECT: subject,
        'fromdomain': extract_domain(sender),
        'emailto': emailto,
        'emailcc': emailcc,
        'emailbcc': emailbcc,
        'status': status,
        'severity': severity
    }
    return incident


def set_existing_incidents_list(incidents_list):
    global EXISTING_INCIDENTS
    EXISTING_INCIDENTS = incidents_list


def executeCommand(command, args=None):
    global EXISTING_INCIDENTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    if command == 'FindDuplicateEmailIncidents':
        incidents_str = json.dumps(EXISTING_INCIDENTS)
        return [{'Contents': incidents_str, 'Type': 'not error'}]
    if command == 'CloseInvestigationAsDuplicate':
        EXISTING_INCIDENT_ID = args['duplicateId']
        return None
    return None


def results(arg):
    global RESULTS
    RESULTS.append(arg)


def mock_summarize_email_body(body, subject, nb_sentences=3, subject_weight=1.5, keywords_weight=1.5):
    return f'{subject}\n{body}'


def test_return_campaign_details_entry(mocker):
    global RESULTS
    RESULTS = []
    mocker.patch.object(demisto, 'results', side_effect=results)
    mocker.patch('FindEmailCampaign.summarize_email_body', mock_summarize_email_body)
    inciddent1 = create_incident(subject='subject', body='email body')
    incidents_list = [inciddent1]
    data = pd.DataFrame(incidents_list)
    return_campaign_details_entry(data, fields_to_display=[])
    res = RESULTS[0]
    context = res['EntryContext']
    assert context['EmailCampaign.isCampaignFound']
    assert context['EmailCampaign.involvedIncidentsCount'] == len(data)
    for original_incident, context_incident in zip(incidents_list, context[INCIDENTS_CONTEXT_KEY]):
        for k in ['id', 'similarity', 'emailfrom']:
            assert original_incident[k] == context_incident[k]
        assert original_incident['emailto'] in context_incident['recipients']
        assert original_incident['fromdomain'] == context_incident['emailfromdomain']
        assert extract_domain(original_incident['emailto']) in context_incident['recipientsdomain']


def test_return_campaign_details_entry_comma_seperated_recipients(mocker):
    global RESULTS
    RESULTS = []
    mocker.patch.object(demisto, 'results', side_effect=results)
    mocker.patch('FindEmailCampaign.summarize_email_body', mock_summarize_email_body)
    inciddent1 = create_incident(subject='subject', body='email body', emailto='a@a.com, b@a.com')
    incidents_list = [inciddent1]
    data = pd.DataFrame(incidents_list)
    return_campaign_details_entry(data, fields_to_display=[])
    res = RESULTS[0]
    context = res['EntryContext']
    assert context['EmailCampaign.isCampaignFound']
    assert context['EmailCampaign.involvedIncidentsCount'] == len(data)
    for original_incident, context_incident in zip(incidents_list, context[INCIDENTS_CONTEXT_KEY]):
        for k in ['id', 'similarity', 'emailfrom']:
            assert original_incident[k] == context_incident[k]
        for recipient in original_incident['emailto'].split(','):
            assert recipient.strip() in context_incident['recipients']
            assert extract_domain(recipient) in context_incident['recipientsdomain']
        assert original_incident['fromdomain'] == context_incident['emailfromdomain']


def test_return_campaign_details_entry_list_dumped_recipients(mocker):
    global RESULTS
    RESULTS = []
    mocker.patch.object(demisto, 'results', side_effect=results)
    mocker.patch('FindEmailCampaign.summarize_email_body', mock_summarize_email_body)
    inciddent1 = create_incident(subject='subject', body='email body', emailto='["a@a.com", "b@a.com"]')
    incidents_list = [inciddent1]
    data = pd.DataFrame(incidents_list)
    return_campaign_details_entry(data, fields_to_display=[])
    res = RESULTS[0]
    context = res['EntryContext']
    assert context['EmailCampaign.isCampaignFound']
    assert context['EmailCampaign.involvedIncidentsCount'] == len(data)
    for original_incident, context_incident in zip(incidents_list, context[INCIDENTS_CONTEXT_KEY]):
        for k in ['id', 'similarity', 'emailfrom']:
            assert original_incident[k] == context_incident[k]
        for recipient in json.loads(original_incident['emailto']):
            assert recipient.strip() in context_incident['recipients']
            assert extract_domain(recipient) in context_incident['recipientsdomain']
        assert original_incident['fromdomain'] == context_incident['emailfromdomain']


def test_return_campaign_details_entry_list_dumped_recipients_cc(mocker):
    global RESULTS
    RESULTS = []
    mocker.patch.object(demisto, 'results', side_effect=results)
    mocker.patch('FindEmailCampaign.summarize_email_body', mock_summarize_email_body)
    inciddent1 = create_incident(subject='subject', body='email body', emailcc='["a@a.com", "b@a.com"]')
    incidents_list = [inciddent1]
    data = pd.DataFrame(incidents_list)
    return_campaign_details_entry(data, fields_to_display=[])
    res = RESULTS[0]
    context = res['EntryContext']
    assert context['EmailCampaign.isCampaignFound']
    assert context['EmailCampaign.involvedIncidentsCount'] == len(data)
    for original_incident, context_incident in zip(incidents_list, context[INCIDENTS_CONTEXT_KEY]):
        for k in ['id', 'similarity', 'emailfrom']:
            assert original_incident[k] == context_incident[k]
        for recipient in json.loads(original_incident['emailcc']):
            assert recipient.strip() in context_incident['recipients']
            assert extract_domain(recipient) in context_incident['recipientsdomain']
        assert original_incident['fromdomain'] == context_incident['emailfromdomain']


ADDITIONAL_CONTEXT_KEYS_PARAMETRIZE = [
    (['name', 'emailfrom', 'emailto', 'severity', 'status', 'created']),
    (['name', 'emailfrom', 'emailto'])
]


def prepare_additional_context_fields_test(mocker):
    global RESULTS
    RESULTS = []
    # prepare
    mocker.patch.object(demisto, 'results', side_effect=results)
    mocker.patch('FindEmailCampaign.summarize_email_body', mock_summarize_email_body)
    incident = create_incident(
        subject='subject', body='email body',
        emailfrom='a@a.com', emailto='a@a.com, b@a.com', emailcc='["a@a.com", "b@a.com"]')
    incidents_list = [incident]
    data = pd.DataFrame(incidents_list)
    return data


@pytest.mark.parametrize(
    'fields_to_store_in_context', ADDITIONAL_CONTEXT_KEYS_PARAMETRIZE)
def test_context_populated_with_requested_fields_happy_path(mocker, fields_to_store_in_context):
    """

    Given:
        - List of valid fields for the command argument fieldsToDisplay, expected to be stored in the context

    When:
        - Get the campaign details entry

    Then:
        - Assert that the user requested fields are stored in the context

    """
    # prepare

    data = prepare_additional_context_fields_test(mocker)

    # run
    return_campaign_details_entry(data, fields_to_display=fields_to_store_in_context)
    res = RESULTS[0]
    context = res['EntryContext']

    # assert
    for context_incident in context[INCIDENTS_CONTEXT_KEY]:
        for field in fields_to_store_in_context:
            assert field in context_incident, f'the field "{field}" is expected to be stored in context'


def test_context_not_populated_with_invalid_fields(mocker):
    """

    Given:
        - List of invalid fields for the command argument fieldsToDisplay, expected not to be stored in the context

    When:
        - Get the campaign details entry

    Then:
        - Assert that the invalid fields aren't stored in the context and there is Warning entry

    """
    invalid_fields = ['name_', 'email_from', 'emailTo', 'Severity', 'statuses', 'create']
    data = prepare_additional_context_fields_test(mocker)

    # run
    return_campaign_details_entry(data, fields_to_display=invalid_fields)

    # assert RESULTS have 2 entries, Warning entry about the invalid fields and context entry
    assert len(RESULTS) == 2
    assert 'Warning: ' in RESULTS[0]['Contents']

    # assert that invalid keys aren't in the context
    context = RESULTS[1]['EntryContext']
    for context_incident in context[INCIDENTS_CONTEXT_KEY]:
        for field in invalid_fields:
            assert field not in context_incident, f'the field "{field}" should not be stored in context'


@pytest.mark.parametrize(
    'include_self', [True, False])
def test_include_self_flag_on(mocker, include_self):
    """

    Given:
        - include_self flag either True or false

    When:
        - Get the campaign details entry

    Then:
        - Assert that the appearance of the current incident is in the context (INCIDENTS_CONTEXT_KEY) according to the
          given flag

    """
    import FindEmailCampaign
    global RESULTS
    RESULTS = []
    FindEmailCampaign.SELF_IN_CONTEXT = include_self
    mocker.patch.object(demisto, 'results', side_effect=results)
    mocker.patch('FindEmailCampaign.summarize_email_body', mock_summarize_email_body)
    incident = create_incident(subject='subject', body='email body')
    mocker.patch.object(demisto, 'incident', return_value=incident)
    incidents_list = [incident]
    data = pd.DataFrame(incidents_list)
    return_campaign_details_entry(data, fields_to_display=[])
    res = RESULTS[0]
    context = res['EntryContext']
    result = incident['id'] in [context_incident['id'] for context_incident in context[INCIDENTS_CONTEXT_KEY]]
    # if include_self is true result should be true
    # if include_self is false result should be false
    assert (include_self and result) or (not include_self and not result)


def test_return_indicator_entry(mocker):
    import FindEmailCampaign

    # create dataframe with one incident
    incidents = pd.DataFrame([{"id": 2}, {"id": 1}])
    mocker.patch.object(FindEmailCampaign.demisto, "searchIndicators", return_value={
        "iocs":
            [{"id": "1", "value": "1", "score": 1, "investigationIDs": [1, 2], "relatedIncCount": 1}], "total": 1},
    )
    mocker.patch.object(FindEmailCampaign.demisto, "executeCommand")
    indicator = FindEmailCampaign.return_indicator_entry(incidents)
    assert indicator["id"].values[0] == "1"
    assert indicator["relatedIncCount"].values[0] == 1


CONTENT_ENTRY = {'Contents': '[]', 'Type': 1}
NON_CONTENT_ENTRY1 = {'Contents': '', 'Type': 16}
NON_CONTENT_ENTRY2 = {'NotContents': '', 'Type': 16}


def test_return_non_content_entries(mocker):
    """
    Given: a content entry and non-content entries as a response to the executeCommand.
    When: Running the scipt (usually happens with debug-mode=true)
    Then: assert the non-content entries are returned.
    """
    import FindEmailCampaign
    mocker.patch.object(FindEmailCampaign.demisto, "args", return_value={})
    mocker.patch.object(FindEmailCampaign.demisto, "executeCommand", return_value=[CONTENT_ENTRY, NON_CONTENT_ENTRY1,
                                                                                   NON_CONTENT_ENTRY2])

    return_results_mock = mocker.patch("FindEmailCampaign.return_results")
    FindEmailCampaign.main()
    return_results_mock.assert_called_with([NON_CONTENT_ENTRY1, NON_CONTENT_ENTRY2])
