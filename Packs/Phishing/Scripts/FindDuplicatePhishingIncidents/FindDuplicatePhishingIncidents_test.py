from CommonServerPython import *
from FindDuplicatePhishingIncidents import *
import json
from datetime import datetime

EXISTING_INCIDENTS = []

RESULTS = None
EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None

IDS_COUNTER = 57878

text = "Imagine there's no countries It isn't hard to do Nothing to kill or die for And no religion too " \
       "Imagine all the people Living life in peace"
text2 = "Love of my life, you've hurt me You've broken my heart and now you leave me Love of my life, can't you see?\
      Bring it back, bring it back Don't take it away from me, because you don't know What it means to me"


def create_incident(subject=None, body=None, html=None, emailfrom=None, created=None, id_=None):
    global IDS_COUNTER
    dt_format = '%Y-%m-%d %H:%M:%S.%f %z'
    incident = {
        "CustomFields": {},
        "id": id_ if id_ is not None else str(IDS_COUNTER),
        "name": ' '.join(str(x) for x in [subject, body, html, emailfrom]),
        'created': created.strftime(dt_format) if created is not None else datetime.now().strftime(dt_format),
        'type': 'Phishing'
    }
    IDS_COUNTER += 1
    if subject is not None:
        incident['CustomFields']['emailsubject'] = subject
    if body is not None:
        incident['CustomFields']['emailbody'] = body
    if html is not None:
        incident['CustomFields']['emailbodyhtml'] = html
    if emailfrom is not None:
        incident['CustomFields']['emailfrom'] = emailfrom
    return incident


def set_existing_incidents_list(incidents_list):
    global EXISTING_INCIDENTS
    EXISTING_INCIDENTS = incidents_list


def executeCommand(command, args=None):
    global EXISTING_INCIDENTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    if command == 'GetIncidentsByQuery':
        incidents_str = json.dumps(EXISTING_INCIDENTS)
        return [{'Contents': incidents_str, 'Type': 'not error'}]
    if command == 'CloseInvestigationAsDuplicate':
        EXISTING_INCIDENT_ID = args['duplicateId']


def results(arg):
    global RESULTS
    RESULTS = arg


def duplicated_incidents_found(existing_incident):
    return existing_incident['id'] == EXISTING_INCIDENT_ID


def test_same_incidents_text_only(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert duplicated_incidents_found(existing_incident)


def test_different_text_only(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    text = "Imagine there's no countries It isn't hard to do Nothing to kill or die for And no religion too " \
           "Imagine all the people Living life in peace"

    existing_incident = create_incident(body=text2, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert not duplicated_incidents_found(existing_incident)


def test_same_incidents_exact_sender_match_same_senders(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None

    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'Exact'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert duplicated_incidents_found(existing_incident)


def test_same_incidents_exact_sender_match_different_senders(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    text = "Imagine there's no countries It isn't hard to do Nothing to kill or die for And no religion too " \
           "Imagine all the people Living life in peace"
    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'Exact'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text, emailfrom='mt.kb.user2@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert not duplicated_incidents_found(existing_incident)


def test_same_incidents_exact_sender_match_same_senders_different_texts(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None

    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'Exact'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text2, emailfrom='mt.kb.user@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert not duplicated_incidents_found(existing_incident)


def test_same_incidents_domain_sender_match_same_senders(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'Domain'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert duplicated_incidents_found(existing_incident)


def test_same_incidents_domain_sender_match_same_domain(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'Domain'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text, emailfrom='mt.kb.user2@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert duplicated_incidents_found(existing_incident)


def test_same_incidents_domain_sender_match_same_domain_different_texts(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'Domain'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text2, emailfrom='mt.kb.user2@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert not duplicated_incidents_found(existing_incident)


def test_slightly_different_texts(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body=text[:-5], emailfrom='mt.kb.user@gmail.co')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert duplicated_incidents_found(existing_incident)


def test_html_text(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID, text, text2
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    html = '<!DOCTYPE html>\
            <html>\
            <body>\
            <h1>{}</h1>\
            <p>{}</p>\
            </body>\
            </html>\
            '.format(text, text2)
    clean_text = '{}\n{}'.format(text, text2)
    existing_incident = create_incident(body=clean_text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'Domain'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(html=html, emailfrom='mt.kb.user2@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert duplicated_incidents_found(existing_incident)


def test_eliminate_urls_extensions():
    url = 'https://urldefense.proofpoint.com/v2/url?u=http-3A__fridmancpa.com_&d=DwIGaQ&c=XRWvQHnpdBDRh-yzrHjqLpXuH' \
          'NC_9nanQc6pPG_SpT0&r=sUpl2dZrOIls7oQLXwn74C7qVYSZVCdsK9UIY1nPz30&m=qD-Bndy5WGvuZizr-Jz7YQ5-8xXgRcK3w8NnNzX' \
          'lOsk&s=_NEaEUMVW0JU5b--ODhZKY9csky777X1jtFywaQyN2o&e='
    url_shortened = eliminate_urls_extensions(url)
    assert url_shortened == 'https://urldefense.proofpoint.com/'
    template = 'hello world {} goodbye'
    assert template.format(url_shortened) == eliminate_urls_extensions(template.format(url))


def test_no_text_fields(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(emailfrom='mt.kb.user@gmail.co')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert 'No text fields' in RESULTS['HumanReadable']


def test_short_text(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body=text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(emailfrom='mt.kb.user@gmail.co', body='short text')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert 'too short' in RESULTS['HumanReadable']


def test_generate_incident_type_query_component():
    type_fields_arg = 'type1'
    type_values_arg = "hello world, hello world 2,hello world 3"
    res = generate_incident_type_query_component(type_fields_arg, type_values_arg)
    assert res == 'type1:("hello world" "hello world 2" "hello world 3")'


def test_linked_to_oldest_incident(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    dt1 = datetime.now()
    dt2 = datetime.now()
    existing_incident_1 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='1', created=dt1)
    existing_incident_2 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='2', created=dt2)

    set_existing_incidents_list([existing_incident_2, existing_incident_1])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(emailfrom='mt.kb.user@gmail.co', body=text)
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert EXISTING_INCIDENT_ID == '1'


def test_linked_to_most_similar_incident(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    dt1 = datetime.now()
    dt2 = datetime.now()
    existing_incident_1 = create_incident(body=text2, emailfrom='mt.kb.user@gmail.com', id_='1', created=dt1)
    existing_incident_2 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='2', created=dt2)

    set_existing_incidents_list([existing_incident_2, existing_incident_1])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(emailfrom='mt.kb.user@gmail.co', body=text)
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert EXISTING_INCIDENT_ID == '2'


def test_linked_to_most_similar__and_oldest_incident(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident_1 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='1')
    existing_incident_2 = create_incident(body=text2, emailfrom='mt.kb.user@gmail.com', id_='2')
    existing_incident_3 = create_incident(body=text2, emailfrom='mt.kb.user@gmail.com', id_='3')
    existing_incident_4 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='4')
    set_existing_incidents_list([existing_incident_3, existing_incident_4, existing_incident_2, existing_incident_1])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(emailfrom='mt.kb.user@gmail.co', body=text)
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert EXISTING_INCIDENT_ID == '1'


def test_tie_break_with_id(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    dt1 = datetime.now()
    dt2 = datetime.now()
    existing_incident_1 = create_incident(body=text2, emailfrom='mt.kb.user@gmail.com', id_='1', created=dt1)
    existing_incident_2 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='2', created=dt2)
    existing_incident_3 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='3', created=dt2)
    set_existing_incidents_list([existing_incident_1, existing_incident_3, existing_incident_2])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(emailfrom='mt.kb.user@gmail.co', body=text)
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert EXISTING_INCIDENT_ID == '2'


def test_tie_break_with_non_numeric_id(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    dt1 = datetime.now()
    dt2 = datetime.now()
    existing_incident_1 = create_incident(body=text2, emailfrom='mt.kb.user@gmail.com', id_='a', created=dt1)
    existing_incident_2 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='b', created=dt2)
    existing_incident_3 = create_incident(body=text, emailfrom='mt.kb.user@gmail.com', id_='c', created=dt2)
    set_existing_incidents_list([existing_incident_1, existing_incident_3, existing_incident_2])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(emailfrom='mt.kb.user@gmail.co', body=text)
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert EXISTING_INCIDENT_ID == 'b'


def test_similar_incidents_1_word_difference(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body='Hi Bob ' + text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly', })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body='Hi Jhon ' + text, emailfrom='mt.kb.user@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert duplicated_incidents_found(existing_incident)


def test_similar_incidents_2_word_difference(mocker):
    global RESULTS, EXISTING_INCIDENT_ID, DUP_INCIDENT_ID
    EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None
    existing_incident = create_incident(body='Hi Bob Burger' + text, emailfrom='mt.kb.user@gmail.com')
    set_existing_incidents_list([existing_incident])
    mocker.patch.object(demisto, 'args', return_value={'fromPolicy': 'TextOnly', })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    new_incident = create_incident(body='Hi Jhon Pizza' + text, emailfrom='mt.kb.user@gmail.com')
    mocker.patch.object(demisto, 'incidents', return_value=[new_incident])
    mocker.patch.object(demisto, 'results', side_effect=results)
    main()
    assert not duplicated_incidents_found(existing_incident)
