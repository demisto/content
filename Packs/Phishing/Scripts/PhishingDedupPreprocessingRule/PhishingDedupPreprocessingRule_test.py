from CommonServerPython import *
from PhishingDedupPreprocessingRule import *
import json

ID_CONtER = 0

EXISTING_INCIDENTS = []

RESULTS = None
EXISTING_INCIDENT_ID = DUP_INCIDENT_ID = None

IDS_COUNTER = 0

text = "Imagine there's no countries It isn't hard to do Nothing to kill or die for And no religion too " \
       "Imagine all the people Living life in peace"
text2 = "Love of my life, you've hurt me You've broken my heart and now you leave me Love of my life, can't you see?\
      Bring it back, bring it back Don't take it away from me, because you don't know What it means to me"


def create_incident(subject=None, body=None, html=None, emailfrom=None):
    global IDS_COUNTER
    incident = {
        "CustomFields": {},
        "id": str(IDS_COUNTER),
        "name": ' '.join(str(x) for x in [subject, body, html, emailfrom, id])
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
    if command == 'linkIncidents':
        EXISTING_INCIDENT_ID = args['incidentId']
        DUP_INCIDENT_ID = args['linkedIncidentIDs']


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
    assert not duplicated_incidents_found(existing_incident)


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
