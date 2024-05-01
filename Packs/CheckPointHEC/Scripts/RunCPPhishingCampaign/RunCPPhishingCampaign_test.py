import json

import demistomock as demisto
from RunCPPhishingCampaign import get_sender_and_subject, search_and_quarantine


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_sender_and_subject(mocker):
    mock_response = util_load_json('./test_data/checkpointhec-get_entity.json')
    entity = mock_response['responseData'][0]['entityPayload']

    def execute_command(name, args):
        if name == 'checkpointhec-get-entity':
            return [{'Contents': entity}]

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    sender, subject = get_sender_and_subject('0' * 32)
    assert sender == entity['fromEmail']
    assert subject == entity['subject']


def test_search_and_quarantine_with_results(mocker):
    mock_response = util_load_json('./test_data/checkpointhec-search_emails.json')

    def execute_command(name, args):
        if name == 'checkpointhec-search-emails':
            entities = mock_response.get('responseData')
            emails = []
            for entity in entities:
                email = entity['entityPayload']
                email['entityId'] = entity['entityInfo']['entityId']
                emails.append(email)
            return [{'Contents': emails}]

        if name == 'checkpointhec-send-action':
            return [{'Contents': {'task': 1}}]

        if name == 'setIncident':
            return [{'Contents': None}]

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = search_and_quarantine('1 day', 'a@b.test', '')
    assert result == [{'Contents': {'task': 1}}]


def test_search_and_quarantine_with_no_results(mocker):
    def execute_command(name, args):
        if name == 'checkpointhec-search-emails':
            return [{'Contents': []}]

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = search_and_quarantine('1 day', 'a@b.test', '')
    assert result == [{'Contents': []}]
