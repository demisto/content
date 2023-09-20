import demistomock as demisto
from RunCPPhishingCampaign import search_and_quarantine

FARM = 'mt-rnd-ng-6'
CUSTOMER = 'avananlab'


def test_search_and_quarantine_with_results(mocker):
    def execute_command(name, args):
        if name == 'checkpointhec-search-emails':
            return [{'Contents': {'ids': ['1', '2']}}]

        if name == 'checkpointhec-send-action':
            return [{'Contents': {'task': 1}}]

        if name == 'setIncident':
            return [{'Contents': None}]

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = search_and_quarantine(FARM, CUSTOMER, '1 day', 'a@b.test', '')
    assert result == [{'Contents': {'task': 1}}]


def test_search_and_quarantine_with_no_results(mocker):
    def execute_command(name, args):
        if name == 'checkpointhec-search-emails':
            return [{'Contents': {'ids': []}}]

        raise ValueError(f'Error: Unknown command or command/argument pair: {name} {args!r}')

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = search_and_quarantine(FARM, CUSTOMER, '1 day', 'a@b.test', '')
    assert result == [{'Contents': {'ids': []}}]
