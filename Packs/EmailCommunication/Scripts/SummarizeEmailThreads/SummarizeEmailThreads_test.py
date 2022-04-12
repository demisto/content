from CommonServerPython import *


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


def test_format_threads(mocker):
    """Unit test
    Given
    - Function is called to summarize email threads into markdown format
    When
    - Email thread entries have primary, CC, and BCC recipients
    - Later emails in the chain add new CC users
    Then
    - Validate that function calls tableToMarkdown with correct table contents
    """
    from SummarizeEmailThreads import format_threads
    import SummarizeEmailThreads
    tableToMarkdown_mocker = mocker.patch.object(SummarizeEmailThreads, 'tableToMarkdown', return_value=True)
    format_threads(util_load_json('test_data/email_threads.json'))
    tableToMarkdown_call_args = tableToMarkdown_mocker.call_args
    expected = util_load_json('test_data/valid_table_data.txt')
    actual = tableToMarkdown_call_args.kwargs['t']
    assert actual == expected
