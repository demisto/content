from CommonServerPython import *
import pytest


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "email_threads, expected_result",
    [
        (util_load_json('test_data/email_threads.json'), util_load_json('test_data/email_threads.json')),
        (util_load_json('test_data/email_threads.json')[0], [util_load_json('test_data/email_threads.json')[0]]),
        ('', None)
    ]
)
def test_fetch_email_threads(email_threads, expected_result, mocker):
    """
    Unit test Scenario 1 - Multiple thread entries present
        Given
        - Function is called to fetch email threads from current incident
        When
        - Context contains multiple mail threads (list of dicts)
        Then
        - Validate that function returns email thread data (list of dicts)
    Unit test Scenario 2 - Single thread entry present
        Given
        - Function is called to fetch email threads from current incident
        When
        - Context contains a single thread entry (dict)
        Then
        - Validate that function returns email thread data (list with one dict)
    Unit test Scenario 3 - No thread entries present
        Given
        - Function is called to fetch email threads from current incident
        When
        - Context contains no thread entries
        Then
        - Validate that function returns None
    """
    from SummarizeEmailThreads import fetch_email_threads
    import SummarizeEmailThreads
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(SummarizeEmailThreads, 'dict_safe_get', return_value=email_threads)
    result = fetch_email_threads('1')
    assert result == expected_result


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
