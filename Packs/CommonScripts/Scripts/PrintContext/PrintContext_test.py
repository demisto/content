import pytest

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from PrintContext import print_context

CONTEXT_DATA = [{'data1': 1}]


@pytest.mark.parametrize('expected_content, fmt, ctx', [
    (CONTEXT_DATA, 'json', CONTEXT_DATA),
    ('Context empty.', 'table', [])
])
def test_print_context(mocker, expected_content, fmt, ctx):
    """
    Given:
        - The script args.
    When:
        - Running the print_context function.
    Then:
        - Validating the outputs as expected.
    """
    results_mock = mocker.patch.object(demisto, 'results')
    print_context(fmt, ctx)
    res = results_mock.call_args[0][0]
    assert expected_content == res


@pytest.mark.parametrize('expected_content, fmt, ctx', [
    ('**Context data**:\n```\n', 'markdown', CONTEXT_DATA),
])
def test_print_context_markdown(mocker, expected_content, fmt, ctx):
    """
    Given:
        - The script args.
    When:
        - Running the print_context function.
    Then:
        - Validating the outputs as expected.
    """
    results_mock = mocker.patch.object(demisto, 'results')
    print_context(fmt, ctx)
    res = results_mock.call_args[0][0]['Contents']
    assert expected_content in res
