import pytest
import demistomock as demisto
from CommonServerPython import formats
from HTMLtoMD import main, html_to_md_command


def test_main(mocker):
    mocker.patch.object(demisto, "args", return_value={"html": '<a href="http://demisto.com">Demisto</a>'})
    mocker.patch.object(demisto, "results")
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["ContentsFormat"] == formats["markdown"]
    assert results[0]["Contents"]["Result"] == "[Demisto](http://demisto.com)"


@pytest.mark.parametrize("escape_misc, expected_results", [(True, "**\\+ \\- \\&**"), (False, "**+ - &**")])
def test_escape_miscs(escape_misc, expected_results):
    """
    Given:
        html string to cast to md and escape_misc value.
        - Case 1: escape_misc=True.
        - Case 2: escape_misc=False.
    When:
        Calling html_to_md_command.
    Then:
        Ensue the right results returned.
        - Case 1: should escape miscellaneous punctuation characters.
        - Case 2: should not escape miscellaneous punctuation characters.
    """
    args = {"html": "<b>+ - &</b>", "escape_misc": escape_misc}
    results = html_to_md_command(args)
    assert results[1] == expected_results
