from BreachConfirmationHTML import main
import pytest
import demistomock as demisto
from CommonServerPython import *


ARGS_MAIN = [
    ([{}],
     "<div style='color:green;'><h2>Pending Confirmation</h2></div>"),
    ([{"CustomFields": {'breachconfirmation': 'Pending Confirmation'}}],
     "<div style='color:green;'><h2>Pending Confirmation</h2></div>"),
    ([{"CustomFields": {'breachconfirmation': 'Confirm'}}],
     "<div style='color:red;'><h2>Confirmed</h2></div>"),
    ([{"CustomFields": {'breachconfirmation': 'Not Confirmed'}}],
     "<div style='color:green;'><h2>Pending Confirmation</h2></div>"
     )
]


@pytest.mark.parametrize('incidents, except_html', ARGS_MAIN)
def test_main(incidents, except_html, mocker):
    """
    Given:
        - query
    When:
        - main function is executed
    Then:
        - Return results to War-Room
    """
    expected_args = {'ContentsFormat': formats['html'], 'Type': entryTypes['note'], 'Contents': except_html}
    mocker.patch.object(demisto, "incidents", return_value=incidents)
    moc = mocker.patch.object(demisto, 'results')
    main()
    assert moc.call_args.args[0] == expected_args
