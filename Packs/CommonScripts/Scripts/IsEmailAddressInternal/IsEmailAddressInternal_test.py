import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from IsEmailAddressInternal import main


def test_is_email_internal(mocker,):
    """
    Given:
        - The script args.
    When:
        - Running the print_context function.
    Then:
        - Validating the outputs as expected.
    """
    mocker.patch.object(demisto, 'args', return_value={'domain': 'domain.com',
                                                       'email': 'email@domain.com'})
    mocker.patch.object(demisto, 'get', return_value='domain.com')
    mocker.patch.object(demisto, 'getArg', return_value='no')
    results_mock = mocker.patch.object(demisto, 'results')
    main()
    res = results_mock.call_args[0][0]['Contents']
    assert res == 'yes'
