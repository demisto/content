import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_main(mocker):
    """Test the main function of TestSupportedModulesScript."""
    from TestSupportedModulesScript import main

    mocker.patch.object(demisto, 'results')
    main()
