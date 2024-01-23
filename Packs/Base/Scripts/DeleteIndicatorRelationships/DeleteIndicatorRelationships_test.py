# import DeleteIndicatorRelationships
from DeleteIndicatorRelationships import *
import demistomock as demisto
# from CommonServerPython import entryTypes


def test_main_success(mocker):
    """
    Given a list of relationship IDs as input
    When deleteRelationships command executes successfully
    Then return success results
    """
    mocker.patch('DeleteIndicatorRelationships.is_error', return_value=False)
    mocker.patch.object(demisto, 'args', return_value={'ids': [1, 2]})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', return_value=[{}])

    main()
    assert demisto.results.call_count == 1


def test_main_failure(mocker):
    """
    Given a list of relationship IDs as input
    When deleteRelationships command fails
    Then return error
    """
    mocker.patch.object(demisto, 'args', return_value={'ids': [1, 2]})
    mocker.patch.object(demisto, 'executeCommand', return_value=[{"Type": entryTypes['error'], 'Contents': 'test'}])
    return_error = mocker.patch('DeleteIndicatorRelationships.return_error')

    main()
    assert return_error.call_count == 1
