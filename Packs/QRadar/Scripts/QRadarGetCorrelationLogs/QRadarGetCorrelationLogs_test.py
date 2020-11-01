import pytest
import demistomock as demisto
from QRadarGetCorrelationLogs import main


@pytest.mark.parametrize('bool_val', ["True"])
def test_get_query_cre_name_null_true(mocker, bool_val):
    def executeCommand(name, args=None):
        mock_dict = {
            'Contents.events': None,
            'Type': 'JSON'
        }
        return [mock_dict, "\"CRE Name\" <> NULL" not in args["query_expression"]]

    mocker.patch.object(demisto, 'args', return_value={'is_cre_name_null': bool_val})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert results[0][1]


@pytest.mark.parametrize('bool_val', ["False"])
def test_get_query_cre_name_null_false(mocker, bool_val):
    def executeCommand(name, args=None):
        mock_dict = {
            'Contents.events': None,
            'Type': 'JSON'
        }
        return [mock_dict, "\"CRE Name\" <> NULL" not in args["query_expression"]]

    mocker.patch.object(demisto, 'args', return_value={'is_cre_name_null': bool_val})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert not results[0][1]
