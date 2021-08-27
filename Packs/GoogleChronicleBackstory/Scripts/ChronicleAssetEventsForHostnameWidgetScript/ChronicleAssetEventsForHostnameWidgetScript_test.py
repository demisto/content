from unittest.mock import patch

import ChronicleAssetEventsForHostnameWidgetScript


def test_main_success(mocker):
    """
        When main function is called, set_arguments_for_widget_view should be called.
    """

    mocker.patch.object(ChronicleAssetEventsForHostnameWidgetScript, 'set_arguments_for_widget_view', return_value={})
    ChronicleAssetEventsForHostnameWidgetScript.main()
    assert ChronicleAssetEventsForHostnameWidgetScript.set_arguments_for_widget_view.called


@patch('ChronicleAssetEventsForHostnameWidgetScript.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """

    mocker.patch.object(ChronicleAssetEventsForHostnameWidgetScript, 'set_arguments_for_widget_view',
                        side_effect=Exception)
    with capfd.disabled():
        ChronicleAssetEventsForHostnameWidgetScript.main()

    mock_return_error.assert_called_once_with('Could not load widget:\n')


def test_set_arguments_for_widget_view_when_hostname_is_empty():
    """
        When chronicleassethostname indicator field is kept empty,
        set_arguments_for_widget_view should return empty argument dictionary.
    """

    # set arguments for command
    indicator_data = {
        'CustomFields': {
        }
    }

    # Execute
    arguments = ChronicleAssetEventsForHostnameWidgetScript.set_arguments_for_widget_view(indicator_data)
    # Assert
    assert {} == arguments


def test_set_arguments_for_widget_view_when_hostname_is_valid():
    """
        When chronicleassethostname indicator field has valid value,
        set_arguments_for_widget_view should set the arguments successfully.
    """

    # set argument for command
    indicator_data = {
        'CustomFields': {
            'chronicleassethostname': 'dummyhost.com'
        }
    }
    # set expected output
    expected_arguments = {
        'asset_identifier': 'dummyhost.com',
        'asset_identifier_type': 'Host Name',
        'preset_time_range': 'Last 30 days'
    }
    # Execute
    arguments = ChronicleAssetEventsForHostnameWidgetScript.set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_arguments == arguments
