from unittest.mock import patch

import ChronicleAssetEventsForIPWidgetScript


def test_main_success(mocker):
    """
        When main function is called, set_arguments_for_widget_view should be called.
    """

    mocker.patch.object(ChronicleAssetEventsForIPWidgetScript, 'set_arguments_for_widget_view', return_value={})
    ChronicleAssetEventsForIPWidgetScript.main()
    assert ChronicleAssetEventsForIPWidgetScript.set_arguments_for_widget_view.called


@patch('ChronicleAssetEventsForIPWidgetScript.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """

    mocker.patch.object(ChronicleAssetEventsForIPWidgetScript, 'set_arguments_for_widget_view',
                        side_effect=Exception)
    with capfd.disabled():
        ChronicleAssetEventsForIPWidgetScript.main()

    mock_return_error.assert_called_once_with('Could not load widget:\n')


def test_set_arguments_for_widget_view_when_ip_is_empty():
    """
        When chronicleassetip indicator field is kept empty,
        set_arguments_for_widget_view should return empty argument dictionary.
    """

    # set arguments for command
    indicator_data = {
        'CustomFields': {
        }
    }

    # Execute
    arguments = ChronicleAssetEventsForIPWidgetScript.set_arguments_for_widget_view(indicator_data)
    # Assert
    assert {} == arguments


def test_set_arguments_for_widget_view_when_ip_is_valid():
    """
        When chronicleassetip indicator field has valid value,
        set_arguments_for_widget_view should set the arguments successfully.
    """

    # set argument for command
    indicator_data = {
        'CustomFields': {
            'chronicleassetip': '0.0.0.0'
        }
    }
    # set expected output
    expected_arguments = {
        'asset_identifier': '0.0.0.0',
        'asset_identifier_type': 'IP Address',
        'preset_time_range': 'Last 30 days'
    }
    # Execute
    arguments = ChronicleAssetEventsForIPWidgetScript.set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_arguments == arguments
