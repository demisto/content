from unittest.mock import patch
import demistomock as demisto

import RiskIQDigitalFootprintAssetDetailsWidgetScript


def test_main_success(mocker):
    """
        When main function is called, set_arguments_for_widget_view should be called.
    """

    mocker.patch.object(RiskIQDigitalFootprintAssetDetailsWidgetScript, 'set_arguments_for_widget_view',
                        return_value='Please provide value in the "RiskIQAsset Type" field to fetch detailed'
                                     ' information of the asset.')
    RiskIQDigitalFootprintAssetDetailsWidgetScript.main()
    assert RiskIQDigitalFootprintAssetDetailsWidgetScript.set_arguments_for_widget_view.called


@patch('RiskIQDigitalFootprintAssetDetailsWidgetScript.return_error')
def test_main_failure(mock_return_error, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """

    mocker.patch.object(RiskIQDigitalFootprintAssetDetailsWidgetScript, 'set_arguments_for_widget_view',
                        side_effect=Exception)
    mocker.patch.object(demisto, 'error', return_value='')
    RiskIQDigitalFootprintAssetDetailsWidgetScript.main()

    mock_return_error.assert_called_once_with('Could not load widget:\n')


def test_set_arguments_for_widget_view_when_riskiqassettype_is_empty():
    """
        When riskiqassettpye indicator field is kept empty,
        set_arguments_for_widget_view should return a validation message.
    """

    # set arguments for command
    indicator_data = {
        'indicator_type': 'RiskIQAsset',
        'value': 'dummy domain',
        'CustomFields': {
        }
    }

    # Execute
    arguments = RiskIQDigitalFootprintAssetDetailsWidgetScript.set_arguments_for_widget_view(indicator_data)
    # Assert
    assert 'Please provide value in the "RiskIQAsset Type" field to fetch detailed information of the asset.'\
           == arguments


def test_set_arguments_for_widget_view_when_riskiqassettype_is_valid():
    """
        When riskiqassettpye indicator field has valid value,
        set_arguments_for_widget_view should set the arguments successfully.
    """

    # set argument for command
    indicator_data = {
        'indicator_type': 'RiskIQAsset',
        'value': 'dummy domain',
        'CustomFields': {
            'riskiqassettype': 'Domain'
        }
    }
    # set expected output
    expected_arguments = {
        'name': 'dummy domain',
        'type': 'Domain'
    }
    # Execute
    arguments = RiskIQDigitalFootprintAssetDetailsWidgetScript.set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_arguments == arguments
