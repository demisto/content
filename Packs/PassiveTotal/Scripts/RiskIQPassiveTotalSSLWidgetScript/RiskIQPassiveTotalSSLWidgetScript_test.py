from RiskIQPassiveTotalSSLWidgetScript import set_arguments_for_widget_view


def test_for_ssl_widget_set_arguments_for_widget_view_when_indicator_type_file_sha_1():
    # Configure

    # set argument for command
    indicator_data = {
        'indicator_type': 'file sha-1',
        'value': 'dummy file sha-1'
    }
    # set expected output
    expected_arguments = {
        'field': 'sha1',
        'query': 'dummy file sha-1'
    }
    # Execute
    arguments = set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_arguments == arguments


def test_for_ssl_widget_set_arguments_for_widget_view_when_indicator_type_riskiqserialnumber():
    # Configure

    # set argument for command
    indicator_data = {
        'indicator_type': 'riskiqserialnumber',
        'value': 'dummy riskiq serial-number'
    }
    # set expected output
    expected_arguments = {
        'field': 'serialNumber',
        'query': 'dummy riskiq serial-number'
    }
    # Execute
    arguments = set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_arguments == arguments
