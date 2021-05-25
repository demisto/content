from RiskIQPassiveTotalWhoisWidgetScript import set_arguments_for_widget_view


def test_for_whois_widget_set_arguments_for_widget_view_when_indicator_type_riskiqasset_and_riskiqassettype_is_empty():
    # Configure

    # set argument for command
    indicator_data = {
        'indicator_type': 'RiskIQAsset',
        'value': 'dummy domain',
        'CustomFields': {
            'riskiqassettype': ''
        }
    }
    # set expected output
    expected_output = 'Please provide value in the "RiskIQAsset Type" field to fetch detailed information of the asset.'
    # Execute
    arguments = set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_output == arguments


def test_for_whois_widget_set_arguments_for_widget_view_when_indicator_type_riskiqasset_and_riskiqassettype_domain():
    # Configure

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
        'field': 'domain',
        'query': 'dummy domain'
    }
    # Execute
    arguments = set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_arguments == arguments


def test_for_whois_widget_set_arguments_for_widget_view_when_indicator_type_riskiqasset_and_riskiqassettype_contact():
    # Configure

    # set argument for command
    indicator_data = {
        'indicator_type': 'RiskIQAsset',
        'value': 'dummy email',
        'CustomFields': {
            'riskiqassettype': 'Contact'
        }
    }
    # set expected output
    expected_arguments = {
        'field': 'email',
        'query': 'dummy email'
    }
    # Execute
    arguments = set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_arguments == arguments


def test_for_whois_widget_set_arguments_for_widget_view_when_indicator_type_riskiqasset():
    # Configure

    # set argument for command
    indicator_data = {
        'indicator_type': 'RiskIQAsset',
        'value': 'dummy email',
        'CustomFields': {
            'riskiqassettype': 'IP Address'
        }
    }
    # set expected output
    expected_output = 'No domain information were found for the given argument(s).'
    # Execute
    arguments = set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_output == arguments


def test_for_whois_widget_set_arguments_for_widget_view_when_indicator_type_domain():
    # Configure

    # set argument for command
    indicator_data = {
        'indicator_type': 'Domain',
        'value': 'dummy domain'
    }
    # set expected output
    expected_arguments = {
        'field': 'domain',
        'query': 'dummy domain'
    }
    # Execute
    arguments = set_arguments_for_widget_view(indicator_data)
    # Assert
    assert expected_arguments == arguments
