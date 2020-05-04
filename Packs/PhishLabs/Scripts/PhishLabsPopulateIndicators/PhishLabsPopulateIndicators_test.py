def test_indicator_type_finder():
    from PhishLabsPopulateIndicators import indicator_type_finder
    indicator_data_1 = {
        'value': 'email@email.com',
        'type': "Sender"
    }

    indicator_data_2 = {
        'value': 'https://www.some.path/email@email.com',
        'type': "URL"
    }

    indicator_data_3 = {
        'value': 'c8092abd8d581750c0530fa1fc8d8318',
        'type': "Attachment"
    }

    assert indicator_type_finder(indicator_data_1) == 'Email'
    assert indicator_type_finder(indicator_data_2) == 'URL'
    assert indicator_type_finder(indicator_data_3) == 'File'
