import json


def test_indicator_type_and_value_finder_email_recognition():
    from PhishLabsPopulateIndicators import indicator_type_and_value_finder
    indicator_data_1 = {
        'value': 'email@email.com',
        'type': "Sender"
    }

    indicator_type_1, indicator_value_1 = indicator_type_and_value_finder(indicator_data_1)
    assert indicator_type_1 == 'Email'
    assert indicator_value_1 == 'email@email.com'


def test_indicator_type_and_value_finder_url_recognition():
    from PhishLabsPopulateIndicators import indicator_type_and_value_finder
    indicator_data_2 = {
        'value': 'https://www.some.path/email@email.com',
        'type': "URL"
    }

    indicator_type_2, indicator_value_2 = indicator_type_and_value_finder(indicator_data_2)
    assert indicator_type_2 == 'URL'
    assert indicator_value_2 == 'https://www.some.path/email@email.com'


def test_indicator_type_and_value_finder_file_recognition():
    from PhishLabsPopulateIndicators import indicator_type_and_value_finder
    files_json = """
            {
                "attributes": [
                    {
                        "createdAt": "2019-05-14T13:03:45Z",
                        "id": "xyz",
                        "name": "md5",
                        "value": "c8092abd8d581750c0530fa1fc8d8318"
                    },
                    {
                        "createdAt": "2019-05-14T13:03:45Z",
                        "id": "abc",
                        "name": "filetype",
                        "value": "application/zip"
                    },
                    {
                        "createdAt": "2019-05-14T13:03:45Z",
                        "id": "qwe",
                        "name": "name",
                        "value": "Baycc.zip"
                    }
                ],
                "createdAt": "2019-05-14T13:03:45Z",
                "falsePositive": false,
                "id": "def",
                "type": "Attachment",
                "updatedAt": "0001-01-01T00:00:00Z",
                "value": "c8092abd8d581750c0530fa1fc8d8318"
            } """

    indicator_data_3 = json.loads(files_json)

    indicator_type_3, indicator_value_3 = indicator_type_and_value_finder(indicator_data_3)
    assert indicator_type_3 == 'File'
    assert indicator_value_3 == 'c8092abd8d581750c0530fa1fc8d8318'
