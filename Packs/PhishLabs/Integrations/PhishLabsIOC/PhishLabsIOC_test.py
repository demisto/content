from CommonServerPython import *


def test_create_indicator_no_date():
    from PhishLabsIOC import create_indicator_content

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
                "value": "c8092abd8d581750c0530fa1fc8d8318"
            } """

    result = {
        'ID': 'def',
        'Indicator': 'c8092abd8d581750c0530fa1fc8d8318',
        'Type': 'Attachment',
        'CreatedAt': '2019-05-14T13:03:45Z',
        'UpdatedAt': '',
        'FalsePositive': False,
    }

    indicator = json.loads(files_json)

    actual = create_indicator_content(indicator)

    assert actual == result


def test_create_indicator_with_none_date():
    from PhishLabsIOC import create_indicator_content

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
                "updatedAt": "0001-01-01T00:00:00Z",
                "falsePositive": false,
                "id": "def",
                "type": "Attachment",
                "value": "c8092abd8d581750c0530fa1fc8d8318"
            } """

    result = {
        'ID': 'def',
        'Indicator': 'c8092abd8d581750c0530fa1fc8d8318',
        'Type': 'Attachment',
        'CreatedAt': '2019-05-14T13:03:45Z',
        'UpdatedAt': '',
        'FalsePositive': False,
    }

    indicator = json.loads(files_json)

    actual = create_indicator_content(indicator)

    assert actual == result


def test_create_indicator_with_date():
    from PhishLabsIOC import create_indicator_content

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
                "updatedAt": "2019-05-14T13:03:45Z",
                "falsePositive": false,
                "id": "def",
                "type": "Attachment",
                "value": "c8092abd8d581750c0530fa1fc8d8318"
            } """

    result = {
        'ID': 'def',
        'Indicator': 'c8092abd8d581750c0530fa1fc8d8318',
        'Type': 'Attachment',
        'CreatedAt': '2019-05-14T13:03:45Z',
        'UpdatedAt': '2019-05-14T13:03:45Z',
        'FalsePositive': False,
    }

    indicator = json.loads(files_json)

    actual = create_indicator_content(indicator)

    assert actual == result


def test_populate_context_files():
    from PhishLabsIOC import populate_context, get_file_properties, create_phishlabs_object
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
    file = json.loads(files_json)
    file_md5, file_name, file_type = get_file_properties(file)

    phishlabs_entry = create_phishlabs_object(file)

    phishlabs_entry['Name'] = file_name
    phishlabs_entry['Type'] = file_type
    phishlabs_entry['MD5'] = file_md5

    phishlabs_result = [{
        'ID': 'def',
        'CreatedAt': '2019-05-14T13:03:45Z',
        'Name': 'Baycc.zip',
        'Type': 'application/zip',
        'MD5': 'c8092abd8d581750c0530fa1fc8d8318',
        'Attribute': [
            {
                'CreatedAt': '2019-05-14T13:03:45Z',
                'Type': None,
                'Name': 'md5',
                'Value': 'c8092abd8d581750c0530fa1fc8d8318'
            },
            {
                'CreatedAt': '2019-05-14T13:03:45Z',
                'Type': None,
                'Name': 'filetype',
                'Value': 'application/zip'
            },
            {
                'CreatedAt': '2019-05-14T13:03:45Z',
                'Type': None,
                'Name': 'name',
                'Value': 'Baycc.zip'
            }
        ]
    }]

    global_entry = {
        'Name': file_name,
        'Type': file_type,
        'MD5': file_md5
    }

    global_result = [{
        'Name': 'Baycc.zip',
        'Type': 'application/zip',
        'MD5': 'c8092abd8d581750c0530fa1fc8d8318'
    }]

    context = populate_context([], [], [(global_entry, phishlabs_entry)], [])

    assert len(context.keys()) == 2
    assert context[outputPaths['file']] == global_result
    assert context['PhishLabs.File(val.ID && val.ID === obj.ID)'] == phishlabs_result


def test_populate_context_emails():
    from PhishLabsIOC import populate_context, get_email_properties, create_phishlabs_object
    emails_json = """
        {
           "attributes":[
              {
                 "createdAt":"2019-05-13T16:54:18Z",
                 "id":"abc",
                 "name":"email-body",
                 "value":"-----Original Message-----From: A Sent: Monday, May 13, 2019 12:22 PMTo:"
              },
              {
                 "createdAt":"2019-05-13T16:54:18Z",
                 "id":"def",
                 "name":"from",
                 "value":"foo@test.com"
              },
              {
                 "createdAt":"2019-05-13T16:54:18Z",
                 "id":"cf3182ca-92ec-43b6-8aaa-429802a99fe5",
                 "name":"to",
                 "value":"example@gmail.com"
              }
           ],
           "createdAt":"2019-05-13T16:54:18Z",
           "falsePositive":false,
           "id":"ghi",
           "type":"E-mail",
           "updatedAt":"0001-01-01T00:00:00Z",
           "value":"FW: Task"
        } """
    email = json.loads(emails_json)
    email_body, email_to, email_from = get_email_properties(email)

    phishlabs_entry = create_phishlabs_object(email)

    phishlabs_entry['To'] = email_to,
    phishlabs_entry['From'] = email_from,
    phishlabs_entry['Body'] = email_body
    phishlabs_entry['Subject'] = email.get('value')

    phishlabs_result = [{
        'ID': 'ghi',
        'CreatedAt': '2019-05-13T16:54:18Z',
        'To': ('example@gmail.com',),
        'From': ('foo@test.com',),
        'Body': '-----Original Message-----From: A Sent: Monday, May 13, 2019 12:22 PMTo:',
        'Subject': 'FW: Task',
        'Attribute':
            [{
                'CreatedAt': '2019-05-13T16:54:18Z',
                'Type': None,
                'Name': 'email-body',
                'Value': '-----Original Message-----From: A Sent: Monday, May 13, 2019 12:22 PMTo:'
            },
            {
                'CreatedAt': '2019-05-13T16:54:18Z',
                'Type': None,
                'Name': 'from',
                'Value': 'foo@test.com'
            },
            {
                'CreatedAt': '2019-05-13T16:54:18Z',
                'Type': None,
                'Name': 'to',
                'Value': 'example@gmail.com'
            }]
    }]

    global_entry = {
        'To': email_to,
        'From': email_from,
        'Body': email_body,
        'Subject': email.get('value')
    }

    global_result = [{
        'To': 'example@gmail.com',
        'From': 'foo@test.com',
        'Body': '-----Original Message-----From: A Sent: Monday, May 13, 2019 12:22 PMTo:',
        'Subject': 'FW: Task'
    }]

    context = populate_context([], [], [], [], [(global_entry, phishlabs_entry)])

    assert len(context.keys()) == 2
    assert context['Email'] == global_result
    assert context['PhishLabs.Email(val.ID && val.ID === obj.ID)'] == phishlabs_result


def test_indicator_type_finder():
    from PhishLabsIOC import indicator_type_finder
    indicator_data_1 = {
        'value': 'email@email.com',
        'type': "Sender"
    }

    indicator_data_2 = {
        'value': 'https://www.some.path/email@email.com',
        'type': "URL"
    }

    assert indicator_type_finder(indicator_data_1) == 'Email'
    assert indicator_type_finder(indicator_data_2) == 'URL'
