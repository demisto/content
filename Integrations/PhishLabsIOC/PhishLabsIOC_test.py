import demistomock as demisto
from CommonServerPython import *


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

    phishlabs_result = {
        'ID': 'def',
        'CreatedAt': '2019-05-14T13:03:45Z',
        'UpdatedAt': '',
        'Type': 'Attachment',
        'Attribute': [
            {
                'CreatedAt': '2019-05-14T13:03:45Z',
                'Name': 'md5',
                'Value': 'c8092abd8d581750c0530fa1fc8d8318'
            },
            {
                'CreatedAt': '2019-05-14T13:03:45Z',
                'Name': 'filetype',
                'Value': 'application/zip'
            },
            {
                'CreatedAt': '2019-05-14T13:03:45Z',
                'Name': 'name',
                'Value': 'Baycc.zip'
            }
    ]}
    global_entry = {
        'Name': file_name,
        'Type': file_type,
        'MD5': file_md5
    }

    global_result = {
        'Name': 'Baycc.zip',
        'Type': 'application/zip',
        'MD5': 'c8092abd8d581750c0530fa1fc8d8318'
    }

    context = populate_context([], [], (global_entry, phishlabs_entry), [])
    print(str(context))
    assert len(context.keys()) == 2
    assert context[outputPaths['file']] == global_result
    assert context['PhishLabs.File(val.ID && val.ID === obj.ID)'] == phishlabs_result

