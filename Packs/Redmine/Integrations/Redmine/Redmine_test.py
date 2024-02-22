import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_baseintegration_dummy():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
from Redmine import (
    Client,
    remove_issue_watcher_command,
    delete_issue_by_id_command,
    get_custom_fields_command,
    add_issue_watcher_command,
    get_project_list_command,
    get_issues_list_command,
    get_issue_by_id_command,
    create_issue_command,
    update_issue_command,
    get_users_command,
)

# @pytest.mark.parametrize(
#     "content_item, expected_result",
#     [
#         (create_integration_object(), []),
#     ]
# )
# def test_ImageExistsValidator_is_valid_image_path(content_item, expected_result):
#     """
#     Given
#     content_item with a valid image path.
    
#     When
#     - Calling the ImageExistsValidator is_valid function.
    
#     Then
#     - Make sure the expected result matches the function result.
#     """
#     result = ImageExistsValidator().is_valid([content_item])

#     assert (
#         result == expected_result
#         if isinstance(expected_result, list)
#         else result[0].message == expected_result)

def create_client(url: str = 'url', verify_certificate: bool = True, proxy: bool = False):
    return Client(url, verify_certificate, proxy)

def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())

client = Client(base_url='some_mock_url', verify=False)
args = {
    'dummy': 'this is a dummy response'
}
response = baseintegration_dummy_command(client, args)

mock_response = util_load_json('test_data/baseintegration-dummy.json')

assert response.outputs == mock_response
