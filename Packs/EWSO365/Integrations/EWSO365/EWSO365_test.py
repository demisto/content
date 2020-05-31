import json
import pytest

from EWSO365 import get_searchable_mailboxes, find_folders


class TestNormalCommands:
    """
    The test class checks the following normal_commands:
        * ews-find-folders
    """
    with open("test_data/commands_outputs.json", "r") as f:
        COMMAND_OUTPUTS = json.load(f)
    with open("test_data/raw_responses.json", "r") as f:
        RAW_RESPONSES = json.load(f)


    class MockClient:
        class MockAccount:
            def __init__(self):
                self.root = self
                self.walk_res = []

            def walk(self):
                return self.walk_res

            def tree(self):
                return ''

        def __init__(self):
            self.default_target_mailbox = ''
            self.client_id = ''
            self.client_secret = ''
            self.tenant_id = ''
            self.folder = ''
            self.is_public_folder = ''
            self.request_timeout = ''
            self.max_fetch = ''
            self.self_deployed = ''
            self.insecure = ''
            self.proxy = ''
            self.account = self.MockAccount()

        def get_account(self, target_mailbox=None, access_type=None):
            return self.account

        def get_items_from_mailbox(self, account, item_ids):
            return ""

        def get_item_from_mailbox(self, account, item_id):
            return ""

        def get_attachments_for_item(self, item_id, account, attachment_ids=None):
            return ""

        def is_default_folder(self, folder_path, is_public):
            return ""

        def get_folder_by_path(self, path, account=None, is_public=False):
            return ""

    def test_ews_find_folders(self):
        """
        This test checks the following normal_commands:
            * ews-find-folders
        Using this method:
        Given:
            - command name is ews-find-folders
            - client function name to mock
            - expected client function result
            - expected command result
        When:
            - we want to execute command function
        Then:
            - the expected result will be the same as the entry context
        """
        command_name = 'ews-find-folders'
        raw_response = self.RAW_RESPONSES[command_name]
        expected = self.COMMAND_OUTPUTS[command_name]
        client = self.MockClient()
        client.account.walk_res = raw_response
        res = find_folders(client)
        actual_ec = res[1]
        assert expected == actual_ec
    #
    # @pytest.mark.parametrize(
    #     "command_name,command_func,client_func,args", TEST_COMMANDS_LIST_CLIENT_RQRD
    # )
    # def test_commands(self, command_name, command_func, client_func, args, mocker):
    #     """
    #     This test checks the following normal_commands:
    #         * ews-find-folders
    #
    #     Using this method:
    #
    #     Given:
    #         - command function
    #         - args
    #         - client function name to mock
    #         - expected client function result
    #         - expected command result
    #     When:
    #         - we want to execute command function with args
    #     Then:
    #         - the expected result will be the same as actual
    #     """
    #     raw_response = self.RAW_RESPONSES[command_name]
    #     expected = self.COMMAND_OUTPUTS[command_name]
    #     client = self.MockClient()
    #     mocker.patch.object(client, client_func, return_value=raw_response)
    #     res = command_func(client, **args)
    #     assert expected == res[1]
