import json

from EWSO365 import (
    find_folders,
    get_searchable_mailboxes,
    GetSearchableMailboxes,
    ExpandGroup,
    get_expanded_group,
)

with open("test_data/commands_outputs.json", "r") as f:
    COMMAND_OUTPUTS = json.load(f)
with open("test_data/raw_responses.json", "r") as f:
    RAW_RESPONSES = json.load(f)


class TestNormalCommands:
    """
    The test class checks the following normal_commands:
        * ews-find-folders
    """

    class MockClient:
        class MockAccount:
            def __init__(self):
                self.root = self
                self.walk_res = []
                self.all_res = ""
                self.contacts = self

            def walk(self):
                return self.walk_res

            def tree(self):
                return ""

            def all(self):
                return self.all_res

        def __init__(self):
            self.default_target_mailbox = ""
            self.client_id = ""
            self.client_secret = ""
            self.tenant_id = ""
            self.folder = ""
            self.is_public_folder = ""
            self.request_timeout = ""
            self.max_fetch = ""
            self.self_deployed = ""
            self.insecure = ""
            self.proxy = ""
            self.account = self.MockAccount()
            self.protocol = ""

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
        This test checks the following normal_command:
            * ews-find-folders
        Using this method:
        Given:
            - command name is ews-find-folders
            - client function name to mock
            - expected raw result
            - expected command result
        When:
            - we want to execute the command function
        Then:
            - the expected result will be the same as the entry context
        """
        command_name = "ews-find-folders"

        raw_response = RAW_RESPONSES[command_name]
        expected = COMMAND_OUTPUTS[command_name]
        client = self.MockClient()
        client.account.walk_res = raw_response
        res = find_folders(client)
        actual_ec = res[1]
        assert expected == actual_ec

    def test_get_searchable_mailboxes(self, mocker):
        """
        This test checks the following normal_command:
            * ews-get-searchable-mailboxes
        Using this method:
        Given:
            - command name is ews-get-searchable-mailboxes
            - client function name to mock
            - expected raw result
            - expected command result
        When:
            - we want to execute the command function
        Then:
            - the expected result will be the same as the entry context
        """
        command_name = "ews-get-searchable-mailboxes"
        expected = COMMAND_OUTPUTS[command_name]
        raw_response = RAW_RESPONSES["ews-get-searchable-mailboxes"]
        mocker.patch.object(GetSearchableMailboxes, "__init__", return_value=None)
        mocker.patch.object(GetSearchableMailboxes, "call", return_value=raw_response)
        client = self.MockClient()
        res = get_searchable_mailboxes(client)
        actual_ec = res[1]
        assert expected == actual_ec

    def test_expand_group(self, mocker):
        """
        This test checks the following normal_command:
            * ews-expand-group
        Using this method:
        Given:
            - command name is ews-expand-group
            - client function name to mock
            - expected raw result
            - expected command result
        When:
            - we want to execute the command function
        Then:
            - the expected result will be the same as the entry context
        """
        command_name = "ews-expand-group"
        expected = COMMAND_OUTPUTS[command_name]
        raw_response = RAW_RESPONSES[command_name]
        mocker.patch.object(ExpandGroup, "__init__", return_value=None)
        mocker.patch.object(ExpandGroup, "call", return_value=raw_response)
        client = self.MockClient()
        res = get_expanded_group(
            client, email_address="testgroup-1@demistodev.onmicrosoft.com"
        )
        actual_ec = res[1]
        assert expected == actual_ec
