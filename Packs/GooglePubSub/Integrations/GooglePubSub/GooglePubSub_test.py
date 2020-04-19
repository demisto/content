import base64
import pytest
from GooglePubSub import GoogleNameParser, convert_datetime_to_iso_str, message_to_incident, \
    attribute_pairs_to_dict, get_publish_body, extract_acks_and_msgs, publish_message_command, pull_messages_command, \
    subscriptions_list_command, get_subscription_command, create_subscription_command, update_subscription_command, \
    topics_list_command, create_topic_command, delete_topic_command, update_topic_command, seek_message_command, \
    snapshot_list_command, snapshot_create_command, snapshot_update_command, snapshot_delete_command
import dateparser
import json


class TestGoogleNameParser:
    DFLT_PROJECT_ID = 'test_project'
    DFLT_TOPIC_ID = 'test_topic'
    DFLT_SUB_ID = 'test_sub'
    DFLT_SNAPSHOT_ID = 'snapshot_sub'

    def test_get_full_project_name(self):
        """
        Given:
            - project_id
        When:
            - we want project_name
        Then:
            - GoogleNameParser should parse it in the expected format
        """
        expected = f'projects/{self.DFLT_PROJECT_ID}'
        assert expected == GoogleNameParser.get_project_name(self.DFLT_PROJECT_ID)

    def test_get_full_topic_name(self):
        """
        Given:
            - project_id
            - topic_id
        When:
            - we want topic_name
        Then:
            - GoogleNameParser should parse it in the expected format
        """
        expected = f'projects/{self.DFLT_PROJECT_ID}/topics/{self.DFLT_TOPIC_ID}'
        assert expected == GoogleNameParser.get_topic_name(self.DFLT_PROJECT_ID, self.DFLT_TOPIC_ID)

    def test_get_full_subscription_project_name(self):
        """
        Given:
            - project_id
            - subscription_id
        When:
            - we want subscription_name
        Then:
            - GoogleNameParser should parse it in the expected format
        """
        expected = f'projects/{self.DFLT_PROJECT_ID}/subscriptions/{self.DFLT_SUB_ID}'
        assert expected == GoogleNameParser.get_subscription_project_name(self.DFLT_PROJECT_ID, self.DFLT_SUB_ID)

    def test_get_full_subscription_topic_name(self):
        """
        Given:
            - project_id
            - topic_id
            - subscription_id
        When:
            - we want topic subscription_name
        Then:
            - GoogleNameParser should parse it in the expected format
        """
        expected = f'projects/{self.DFLT_PROJECT_ID}/topics/{self.DFLT_TOPIC_ID}/subscriptions/{self.DFLT_SUB_ID}'
        assert expected == GoogleNameParser.get_subscription_topic_name(self.DFLT_PROJECT_ID, self.DFLT_TOPIC_ID,
                                                                        self.DFLT_SUB_ID)

    def test_get_snapshot_project_name(self):
        """
        Given:
            - project_id
            - snapshot_id
        When:
            - we want snapshot_name
        Then:
            - GoogleNameParser should parse it in the expected format
        """
        expected = f'projects/{self.DFLT_PROJECT_ID}/snapshots/{self.DFLT_SNAPSHOT_ID}'
        assert expected == GoogleNameParser.get_snapshot_project_name(self.DFLT_PROJECT_ID, self.DFLT_SNAPSHOT_ID)


class TestHelperFunctions:
    DECODED_B64_MESSAGE = 'decoded message'
    ENCODED_B64_MESSAGE = str(base64.b64encode(DECODED_B64_MESSAGE.encode("utf8")))[2:-1]
    DATE_NO_MS = '2020-01-01T11:11:11Z'
    DATE_WITH_MS = '2020-01-01T11:11:11.123000Z'
    MOCK_MESSAGE = {
        'messageId': '123',
        'publishTime': DATE_WITH_MS
    }

    def test_convert_datetime_to_iso_str(self):
        """
        Given:
            - date with ms
            - date without ms
        When:
            - we want the publish_time in str
        Then:
            - convert_datetime_to_iso_str should convert the dates to the same string
        """
        datetime_no_ms = dateparser.parse(self.DATE_NO_MS)
        assert f'{self.DATE_NO_MS[:-1]}.000000Z' == convert_datetime_to_iso_str(datetime_no_ms)

        datetime_with_ms = dateparser.parse(self.DATE_WITH_MS)
        assert self.DATE_WITH_MS == convert_datetime_to_iso_str(datetime_with_ms)

    def test_message_to_incident(self):
        """
        Given:
            - pulled message
        When:
            - we want to convert it to an incident
        Then:
            - message_to_incident should convert it correctly
        """
        incident, _ = message_to_incident(self.MOCK_MESSAGE)
        assert self.DATE_WITH_MS == incident.get('occurred')
        assert f'Google PubSub Message {self.MOCK_MESSAGE.get("messageId")}' == incident.get('name')
        assert json.dumps(self.MOCK_MESSAGE) == incident.get('rawJSON')

    class TestGetPublishBody:
        def test_get_publish_body__invalid(self):
            """
            Given:
                - invalid message data
            When:
                - we try to create a publish body
            Then:
                - throw an exception
            """
            # invalid message_data
            e_thrown = False
            try:
                get_publish_body('', message_data={'test': 'val'})
            except AttributeError:
                e_thrown = True
            assert e_thrown

            # invalid message_attributes
            e_thrown = False
            try:
                get_publish_body(message_attributes={'test': 'val'}, message_data='')
            except AttributeError:
                e_thrown = True
            assert e_thrown

        def test_get_publish_body__empty(self):
            """
            Given:
                - empty message data
            When:
                - we try to create a publish body
            Then:
                - return a body with no messages
            """
            expected = {"messages": [{}]}
            assert expected == get_publish_body('', '')

        def test_get_publish_body__valid(self):
            """
            Given:
                message with
                - 2 attributes
                - decrypted message
            When:
                - we try to create a publish body
            Then:
                return a body with
                - attributes dict
                - encrypted message
            """
            key_1 = 't_key1'
            val_1 = 't_val1'
            key_2 = 't_key2'
            val_2 = 't_val2'
            attrs_str = f'{key_1}={val_1},{key_2}={val_2}'
            expected_attributes = {key_1: val_1, key_2: val_2}
            expected_data = TestHelperFunctions.ENCODED_B64_MESSAGE
            expected = {"messages": [{'data': expected_data, 'attributes': expected_attributes}]}
            assert expected == get_publish_body(attrs_str, TestHelperFunctions.DECODED_B64_MESSAGE)

    class TestAttributePairsToDict:
        def test_attribute_pairs_to_dict__invalid(self):
            """
            Given:
                - invalid attribute pairs
            When:
                - converting attribute pairs to dict
            Then:
                - throw an error
            """
            e_thrown = False
            try:
                attribute_pairs_to_dict({'1': '1'})
            except AttributeError:
                e_thrown = True
            assert e_thrown

        def test_attribute_pairs_to_dict__empty(self):
            """
            Given:
                - empty attribute pairs
            When:
                - converting attribute pairs to dict
            Then:
                - return attribute pairs
            """
            assert '' == attribute_pairs_to_dict('')
            assert attribute_pairs_to_dict(None) is None

        def test_attribute_pairs_to_dict__single(self):
            """
            Given:
                - single attribute pair
            When:
                - converting attribute pairs to dict
            Then:
                - return a single attribute pair dict
            """
            expected_key = 't_key'
            expected_val = 't_val'
            expected = {expected_key: expected_val}
            attrs_str = f'{expected_key}={expected_val}'
            assert expected == attribute_pairs_to_dict(attrs_str)

        def test_attribute_pairs_to_dict__multi(self):
            """
            Given:
                - multiple attribute pairs
            When:
                - converting attribute pairs to dict
            Then:
                - return multiple pairs in a dict
            """
            key_1 = 't_key1'
            val_1 = 't_val1'
            key_2 = 't_key2'
            val_2 = 't_val2'
            expected = {key_1: val_1, key_2: val_2}
            attrs_str = f'{key_1}={val_1},{key_2}={val_2}'
            assert expected == attribute_pairs_to_dict(attrs_str)

    class TestExtractAcksAndMsgs:
        def test_extract_acks_and_msgs__invalid(self):
            """
            Given:
                - invalid pulled messages response
            When:
                - we want to extract acks and messages
            Then:
                - return an empty array tuple
            """
            expected = tuple(([], []))
            assert expected == extract_acks_and_msgs('invalid')

            empty_raw_msgs = {'receivedMessages': {}}
            assert expected == extract_acks_and_msgs(empty_raw_msgs)

        def test_extract_acks_and_msgs__empty(self):
            """
            Given:
                - empty pulled messages response
            When:
                - we want to extract acks and messages
            Then:
                - return empty ack list, and message list with no message
            """
            expected = tuple(([], []))
            assert expected == extract_acks_and_msgs({})

            expected = tuple(([], [{'data': ''}]))
            invalid_raw_msgs = {'receivedMessages': [{}]}
            assert expected == extract_acks_and_msgs(invalid_raw_msgs)

        def test_extract_acks_and_msgs__single(self):
            """
            Given:
                - single pulled messages response
            When:
                - we want to extract acks and messages
            Then:
                - return ack list with ack id, and message list with decoded message
            """
            raw_msgs = {
                'receivedMessages': [{'ackId': 1, 'message': {'data': TestHelperFunctions.ENCODED_B64_MESSAGE}}]}
            expected = ([1], [{'data': 'decoded message', 'ackId': 1}])
            assert expected == extract_acks_and_msgs(raw_msgs)

        def test_extract_acks_and_msgs__multi(self):
            """
            Given:
                - multiple pulled messages response
            When:
                - we want to extract acks and messages
            Then:
                - return ack list with multi ack id, and message list with decoded messages
            """
            raw_msgs = {'receivedMessages': [
                {'ackId': 1, 'message': {'data': TestHelperFunctions.ENCODED_B64_MESSAGE}},
                {'ackId': 2, 'message': {'attributes': {'q': 'a'}}}
            ]}
            expected = ([1, 2], [{'data': 'decoded message', 'ackId': 1}, {'data': '', 'attributes': {'q': 'a'}, 'ackId': 2}])
            assert expected == extract_acks_and_msgs(raw_msgs)


class TestCommands:
    class MockClient:
        def publish_message(self, **kwargs): return ''
        def pull_messages(self, **kwargs): return ''
        def list_project_subs(self, a, b, c): return ''
        def get_sub(self, **kwargs): return ''
        def create_subscription(self, **kwargs): return ''
        def update_subscription(self, **kwargs): return ''
        def delete_subscription(self, **kwargs): return ''
        def list_topic(self, **kwargs): return ''
        def create_topic(self, **kwargs): return ''
        def delete_topic(self, a): return ''
        def update_topic(self, **kwargs): return ''
        def subscription_seek_message(self, **kwargs): return ''
        def get_project_snapshots_list(self, **kwargs): return ''
        def create_snapshot(self, **kwargs): return ''
        def update_snapshot(self, **kwargs): return ''
        def delete_snapshot(self, **kwargs): return ''
        def ack_messages(self, a, b): return ''

    with open('test_data/commands_outputs.json', 'r') as f:
        COMMAND_OUTPUTS = json.load(f)
    with open('test_data/raw_responses.json', 'r') as f:
        RAW_RESPONSES = json.load(f)

    TEST_COMMANDS_LIST = [
        ('gcp-pubsub-topic-publish-message',
         publish_message_command, 'publish_message', {'data': "42", 'project_id': 'dmst-doc-prjct', 'topic_id': 'dmst-test-topic'}),
        ('gcp-pubsub-topic-messages-pull',
         pull_messages_command, 'pull_messages', {'ack': 'true', 'max_messages': '1', 'project_id': 'dmst-doc-prjct', 'subscription_id': 'test_sub_2'}),
        ('gcp-pubsub-topic-subscriptions-list',
         subscriptions_list_command, 'list_project_subs', {'project_id': 'dmst-doc-prjct'}),
        ('gcp-pubsub-topic-subscription-get-by-name',
         get_subscription_command, 'get_sub', {'subscription_id': 'test_sub_2', 'project_id': 'dmst-doc-prjct'}),
        ('gcp-pubsub-topic-subscription-create',
         create_subscription_command, 'create_subscription', {'expiration_ttl': '86400s', 'project_id': 'dmst-doc-prjct', 'topic_id': 'dmst-test-topic', 'subscription_id': 'doc_sub_11'}),
        ('gcp-pubsub-topic-subscription-update',
         update_subscription_command, 'update_subscription', {'labels': "doc=true", 'project_id': 'dmst-doc-prjct', 'subscription_id': 'doc_sub_11', 'topic_id': 'dmst-test-topic', 'update_mask': 'labels'}),
        ('gcp-pubsub-topics-list',
         topics_list_command, 'list_topic', {'project_id': 'dmst-doc-prjct'}),
        ('gcp-pubsub-topic-create',
         create_topic_command, 'create_topic', {'project_id': 'dmst-doc-prjct', 'topic_id': 'dmst-doc-topic11'}),
        ('gcp-pubsub-topic-delete',
         delete_topic_command, 'delete_subscription', {'project_id': 'dmst-doc-prjct', 'topic_id': 'dmst-doc-topic11'}),
        ('gcp-pubsub-topic-update',
         update_topic_command, 'update_topic', {'project_id': 'dmst-doc-prjct', 'topic_id': 'dmst-doc-topic11', 'labels': "doc=true", 'update_mask': 'labels'}),
        ('gcp-pubsub-topic-messages-seek',
         seek_message_command, 'subscription_seek_message', {'project_id': 'dmst-doc-prjct', 'subscription_id': 'dean-sub1', 'time_string': '2020-04-10T00:00:00.123456Z'}),
        ('gcp-pubsub-topic-snapshots-list',
         snapshot_list_command, 'get_project_snapshots_list', {'project_id': 'dmst-doc-prjct'}),
        ('gcp-pubsub-topic-snapshot-create',
         snapshot_create_command, 'create_snapshot', {'project_id': 'dmst-doc-prjct', 'subscription_id': 'test_sub_2', 'snapshot_id': 'doc_snapshot'}),
        ('gcp-pubsub-topic-snapshot-update',
         snapshot_update_command, 'update_snapshot', {'project_id': 'dmst-doc-prjct', 'snapshot_id': 'doc_snapshot', 'labels': "doc=true", 'update_mask': 'labels', 'topic_id': 'dmst-test-topic'}),
        ('gcp-pubsub-topic-snapshot-delete',
         snapshot_delete_command, 'delete_snapshot', {'project_id': 'dmst-doc-prjct', 'snapshot_id': 'doc_snapshot'})
    ]

    @pytest.mark.parametrize('command_name,command_func,client_func,args, ', TEST_COMMANDS_LIST)
    def test_commands(self, command_name, command_func, client_func, args, mocker):
        """
        Given:
            - command function
            - args
            - client function name to mock
            - expected client function result
            - expected command result
        When:
            - we want to execute command function with args
        Then:
            - the expected result will be the same as actual
        """
        raw_response = self.RAW_RESPONSES[command_name]
        expected = self.COMMAND_OUTPUTS[command_name]
        client = self.MockClient()
        mocker.patch.object(client, client_func, return_value=raw_response)
        res = command_func(client, **args)
        with open('/Users/darbel/dev/demisto/content/Packs/GooglePubSub/Integrations/GooglePubSub/commands.json', 'w') as f:
            json.dump(res[1], f)
        assert expected == res[1]
