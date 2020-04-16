import base64
import pytest
from GooglePubSub import GoogleNameParser, PubSubClient, \
    convert_publish_datetime_to_str, message_to_incident, attribute_pairs_to_dict, get_publish_body, \
    extract_acks_and_msgs, publish_message_command, pull_messages_command, subscriptions_list_command, \
    get_subscription_command, create_subscription_command, update_subscription_command, topics_list_command, \
    create_topic_command, delete_topic_command, update_topic_command, seek_message_command, snapshot_list_command, \
    snapshot_create_command, snapshot_update_command, snapshot_delete_command
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

    def test_convert_publish_datetime_to_str(self):
        """
        Given:
            - date with ms
            - date without ms
        When:
            - we want the publish_time in str
        Then:
            - convert_publish_datetime_to_str should convert the dates to the same string
        """
        datetime_no_ms = dateparser.parse(self.DATE_NO_MS)
        assert f'{self.DATE_NO_MS[:-1]}.000000Z' == convert_publish_datetime_to_str(datetime_no_ms)

        datetime_with_ms = dateparser.parse(self.DATE_WITH_MS)
        assert self.DATE_WITH_MS == convert_publish_datetime_to_str(datetime_with_ms)

    def test_message_to_incident(self):
        """
        Given:
            - pulled message
        When:
            - we want to convert it to an incident
        Then:
            - message_to_incident should convert it correctly
        """
        incident = message_to_incident(self.MOCK_MESSAGE)
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
            expected = ([1], [{'data': 'decoded message'}])
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
            expected = ([1, 2], [{'data': 'decoded message'}, {'data': '', 'attributes': {'q': 'a'}}])
            assert expected == extract_acks_and_msgs(raw_msgs)


# class TestCommands:
#     TEST_COMMANDS_LIST = [
#         # google-cloud-pubsub-topic-publish-message
#         (publish_message_command, {}, 'publish_message', '', ''),
#         # google-cloud-pubsub-topic-messages-pull
#         (pull_messages_command, {}, 'pull_messages', '', ''),
#         # google-cloud-pubsub-topic-subscriptions-list
#         (subscriptions_list_command, {}, 'list_topic_subs', '', ''),
#         # google-cloud-pubsub-topic-subscription-get-by-name
#         (get_subscription_command, {'project_id': '1', 'subscription_id': '1'}, 'get_sub', '', ''),
#         # google-cloud-pubsub-topic-subscription-create
#         (create_subscription_command, {'project_id': '1', 'subscription_id': '1', 'topic_id': '1'}, 'create_subscription', '', ''),
#         # google-cloud-pubsub-topic-subscription-update
#         (update_subscription_command,),
#         # google-cloud-pubsub-topics-list
#         (topics_list_command,),
#         # google-cloud-pubsub-topic-create
#         (create_topic_command,),
#         # google-cloud-pubsub-topic-delete
#         (delete_topic_command,),
#         # google-cloud-pubsub-topic-update
#         (update_topic_command,),
#         # google-cloud-pubsub-topic-messages-seek
#         (seek_message_command,),
#         # google-cloud-pubsub-topic-snapshots-list
#         (snapshot_list_command,),
#         # google-cloud-pubsub-topic-snapshot-create
#         (snapshot_create_command,),
#         # google-cloud-pubsub-topic-snapshot-update
#         (snapshot_update_command,),
#         # google-cloud-pubsub-topic-snapshot-delete
#         (snapshot_delete_command,)
#     ]
#
#     @pytest.mark.parametrize('command,args,client_func,func_result,expected_result', TEST_COMMANDS_LIST)
#     def test_commands(self, command, args, client_func, func_result, expected_result, mocker):
#         """
#         Given:
#             - command function
#             - args
#             - client function name to mock
#             - expected client function result
#             - expected command result
#         When:
#             - we want project_name
#         Then:
#             - GoogleNameParser should parse it in the expected format
#         """
#         client = Client(base_url='', verify=False, proxy=True, headers=headers)
#         mocker.patch.object(client, '_http_request', return_value=response)
#         res = command(client, args)
#         assert expected_result == res[1]
