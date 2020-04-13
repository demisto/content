import base64

from GooglePubSub import GoogleNameParser, convert_publish_datetime_to_str, message_to_incident, \
    attribute_pairs_to_dict, get_publish_body, extract_acks_and_msgs
import dateparser
import json


class TestGoogleNameParser:
    DFLT_PROJECT_ID = 'test_project'
    DFLT_TOPIC_ID = 'test_topic'
    DFLT_SUB_ID = 'test_sub'

    def test_get_full_project_name(self):
        expected = f'projects/{self.DFLT_PROJECT_ID}'
        assert expected == GoogleNameParser.get_project_name(self.DFLT_PROJECT_ID)

    def test_get_full_topic_name(self):
        expected = f'projects/{self.DFLT_PROJECT_ID}/topics/{self.DFLT_TOPIC_ID}'
        assert expected == GoogleNameParser.get_topic_name(self.DFLT_PROJECT_ID, self.DFLT_TOPIC_ID)

    def test_get_full_subscription_project_name(self):
        expected = f'projects/{self.DFLT_PROJECT_ID}/subscriptions/{self.DFLT_SUB_ID}'
        assert expected == GoogleNameParser.get_subscription_project_name(self.DFLT_PROJECT_ID, self.DFLT_SUB_ID)

    def test_get_full_subscription_topic_name(self):
        expected = f'projects/{self.DFLT_PROJECT_ID}/topics/{self.DFLT_TOPIC_ID}/subscriptions/{self.DFLT_SUB_ID}'
        assert expected == GoogleNameParser.get_subscription_topic_name(self.DFLT_PROJECT_ID, self.DFLT_TOPIC_ID,
                                                                        self.DFLT_SUB_ID)


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
        datetime_no_ms = dateparser.parse(self.DATE_NO_MS)
        assert f'{self.DATE_NO_MS[:-1]}.000000Z' == convert_publish_datetime_to_str(datetime_no_ms)

        datetime_with_ms = dateparser.parse(self.DATE_WITH_MS)
        assert self.DATE_WITH_MS == convert_publish_datetime_to_str(datetime_with_ms)

    def test_message_to_incident(self):
        incident = message_to_incident(self.MOCK_MESSAGE)
        assert self.DATE_WITH_MS == incident.get('occurred')
        assert f'Google PubSub Message {self.MOCK_MESSAGE.get("messageId")}' == incident.get('name')
        assert json.dumps(self.MOCK_MESSAGE) == incident.get('rawJSON')

    class TestGetPublishBody:
        def test_get_publish_body__invalid(self):
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
            expected = {"messages": [{}]}
            assert expected == get_publish_body('', '')

        def test_get_publish_body__valid(self):
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
            e_thrown = False
            try:
                attribute_pairs_to_dict({'1': '1'})
            except AttributeError:
                e_thrown = True
            assert e_thrown

        def test_attribute_pairs_to_dict__empty(self):
            assert '' == attribute_pairs_to_dict('')
            assert attribute_pairs_to_dict(None) is None

        def test_attribute_pairs_to_dict__single(self):
            expected_key = 't_key'
            expected_val = 't_val'
            expected = {expected_key: expected_val}
            attrs_str = f'{expected_key}={expected_val}'
            assert expected == attribute_pairs_to_dict(attrs_str)

        def test_attribute_pairs_to_dict__multi(self):
            key_1 = 't_key1'
            val_1 = 't_val1'
            key_2 = 't_key2'
            val_2 = 't_val2'
            expected = {key_1: val_1, key_2: val_2}
            attrs_str = f'{key_1}={val_1},{key_2}={val_2}'
            assert expected == attribute_pairs_to_dict(attrs_str)

    class TestExtractAcksAndMsgs:
        def test_extract_acks_and_msgs__invalid(self):
            assert tuple(([], [])) == extract_acks_and_msgs('invalid')

            invalid_raw_msgs = {'receivedMessages': [{}]}
            assert tuple(([], [{'data': ''}])) == extract_acks_and_msgs(invalid_raw_msgs)

        def test_extract_acks_and_msgs__empty(self):
            expected = tuple(([], []))
            assert expected == extract_acks_and_msgs({})

            empty_raw_msgs = {'receivedMessages': {}}
            assert expected == extract_acks_and_msgs(empty_raw_msgs)

        def test_extract_acks_and_msgs__single(self):
            raw_msgs = {'receivedMessages': [{'ackId': 1, 'message': {'data': TestHelperFunctions.ENCODED_B64_MESSAGE}}]}
            expected = ([1], [{'data': 'decoded message'}])
            assert expected == extract_acks_and_msgs(raw_msgs)

        def test_extract_acks_and_msgs__multi(self):
            raw_msgs = {'receivedMessages': [
                {'ackId': 1, 'message': {'data': TestHelperFunctions.ENCODED_B64_MESSAGE}},
                {'ackId': 2, 'message': {'attributes': {'q': 'a'}}}
            ]}
            expected = ([1, 2], [{'data': 'decoded message'}, {'data': '', 'attributes': {'q': 'a'}}])
            assert expected == extract_acks_and_msgs(raw_msgs)
