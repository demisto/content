import pytest
import json
import dictdiffer
import EmailHippo
from EmailHippo import Client, DemistoException


@pytest.fixture
def client():
    return Client(more_api_key='test', whois_api_key='test', more_server_url='https://test.com',
                  whois_server_url='https://test.com')


def load_test_data(path):
    with open(path) as f:
        return json.load(f)


def compare_dicts(title, actual, expected):
    """compare two dicts and return the diff if they don't.

    Args:
        actual (dict): The actual dict.
        expected (dict): The expected dict.

    Returns:
        Tuple: True or False indicating if dicts match, message if they don't.
    """
    diff = list(dictdiffer.diff(expected, actual))
    if diff:
        msg = f"Actual {title} are different from the expected.\nDifferences found in the following keys:"
        for (action, path_list, key) in diff:
            path = f'{".".join((str(x) for x in path_list))}'
            if action != 'change':
                path += f'.{key[0]}'
            msg += f'\n{path} - was {action}'
        return False, msg
    return True, ''


class TestHappyPath:
    def test_get_email_reputation_success(self, requests_mock, client):
        """
        Given:
            a Client instance and a mocked API response
        When:
            get_email_reputation is called with a valid email address
        Then:
            result returned as expected
        """
        requests_mock.get('https://test.com/v3/more/json/test/test@example.com',
                          json=load_test_data('test_data/get_email_output.json')['api_result'])
        expected_entry_context = load_test_data('test_data/get_email_output.json')['expected_context']

        command_res = EmailHippo.email_reputation_command(client, {'email': 'test@example.com'}, 0)

        hr_keys = ['Result', 'Hippo Trust Score', 'Inbox quality score', 'Spam risk score']

        assert command_res
        actual_entry_context = command_res[0].to_context()['EntryContext']
        dict_diff, msg = compare_dicts('email_reputation results', expected_entry_context, actual_entry_context)
        assert dict_diff, msg
        assert all(key in command_res[0].readable_output for key in hr_keys)

    def test_domain_reputation_command_success(self, requests_mock, client):
        """
        Given:
            - a Client instance and a mocked API response
        When:
            - domain_reputation_command is called with a valid domain
        Then:
            - result returned as expected
        """
        requests_mock.get('https://test.com/v1/test/example.com',
                          json=load_test_data('test_data/get_domain_output.json')['api_result'])
        expected_entry_context = load_test_data('test_data/get_domain_output.json')['expected_context']

        command_res = EmailHippo.domain_reputation_command(client, {'domain': 'example.com'}, 0)

        hr_keys = [
            'Registrar', 'Registered On',
            'Domain Age', 'Expires On',
            'Time To Expiry', 'Updated On',
            'Status', 'Name servers'
        ]

        assert command_res
        actual_entry_context = command_res[0].to_context()['EntryContext']
        dict_diff, msg = compare_dicts('domain_reputation results', expected_entry_context, actual_entry_context)
        assert dict_diff, msg
        assert all(key in command_res[0].readable_output for key in hr_keys)

    def test_quota_command_success(self, requests_mock, client):
        """
        Given:
            - a Client instance and a mocked API response
        When:
            - get_email_quota_command is called with a valid domain
        Then:
            - result returned as expected
        """
        requests_mock.get('https://test.com/customer/reports/v3/quota/test',
                          json=load_test_data('test_data/get_quota_output.json'))

        command_res = EmailHippo.get_email_quota_command(client)

        hr_keys = [
            'Email Quota used', 'Email Quota remaining'
        ]

        assert command_res
        assert all(key in command_res.readable_output for key in hr_keys)
        assert 'licenseKey' not in command_res.outputs


class TestFailure:

    def test_get_email_reputation_failure_quota_limit(self, requests_mock, client):
        """
        Given:
            a Client instance and a mocked failed quota limit API response
        When:
            get_email_reputation is called with a valid email address
        Then:
            - a DemistoException is raised
            - matrix quota_error increased
        """
        requests_mock.get(
            'https://test.com/v3/more/json/test/test@example.com',
            status_code=401,
            text='Insufficient quota')

        with pytest.raises(DemistoException):
            client.get_email_reputation('test@example.com')
        assert client.execution_metrics.quota_error == 1
