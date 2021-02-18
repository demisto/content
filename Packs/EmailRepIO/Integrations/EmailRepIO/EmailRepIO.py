"""EmailRepIO Integration for Cortex XSOAR"""
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback
from typing import Any, Dict, List, Optional

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


ACCEPTED_TAGS = ['account_takeover', 'bec', 'brand_impersonation', 'browser_exploit', 'credential_phishing',
                 'generic_phishing', 'malware', 'scam', 'spam', 'spoofed', 'task_request', 'threat_actor']
APP_NAME = 'Cortex-XSOAR'
INTEGRATION_NAME = 'EmailRepIO'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the EmailRepIO service API"""

    def get_email_address_reputation(self, email: str) -> Dict[str, Any]:
        """Get email reputation using the '/{email}' API endpoint"""

        return self._http_request(
            method='GET',
            url_suffix=f"/{email}"
        )

    def post_email_address_report(self, email: str, tags: List[str], description: Optional[str],
                                  timestamp: Optional[int], expires: Optional[int]) -> Dict[str, Any]:
        """Report email reputation using the '/report' API endpoint"""
        request_params: Dict[str, Any] = {}
        request_params["email"] = email
        request_params["tags"] = tags

        if description:
            request_params["description"] = description

        if timestamp:
            request_params["timestamp"] = timestamp

        if expires:
            request_params["expires"] = expires

        return self._http_request(
            method='POST',
            url_suffix='/report',
            json_data=request_params
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Test API connectivity and authentication."""
    try:
        client.get_email_address_reputation(email="test@example.com")
    except DemistoException as e:
        if 'invalid api key' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def email_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get email address reputation from EmailRepIO and calculate DBotScore.

    DBot score:
    Good: Suspicious = false
    Malicious: Suspicious = true + (malicious_activity_recent = true or credentials_leaked_recent = true)
    Suspicious: Suspicious = true and not malicious
    """
    emails = argToList(args.get('email'))
    if len(emails) == 0 or emails is None:
        raise ValueError('Email(s) not specified')

    email = emails[0]
    email_data = client.get_email_address_reputation(email)
    description = f'{INTEGRATION_NAME} returned'
    suspicious = email_data.get('suspicious')
    malicious_activity_recent = email_data.get('details.malicious_activity_recent')
    credentials_leaked_recent = email_data.get('details.credentials_leaked_recent')
    if not suspicious:
        score = Common.DBotScore.GOOD
        description = ''
    elif malicious_activity_recent or credentials_leaked_recent:
        if malicious_activity_recent:
            description += ' malicious_activity_recent'
        if credentials_leaked_recent:
            description += ' credentials_leaked_recent'
        score = Common.DBotScore.BAD
    else:
        score = Common.DBotScore.SUSPICIOUS
        description = ''

    dbot_score = Common.DBotScore(
        indicator=email,
        indicator_type=DBotScoreType.ACCOUNT,
        integration_name=INTEGRATION_NAME,
        score=score,
        malicious_description=description
    )

    account_context = Common.Account(
        id=email,
        email_address=email,
        dbot_score=dbot_score
    )

    readable_output = tableToMarkdown('Email', email_data)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Email',
        outputs_key_field='id',
        outputs=email_data,
        indicator=account_context
    )


def email_reputation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get email address reputation from EmailRepIO"""

    emails = argToList(args.get('email_address'))
    if len(emails) == 0 or emails is None:
        raise ValueError('Email(s) not specified')

    email = emails[0]
    email_data = client.get_email_address_reputation(email)

    readable_output = tableToMarkdown('Email', email_data)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Email',
        outputs_key_field='email',
        outputs=email_data
    )


def report_email_address_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Report email address to EmailRepIO"""

    email_address = args.get('email_address')
    if email_address is None:
        raise ValueError('Email(s) not specified')
    tags = argToList(args.get('tags'))
    if len(tags) == 0:
        raise ValueError('Tag(s) not specified')
    for tag in tags:
        if tag not in ACCEPTED_TAGS:
            raise ValueError(f'Tag \'{tag}\' not in accepted tag list: {ACCEPTED_TAGS}')

    description = args.get('description')
    timestamp = args.get('timestamp')
    if timestamp is not None:
        timestamp = int(args.get('timestamp'))  # type: ignore

    expires = args.get('expires')
    if expires is not None:
        expires = int(args.get('expires'))  # type: ignore

    result = client.post_email_address_report(
        email=email_address,
        tags=tags,
        description=description,
        timestamp=timestamp,
        expires=expires
    )

    readable_output = tableToMarkdown('Email Report Response', result)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Report',
        outputs_key_field='status',
        outputs=result
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions"""

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = demisto.params()['url']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Key': f'{api_key}',
            'User-Agent': APP_NAME
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'emailrepio-email-reputation-get':
            return_results(email_reputation_command(client, demisto.args()))

        elif demisto.command() == 'email':
            return_results(email_command(client, demisto.args()))

        elif demisto.command() == 'emailrepio-email-address-report':
            return_results(report_email_address_command(client, demisto.args()))

        elif demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
