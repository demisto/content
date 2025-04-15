from CommonServerPython import *  # noqa: F401

import urllib3
import re

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):

    def __init__(self, base_url: str, proxy: bool, verify: bool, headers: dict):
        """
        Client to use. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request. Webhook url.

        """
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)

    def register(self, first_name: str, last_name: str, email: str, org: str):
        """
        Registers the user of the API Service.

        Args:
            first_name (str): The users first name used for registering to the API service
            last_name (str): The users last name used for registering to the API service
            email (str): The users email used for registering to the API service
            org (str): The organization registering to the API service
        """

        json_data = {
            'firstName': first_name,
            'lastName': last_name,
            'email': email,
            'organization': org
        }

        res = self._http_request(
            method='POST',
            json_data=json_data,
            raise_on_status=True,
            url_suffix='/register',
            headers={'Content-Type': 'application/json'}
        )
        demisto.info(f'Registration Sent. Response {res}')
        return res

    def info(self):
        """
        Check the availability of the SSL Labs servers
        retrieve the engine and criteria version
        initialize the maximum number of concurrent assessments.

        Args:
            None
        """

        res = self._http_request(
            method='GET',
            raise_on_status=True,
            url_suffix='/info',
            headers={'Content-Type': 'application/json'}
        )
        demisto.info(f'SSL Labs Info. Response {res}')
        return res

    def analyze(self, host: str, publish: Optional[str], start_new: Optional[str],
                from_cache: Optional[str], max_age: Optional[str], all_endpoints: Optional[str],
                ignore_mismatch: Optional[str]):
        """
        Initiate an assessment, or to retrieve the status of an assessment in
        progress or in the cache. It will return a single Host object on success.
        The Endpoint object embedded in the Host object will provide partial endpoint results.

    Args:
        client (Client): SSL Labs client to use.
        host (str): Hostname or URL to analyze.
        publish (str): Set to on if assessment results needs to be published on the public results
            boards.
        start_new (str): If on setting is enabled, a new assessment is started, even if there is a
            cached assessment in progress. However, if an assessment is in progress, its status is
            returned instead of starting a new assessment. Note: This parameter should only be used
            once to start a new assessment; any additional use may cause an assessment loop.
        from_cache (str): Delivers cached assessment reports if available. This parameter is
            intended for API consumers who do not wish to wait for assessment results and cannot be
            used simultaneouslywith the startNew parameter.
        max_age (str): Maximum report age in hours if retrieving from cache (fromCache parameter).
        all_endpoints (str): When the parameter is set to on, full information will be returned.
            When the parameter is set to done, full information will be returned only if the assessment
            is complete (status is READY or ERROR).
        ignore_mismatch (str): Ignores the mismatch if server certificate doesn't match the assessment
            hostname and proceeds with assessments if set to on.
        """
        cmd = 'ssl-labs-analyze'
        ScheduledCommand.raise_error_if_not_supported()
        polling_timeout = int(600)
        interval_in_secs = int(60)
        url_suffix = (
            f'/analyze?host={host}&publish={publish}&startNew={start_new}'
            f'&fromCache={from_cache}&maxAge={max_age}&all={all_endpoints}'
            f'&ignoreMismatch={ignore_mismatch}'
        )
        res = self._http_request(
            method='GET',
            raise_on_status=True,
            url_suffix=url_suffix
        )
        outputs = []
        polling_args = {
            'host': host,
            'publish': publish,
            'start_new': start_new,
            'from_cache': from_cache,
            'max_age': max_age,
            'all_endpoints': all_endpoints,
            'ignore_mismatch': ignore_mismatch,
            'interval_in_seconds': interval_in_secs,
            'polling': True,
        }
        if res['status'] != 'READY':
            status = res['status']
            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=interval_in_secs,
                args=polling_args,
                timeout_in_seconds=polling_timeout
            )
            command_results = CommandResults(scheduled_command=scheduled_command,
                                             readable_output=f"Scan Status: {status}")
            return command_results
        else:
            outputs.append({
                'host': res.get('host'),
                'port': res.get('port'),
                'protocol': res.get('protocol'),
                'status': res.get('status'),
                'start_time': res.get('startTime'),
                'test_time': res.get('testTime')
            })
            headers = ['host', 'port', 'protocol', 'status', 'start_time', 'test_time']
        return CommandResults(outputs_prefix='sslLabs.analysis',
                              outputs=outputs,
                              readable_output=tableToMarkdown('SSL Labs Analysis', outputs, headers, removeNull=True),
                              raw_response=res
                              )

    def is_valid(self, host: str):
        """
        This regex checks for the basic components of a URL
        """
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # subdomain
            r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # top-level domain
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )
        return re.match(regex, host) is not None


def register_email_command(client: Client, first_name: str, last_name: str, email: str, org: str) -> CommandResults:
    """
    SSLLabs has been available directly for all its users directly
    via UI and API to be consumed freely. It will remain the same with
    slight change with introduction to this new registration API. Now
    you need to register yourself with first name, last name,
    organization's name and organization's email.

    Args:
        client (Client): SSL Labs client to use.
        first_name (str): The users first name used for registering
        to the API service
        last_name (str): The users last name used for registering to
        the API service
        email (str): The users email used for registering to the
        API service
        org (str): The organization registering to the API service

    Returns:
        CommandResults/dict: A 'CommandResults' Compatible to return
        'return_results()', which contains the readable_output
        indicating the message was sent.
    """
    res = client.register(first_name, last_name, email, org)
    if res:
        result = {
            'message': res.get('message'),
            'status': res.get('status')
        }
        markdown = '### SSL Labs Registration\n'
        markdown += tableToMarkdown('Response', result)
        results = CommandResults(
            readable_output=markdown,
            outputs_prefix='SslLabs.Registation',
            outputs_key_field='name',
            outputs=result
        )
        return results
    return CommandResults(
        entry_type=EntryType.ERROR,
        readable_output='Could not register email'
    )


def info_command(client: Client) -> CommandResults:
    """
    This API request should be used to check the availability of
    the SSL Labs servers, retrieve the engine and criteria version,
    and initialize the maximum number of concurrent assessments.

    Args:
        client (Client): SSL Labs client to use.

    Returns:
        CommandResults/dict: A 'CommandResults' Compatible to return
        'return_results()', which contains the readable_output
        indicating the message was sent.
    """
    res = client.info()
    if res:
        result = {
            'engineVersion': res.get('engineVersion'),
            'criteriaVersion': res.get('criteriaVersion'),
            'maxAssessments': res.get('maxAssessments'),
            'currentAssessments': res.get('currentAssessments'),
            'newAssessmentCoolOff': res.get('newAssessmentCoolOff'),
            'messages': res.get('messages')
        }
        markdown = '### SSL Labs Info\n'
        markdown += tableToMarkdown('Response', result)
        results = CommandResults(
            readable_output=markdown,
            outputs_prefix='SslLabs.Info',
            outputs_key_field='name',
            outputs=result
        )
        return results
    return CommandResults(
        entry_type=EntryType.ERROR,
        readable_output='Could not retrieve client info'
    )


def analyze_command(client: Client, host: str, publish: Optional[str], start_new: Optional[str],
                    from_cache: Optional[str], max_age: Optional[str], all_endpoints: Optional[str],
                    ignore_mismatch: Optional[str]) -> CommandResults:
    """
    This API request is used to initiate an assessment, or to retrieve the status of an assessment
    in progress or in the cache. It will return a single Host object on success. The Endpoint
    object embedded in the Host object will provide partial endpoint results. Please note that
    assessments of individual endpoints can fail even when the overall assessment is successful
    (e.g., one server might be down). At this time, you can determine the success of an endpoint
    assessment by checking the statusMessage field; it should contain "Ready".

    Args:
        client (Client): SSL Labs client to use.
        host (str): Hostname or URL to analyze.
        publish (str): Set to on if assessment results needs to be published on the public results
            boards.
        start_new (str): If on setting is enabled, a new assessment is started, even if there is a
            cached assessment in progress. However, if an assessment is in progress, its status is
            returned instead of starting a new assessment. Note: This parameter should only be used
            once to start a new assessment; any additional use may cause an assessment loop.
        from_cache (str): Delivers cached assessment reports if available. This parameter is intended
            for API consumers who do not wish to wait for assessment results and cannot be used simultaneously
            with the startNew parameter.
        max_age (str): Maximum report age in hours if retrieving from cache (fromCache parameter).
        all_endpoints (str): When the parameter is set to on, full information will be returned.
            When the parameter is set to done, full information will be returned only if the assessment
            is complete (status is READY or ERROR).
        ignore_mismatch (str): Ignores the mismatch if server certificate doesn't match the assessment
            hostname and proceeds with assessments if set to on.

    Returns:
        CommandResults/dict: A 'CommandResults' Compatible to return 'return_results()',
        which contains the readable_output indicating the message was sent.
    """

    is_url = client.is_valid(host)
    if is_url is False:
        raise Exception(
            f'Input is not a valid URL.\n'
            f'http://example.com OR https://example.com \n'
            f'Input provided {host}'
        )

    res = client.analyze(host, publish, start_new, from_cache, max_age, all_endpoints,
                         ignore_mismatch)
    return res


def test_module(client):
    """
    Test command, will send a request to the info endpoint.

    Args:
        client (Client): SSL Labs client to use.

    Return:
        str: 'ok' if test passed, anything else will raise an exception in main.
    """
    res = client.info()
    if res:
        return 'ok'
    return None


''' ENTRY POINT '''


def main() -> None:
    """
    Main function, parses params and runs command functions
    Executes a test, analyzes hosts and urls, gets info
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    email = params.get('email')
    base_url = 'https://api.ssllabs.com/api/v4'
    proxy = params.get('proxy', False)
    verify_certificate = not params.get('insecure', False)
    headers = {'email': email}

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers
        )

        # Runs the Register Email command.
        if command == 'ssl-labs-register-email':
            first_name = args.get('firstName', '')
            last_name = args.get('lastName', '')
            email = args.get('email', '')
            org = args.get('organization', '')
            return_results(register_email_command(client, first_name, last_name, email, org))
        # Runs the Info command.
        elif command == 'ssl-labs-info':
            return_results(info_command(client))
        # Runs the Analyze command.
        elif command == 'ssl-labs-analyze':
            host = args.get('host', '')
            publish = args.get('publish', '')
            start_new = args.get('startNew', '')
            from_cache = args.get('fromCache', '')
            max_age = args.get('maxAge', '')
            all_endpoints = args.get('all', '')
            ignore_mismatch = args.get('ignoreMismatch', '')
            return_results(analyze_command(client, host, publish, start_new, from_cache, max_age, all_endpoints, ignore_mismatch))
        elif command == 'test-module':
            return_results(test_module(client))
        else:
            raise NotImplementedError(f'command {command} is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} encountered {e}.')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
