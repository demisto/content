import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Bonusly Integration for Cortex XSOAR (aka DBot)

This integration only has a few commands and more maybe added depending on feedback.

"""

import json

import urllib3
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

import dateparser

# IMPORTS


# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


# Client Class
class Client(BaseClient):
    """

    This is the base client used for Bonusly http requests

    """

    def bonusly_test(self):
        suffix = 'bonuses'
        return self._http_request('GET', suffix)

    def bonusly_list_bonuses_http_request(self, url_params) -> dict:
        """
        Gets a list of bonusly bonuses
            Args:
                limit=20 - defaults to 20
                skip=0 - skip
                start_time=%Y-%m-%dT%H:%M:%SZ -
                end_time=%Y-%m-%dT%H:%M:%SZ
                giver_email=person@company.com - giver email address
                receiver_email=otherperson@company.com - receiver email address
                user_email=someperson@company.com - user email address
                hashtag=%23#collaboration - hashtag to filter on
                include_children=false - include children responses
                custom_property_name='somename' - filter on some customer property
                show_private_bonuses=false - show private bonuses if admin API key

        """
        suffix = 'bonuses'
        params = url_params
        params['limit'] = url_params.get('limit', 20)
        params['skip'] = 0
        an_hour_ago_date = dateparser.parse('1 hour ago')
        assert an_hour_ago_date is not None
        start_time = an_hour_ago_date.strftime(DATE_FORMAT)
        now_date = datetime.utcnow()
        assert now_date is not None
        end_time = now_date.strftime(DATE_FORMAT)
        if url_params.get('start_time') is not None:
            start_time_date = dateparser.parse(url_params['start_time'])
            assert start_time_date is not None, f'failed parsing {url_params["start_time"]}'
            start_time = start_time_date.strftime(DATE_FORMAT)
        if url_params.get('end_time') is not None:
            end_time_date = dateparser.parse(url_params['end_time'])
            assert end_time_date is not None
            end_time = end_time_date.strftime(DATE_FORMAT)
        params['start_time'] = start_time
        params['end_time'] = end_time
        params['giver_email'] = url_params.get('giver_email', '')
        params['receiver_email'] = url_params.get('receiver_email', '')
        params['user_email'] = url_params.get('user_email', '')
        params['include_children'] = url_params.get('include_children', 'false')
        params['show_private_bonuses'] = url_params.get('show_private_bonuses', 'false')
        resp = self._http_request('GET', suffix, params=params)
        return resp

    def bonusly_get_bonus_http_request(self, url_params) -> dict:
        """
        Get a bonusly based on an ID
            Args:
                id - id of bonusly bonus to fetch
        """
        id = url_params['id']
        result = self._http_request(
            method='GET',
            url_suffix='/bonuses/' + id
        )
        return result

    def bonusly_create_bonus_http_request(self, url_params) -> dict:
        """
        Creates a bonusly using a giver_email and a reason

            Args:
                giver_email - person@company.com
                reason - they did a great job with #integrity

        """

        values = {'giver_email': url_params.get('giver_email'), 'reason': url_params.get('reason')}
        valstring = json.dumps(values)
        return self._http_request(method='POST', url_suffix='bonuses', data=valstring)

    def bonusly_update_bonus_http_request(self, url_params) -> dict:
        """
        Updates a bonusly using
            Args:
                id - id of bonusly to update
                reason - reason for bonusly
        """
        values = {'reason': url_params['reason']}
        valstring = json.dumps(values)
        id = url_params.get('id')
        result = self._http_request(
            method='PUT',
            url_suffix='/bonuses/' + id,
            data=valstring
        )
        return result

    def bonusly_delete_bonus_http_request(self, url_params) -> dict:
        """
        Deletes a bonusly
        Args:
                id - of bonusly bonus
        """
        id = url_params['id']
        result = self._http_request(
            method='DELETE',
            url_suffix='/bonuses/' + id
        )
        return result

    def list_incidents(self, last_fetch_date, fetch_params):
        """
        returns an array of JSON bonuses
        """
        url_params = {}
        url_params['application_name'] = fetch_params.get('application_name', None)
        url_params['limit'] = fetch_params.get('limit')
        url_params['user_email'] = fetch_params.get('user_email')
        url_params['hashtag'] = fetch_params.get('hashtag')
        url_params['start_date'] = last_fetch_date
        demisto.debug('URL Params being called is ' + str(url_params))
        resp = self.bonusly_list_bonuses_http_request(url_params)
        return resp.get('result', [])


def test_module(client):
    """
    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.bonusly_test()
    if result.get('success'):
        return 'ok'
    else:
        return 'Test failed Message:' + json.dumps(result)


def bonusly_list_bonuses_command(client, args):
    """
       Returns:
           list of bonuses based on the bonusly_list_bonuses_http_request
    """
    resp = client.bonusly_list_bonuses_http_request(args)
    result = resp.get('result')
    readable_output = tableToMarkdown('Latest Updates From Bonus.ly', result)
    outputs = {
        'Bonusly.Bonus': result
    }

    return (
        readable_output,
        outputs,
        resp  # raw response - the original response
    )


def bonusly_get_bonus_command(client, args):
    resp = client.bonusly_get_bonus_http_request(args)
    result = resp.get('result')
    readable_output = tableToMarkdown('Latest Updates From Bonus.ly', result)
    outputs = {
        'Bonusly.Bonus': result
    }

    return (
        readable_output,
        outputs,
        resp  # raw response - the original response
    )


def bonusly_create_bonus_command(client, args):
    resp = client.bonusly_create_bonus_http_request(args)
    result = resp.get('result')
    readable_output = tableToMarkdown('Latest Updates From Bonus.ly', result)
    outputs = {
        'Bonusly.Bonus': result
    }

    return (
        readable_output,
        outputs,
        resp  # raw response - the original response
    )


def bonusly_update_bonus_command(client, args):
    resp = client.bonusly_update_bonus_http_request(args)
    result = resp.get('result')
    readable_output = tableToMarkdown('Message Deleted From Bonus.ly', result)
    outputs = {
        'Bonusly.Bonus': result
    }

    return (
        readable_output,
        outputs,
        resp  # raw response - the original response
    )


def bonusly_delete_bonus_command(client, args):
    resp = client.bonusly_delete_bonus_http_request(args)
    result_text = resp.get('message')
    res_message = []
    res_message_table = {'Message': result_text}
    res_message.append(res_message_table)
    readable_output = tableToMarkdown('Latest Updates From Bonus.ly', res_message_table)
    outputs = {
        'Bonusly.Bonus.message': result_text
    }

    return (
        readable_output,
        outputs,
        resp  # raw response - the original response
    )


def fetch_incidents(client, last_run, first_fetch_time, fetch_params):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
        :param fetch_params params from integration settings
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    last_fetch_date = last_fetch.strftime('%Y-%m-%dT%H:%M:%SZ')
    items = client.list_incidents(last_fetch_date=last_fetch_date, fetch_params=fetch_params)
    for item in items:
        incident_created_time = dateparser.parse(item['created_at'])
        assert incident_created_time is not None, f'failed parsing {item["created_at"]}'
        incident = {
            'name': 'New Bonusly - ' + item['reason'],
            'occurred': incident_created_time.strftime(DATE_FORMAT),
            'type': fetch_params.get('incidentType'),
            'rawJSON': json.dumps(item)
        }

        # If created time is greater than latest created time then set latest created time
        # to incident created time
        if incident_created_time.timestamp() > latest_created_time.timestamp():
            latest_created_time = incident_created_time

        # if the last time fetched is before the current incident time then add it to the list of incidents
        if last_fetch.timestamp() < incident_created_time.timestamp():
            incidents.append(incident)

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # set default params
    params = demisto.params()
    base_url = params.get('url')
    api_key = params.get('api_key')
    # is_fetch = params.get('isFetch')
    # inc_type = params.get('incidentType')
    verify_certificate = not params.get('insecure', False)

    # Fetch Params
    proxy = params.get('proxy', False)

    # get the service API url
    # base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')
    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '1 day').strip()

    LOG(f'Command being called is {demisto.command()}')
    try:
        bearer_token = 'Bearer ' + api_key
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': bearer_token, 'Content-Type': 'application/json'},
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time, fetch_params=params)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'bonusly-list-bonuses':
            return_outputs(*bonusly_list_bonuses_command(client, demisto.args()))
        elif demisto.command() == 'bonusly-get-bonus':
            return_outputs(*bonusly_get_bonus_command(client, demisto.args()))
        elif demisto.command() == 'bonusly-create-bonus':
            return_outputs(*bonusly_create_bonus_command(client, demisto.args()))
        elif demisto.command() == 'bonusly-update-bonus':
            return_outputs(*bonusly_update_bonus_command(client, demisto.args()))
        elif demisto.command() == 'bonusly-delete-bonus':
            return_outputs(*bonusly_delete_bonus_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        if 'Error in API call [404]' in str(e):
            return_error(f'Failed to execute {demisto.command()} command. Error: 404 Error URL Not Found Or Invalid')

        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
