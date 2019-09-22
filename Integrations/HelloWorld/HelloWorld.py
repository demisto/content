import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
API_SUFFIX = "/api/v1/suffix"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Client:
    """
    Client will implement the service API, should not contain Demisto logic.
    Should do requests and return data
    """
    def __init__(self, url, verify, username, password, proxies=None):
        self.base_url = "{}{}".format(url, API_SUFFIX)
        self.verify = verify
        self.username = username
        self.password = password
        self.proxies = proxies

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = self.base_url + url_suffix

        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            auth=(self.username, self.password),
            proxies=self.proxies
        )

        if res.status_code not in [200, 204]:
            raise ValueError('Error in API call to url [%s]. Status Code: [%d]. Reason: %s' % (full_url,
                                                                                               res.status_code,
                                                                                               res.text))

        try:
            return res.json()
        except Exception:
            raise ValueError(
                "Failed to parse http response to JSON format. Original response body: \n{}".format(res.text))

    def say_hello(self, name):
        return "Hello {}".format(name)

    def say_hello_http_request(self, name):
        """
        initiates a http request to test url
        """
        data = self.http_request("GET", "/hello/" + name)
        return data["result"]

    def list_incidents(self):
        """
        returns dummy incident data, just for the example.
        """
        return [
            {
                "incident_id": 1,
                "description": "Hello incident 1",
                "created_time": datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                "incident_id": 2,
                "description": "Hello incident 2",
                "created_time": datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]


def test_module(client):
    """
    returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.
    """
    result = client.say_hello("DBot")
    if "Hello DBot" == result:
        return 'ok'
    else:
        return 'Test failed because ......'


def say_hello_command(client, args):
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = "## {}".format(result)
    outputs = {
        "hello": result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def say_hello_over_http_command(client, args):
    name = args.get("name")

    result = client.say_hello_http_request(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = "## {}".format(result)
    outputs = {
        "hello": result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each 1 minute.

    :return: next_run, list of incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT)

    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = item["created_time"]
        incident = {
            "name": item["description"],
            "occurred": datetime.strptime(incident_created_time, "%Y-%m-%dT%H:%M:%SZ"),
            "rawJSON": json.dumps(item)
        }

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > last_fetch:
            last_fetch = incident_created_time
            incidents.append(incident)

    next_run = {"last_fetch": last_fetch}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']

    verify_certificate = not demisto.params().get('insecure', False)

    # How many time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days')

    proxies = handle_proxy()

    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(server_url, verify_certificate, username, password, proxies)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_outputs(result, None)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'helloworld-say-hello':
            return_outputs(*say_hello_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error("Failed to execute {} command. Error: {}".format(), e)
        raise


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
