import json
import traceback

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


''' CLIENT CLASS '''


class Client(BaseClient):

    """
    This client class for MS-ISAC definies two API endpoints
    Query events in a set amount of days /albert/{days}
    Retrieve event details /albertlogs/{event_id}
    """

    def get_event(self, event_id: str) -> Dict[str, Any]:
        """
        Returns the details of an MS-ISAC event

        :type event_id: ``str``
        :param event_id: id of the event

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        # We need to specify 404 as an OK code so that we can handle "no results found" as an output instead of an error
        # The API returns 404 if the specified event ID was not found
        return self._http_request(
            method='GET',
            url_suffix=f'/albertlogs/{event_id}',
            timeout=100,
            ok_codes=(200, 404)
        )

    def retrieve_events(self, days: int) -> Dict[str, Any]:
        """
        Returns a list of MS-ISAC events in a given amount of days

        :type days: ``str``
        :param days: The number of days to search. This will be one or greater

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix=f'/albert/{days}',
            timeout=100
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: Client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.retrieve_events(days=1)
    except DemistoException as error:
        raise error
    return 'ok'


def get_event_command(client: Client, args: Dict[str, Any]):
    """msisac-get-event command: Returns an MS-ISAC event with detailed stream information

    :type client: ``Client``
    :param Client: Client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['event_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``

    :rtype: ``CommandResults``
    """

    event_id = args.get('event_id', None)
    if not event_id:
        raise ValueError('event_id not specified')

    # event is our raw-response
    event = client.get_event(event_id=event_id)
    output = {
        'EventID': event_id,
        'Stream': None
    }

    # If there is no event ID found the API returns a 404 error
    # Have 404 as on 'ok' response in the base class, and use this JSON path to provide output
    if 'error' in event:
        # If there are ever more errors to parse we can expand this conditional
        if event['error']['message'] == "Event does not exist":
            return CommandResults(
                readable_output=f"There was no MS-ISAC event retrieved with Event ID {event_id}.\n",
                raw_response=event,
                outputs_prefix='MSISAC.Event',
                outputs_key_field='event_id',
                outputs=output
            )

    # the json_data in the payload is the most verbose and should be our final output
    # However there are several keys that are not present in json_data we still want/need in the markdown and context
    stream = []
    for event_data in event['data']:
        stream_data = json.loads(event_data['json_data'])
        stream_data['time'] = event_data['time']
        stream_data['streamdataascii'] = event_data['streamdataascii']
        stream_data['streamdatahex'] = event_data['streamdatahex']
        stream_data['logical_sensor_id'] = event_data['logical_sensor_id']
        stream_data['streamdatalen'] = event_data['streamdatalen']
        # Not all responses have the http stream data so we need to make sure we're not referencing non-existant entries
        http = stream_data.get('http', None)
        if http:
            # The data we have in here we want at the root to more easily reference in context paths
            for entry in stream_data['http']:
                stream_data[entry] = stream_data['http'][entry]
            del stream_data['http']
        # Same deal as http, we want this refereanceable in context
        for data in stream_data['flow']:
            stream_data[data] = stream_data['flow'][data]
        del stream_data['flow']
        stream.append(stream_data)

    output['Stream'] = stream

    return CommandResults(
        readable_output=tableToMarkdown(f'MS-ISAC Event Details for {event_id}', stream),
        raw_response=event,
        outputs_prefix='MSISAC.Event',
        outputs_key_field='event_id',
        outputs=output
    )


def retrieve_events_command(client: Client, args: Dict[str, Any]):
    """msisac-retrieve-events command: Returns a list of MS-ISAC events in a give span of days

    :type client: ``Client``
    :param Client: Client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['days']`` The number of days to return alerts

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``

    :rtype: ``CommandResults``
    """

    days = args.get('days', None)
    # The input from our custom fields could be ints so we want to make sure we always use string type comparison
    event_id_raw = args.get('event_id', None)
    if not days:
        raise ValueError('Number of days not specified')

    # event is our raw-response
    event_list = client.retrieve_events(days=days)['data']
    # We initialize raw_response so we can use it as a check after the for loop has completed
    # If we find the event ID then this will be overwritten otherwise we return a different output
    raw_response = None
    if event_id_raw:
        event_id = str(event_id_raw)
        # Use an incrementing index to return the proper list value when we find the event_id in the response
        index = 0
        for event in event_list:
            if str(event['event_id']) == event_id:
                readable_output = tableToMarkdown(f'MS-ISAC Event {event_id} fetched', event_list[index])
                raw_response = event_list[index]
                outputs = event_list[index]
                break
            index += 1
        # If we found the event ID then raw_response would be populated.
        # If not we catch the null response to return a different message
        if not raw_response:
            readable_output = f"No Results\n--------\nEvent ID {event_id} was not found in the past {days} days"
            outputs = None
    else:
        readable_output = tableToMarkdown(f'MS-ISAC Event List Fetched for {days} Days', event_list)
        raw_response = event_list
        outputs = event_list

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
        outputs_prefix='MSISAC.RetrievedEvents',
        outputs_key_field='event_id',
        outputs=outputs
    )


''' MAIN FUNCTION '''


def main():

    api_key = demisto.params().get('apikey')

    base_url = urljoin(demisto.params()['url'], '/api/v1')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'msisac-get-event':
            result = get_event_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == 'msisac-retrieve-events':
            result = retrieve_events_command(client, demisto.args())
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
