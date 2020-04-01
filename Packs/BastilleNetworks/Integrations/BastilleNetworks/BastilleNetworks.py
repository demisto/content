import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS
import json
import requests
from datetime import datetime

import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS = 100


class Client(BaseClient):
    """ Client to communicate with the Bastille service API """

    @staticmethod
    def _build_event_query_params(site, concentrator, map, protocol=None, since=None,
                                  until=None, tags=None, event_id=None,
                                  limit=MAX_INCIDENTS):
        """ Build dictionary of common event query parameters """

        if isinstance(since, datetime):
            since = str(since.timestamp())
        if isinstance(until, datetime):
            until = str(until.timestamp())

        params = {
            'site': site,
            'concentrator': concentrator,
            'map': map,
            'limit': limit
        }

        if protocol is not None:
            params['protocol'] = protocol
        if since is not None:
            params['since'] = since
        if until is not None:
            params['until'] = until
        if tags is not None:
            params['tags'] = tags
        if event_id is not None:
            params['event_id'] = event_id

        return params

    def get_zone_events(self, site, concentrator, map, zone=None, protocol=None,
                        since=None, until=None, tags=None, event_id=None,
                        limit=MAX_INCIDENTS):
        """ Get detections that occurred in one given or all zones """

        url_suffix = '/detection/zones'

        params = self._build_event_query_params(site, concentrator, map, protocol, since,
                                                until, tags, event_id, limit)
        if zone is not None:
            params['zone'] = zone

        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_device_events(self, site, concentrator, map, transmitter_id=None,
                          protocol=None, since=None, until=None, tags=None, event_id=None,
                          limit=MAX_INCIDENTS):
        """ Get device detection events for one given transmitter """

        url_suffix = '/detection/devices'

        params = self._build_event_query_params(site, concentrator, map, protocol, since,
                                                until, tags, event_id, limit)
        params['transmitter_id'] = transmitter_id

        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    @staticmethod
    def _build_tag_action_body(site, concentrator, map, transmitter_id, tag):
        """ Build dictionary of common device tagging action query body entries """

        data = {
            'site': site,
            'concentrator': concentrator,
            'map': map,
            'transmitter_id': transmitter_id,
            'tag': tag
        }

        return data

    def add_device_tag(self, site, concentrator, map, transmitter_id, tag):
        """ Add tag to a device """

        url_suffix = 'admin/devices/action.addTag'

        data = self._build_tag_action_body(site, concentrator, map, transmitter_id, tag)

        return self._http_request(method='POST', url_suffix=url_suffix, json_data=data)

    def remove_device_tag(self, site, concentrator, map, transmitter_id, tag):
        """ Remove tag from an existing device """

        url_suffix = 'admin/devices/action.removeTag'

        data = self._build_tag_action_body(site, concentrator, map, transmitter_id, tag)

        return self._http_request(method='POST', url_suffix=url_suffix, json_data=data)


def test_module(client):
    """ Check connection to the Bastille API service """

    try:
        client.get_zone_events(limit=0)
        result = 'ok'
    except DemistoException as exc:
        if '404' in str(exc):
            result = '404 Server Not Found'
        elif '401' in str(exc):
            result = '401 Unauthorized'
        elif '500' in str(exc):
            result = '500 Internal Server Error'
        else:
            result = f'Unknown Error {exc}'

    return result


def get_site_params():
    """ Helper to get the area related integration parameters """

    params = demisto.params()
    site = params.get('site')
    concentrator = params.get('concentrator')
    map = params.get('map')

    return site, concentrator, map


def get_event_args(args):
    """ Helper to get the common event related command arguments """

    protocol = args.get('protocol')
    since = args.get('since')
    until = args.get('until')
    limit = args.get('limit')
    tags = args.get('tags')
    event_id = args.get('event_id')

    if isinstance(since, str):
        since = dateparser.parse(since, settings={'TIMEZONE': 'UTC'}).timestamp()
    if isinstance(until, str):
        until = dateparser.parse(until, settings={'TIMEZONE': 'UTC'}).timestamp()

    return protocol, since, until, limit, tags, event_id


def format_timestamp(timestamp):
    """ Convert unix epoch to ISO formatted timestamp """

    return datetime.utcfromtimestamp(timestamp).astimezone().isoformat()


def parse_events(events, readable_fields):
    """ Helper to parse common event command response """

    for event in events:
        event['time_s'] = format_timestamp(event['time_s'])
        event['first_seen']['time_s'] = format_timestamp(event['first_seen']['time_s'])
        if 'last_seen' in event:
            event['last_seen']['time_s'] = format_timestamp(event['last_seen']['time_s'])

    readable_events = [{f: e[f] for f in readable_fields} for e in events]

    return events, readable_events


def get_zone_events_command(client, args):
    """ Command to fetch zone events """

    site, concentrator, map = get_site_params()
    protocol, since, until, limit, tags, event_id = get_event_args(args)
    zone = args.get('zone')

    events = client.get_zone_events(site=site, concentrator=concentrator, map=map,
                                    zone=zone, protocol=protocol, since=since,
                                    until=until, limit=limit, tags=tags,
                                    event_id=event_id)

    readable_fields = ['event_id', 'time_s', 'area', 'zone_name', 'tags', 'device_info',
                       'emitter', 'first_seen', 'last_seen']

    raw_response = json.dumps(events)
    context_events, readable_events = parse_events(events, readable_fields)

    readable_output = tableToMarkdown('Zone Events', readable_events)
    context_output = {'Bastille.ZoneEvent(val.event_id == obj.event_id)': context_events}

    return readable_output, context_output, raw_response


def get_device_events_command(client, args):
    """ Command to fetch device detection events """

    site, concentrator, map = get_site_params()
    protocol, since, until, limit, tags, event_id = get_event_args(args)
    transmitter_id = args.get('transmitter_id')

    events = client.get_device_events(site=site, concentrator=concentrator, map=map,
                                      protocol=protocol, since=since, until=until,
                                      limit=limit, tags=tags, event_id=event_id,
                                      transmitter_id=transmitter_id)

    readable_fields = ['event_id', 'time_s', 'area', 'tags', 'device_info', 'emitter',
                       'first_seen', 'last_seen']

    raw_response = json.dumps(events)
    context_events, readable_events = parse_events(events, readable_fields)

    readable_output = tableToMarkdown('Device Events', readable_events)
    context_output = {
        'Bastille.DeviceEvent(val.event_id == obj.event_id)': context_events}

    return readable_output, context_output, raw_response


def add_device_tag_command(client, args):
    """ Command to add tag to an existing admin devices entry """

    site, concentrator, map = get_site_params()

    transmitter_id = args.get('transmitter_id')
    tag = args.get('tag')

    result = client.add_device_tag(site=site, concentrator=concentrator, map=map,
                                   transmitter_id=transmitter_id, tag=tag)

    return result.get('status', 'failed'), {}, result


def remove_device_tag_command(client, args):
    """ Command to remove tag from an existing admin devices entry """

    site, concentrator, map = get_site_params()

    transmitter_id = args.get('transmitter_id')
    tag = args.get('tag')

    result = client.remove_device_tag(site=site, concentrator=concentrator, map=map,
                                      transmitter_id=transmitter_id, tag=tag)

    return result.get('status', 'failed'), {}, result


def fetch_incidents(client, last_run):
    """ Callback to fetch incidents periodically """

    last_fetch_time = last_run.get('last_fetch', datetime.utcnow().timestamp() - 60)

    site, concentrator, map = get_site_params()

    params = demisto.params()
    tags = params.get('tags') or None
    event_types = params.get('event_types')

    zone_events = []
    if event_types is None or 'zone_event' in event_types:
        zone_events = client.get_zone_events(concentrator=concentrator, map=map,
                                             site=site, tags=tags, since=last_fetch_time)

    device_events = []
    if event_types is None or 'device_event' in event_types:
        device_events = client.get_device_events(concentrator=concentrator, map=map,
                                                 site=site, tags=tags,
                                                 since=last_fetch_time)

    events = zone_events + device_events

    incidents = []
    for event in events:
        event_time = int(event['time_s'])
        incident = {
            'name': event['event_type'],
            'occurred': datetime.utcfromtimestamp(event_time).strftime(
                DATE_FORMAT),
            'rawJSON': json.dumps(event),
        }
        incidents.append(incident)

        if event_time > last_fetch_time:
            last_fetch_time = event_time

    next_run = {'last_fetch': last_fetch_time}

    return next_run, incidents


def main():
    """ Parse and validate integration parameters """

    api_url = urljoin(demisto.params()['api_url'])
    api_key = demisto.params().get('api_key')

    headers = {
        'Content-Type': 'application/json',
        'x-api-key': api_key,
    }

    try:
        client = Client(api_url, headers=headers)

        if demisto.command() == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'bastille-get-zone-events':
            results = get_zone_events_command(client, demisto.args())
            return_outputs(*results)

        elif demisto.command() == 'bastille-get-device-events':
            results = get_device_events_command(client, demisto.args())
            return_outputs(*results)

        elif demisto.command() == 'bastille-add-device-tag':
            results = add_device_tag_command(client, demisto.args())
            return_outputs(*results)

        elif demisto.command() == 'bastille-remove-device-tag':
            results = remove_device_tag_command(client, demisto.args())
            return_outputs(*results)

    except Exception as e:
        return_error(
            f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
