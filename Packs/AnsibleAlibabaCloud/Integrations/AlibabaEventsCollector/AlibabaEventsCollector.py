import demistomock as demisto
from CommonServerPython import *
from SiemApiModule import *
from datetime import datetime
from typing import Any
import six
import hmac
import hashlib
import base64
import urllib3

API_VERSION = '0.6.0'

urllib3.disable_warnings()


class AlibabaEventsClient(IntegrationEventsClient):
    def __init__(self, request: IntegrationHTTPRequest, options: IntegrationOptions, access_key: str,
                 access_key_id: str, logstore_name: str):
        self.access_key = access_key
        self.access_key_id = access_key_id
        self.logstore_name = logstore_name
        super().__init__(request=request, options=options)

    def set_request_filter(self, after: Any):
        from_time = int(after)

        self.request.params['from'] = from_time + 1
        self.request.params['to'] = from_time + 3600

    def prepare_request(self):
        headers = self.request.headers

        del headers['x-log-date']
        headers['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        signature = get_request_authorization(f'/logstores/{self.logstore_name}', self.access_key, self.request.params,
                                              headers)
        headers['Authorization'] = "LOG " + self.access_key_id + ':' + signature
        headers['x-log-date'] = headers['Date']
        del headers['Date']

        self.request.headers = headers


class AlibabaGetEvents(IntegrationGetEvents):
    @staticmethod
    def get_last_run(events: list) -> dict:
        return {'from': events[-1]['__time__']}

    def _iter_events(self):
        self.client.prepare_request()
        response = self.call()
        events: list = response.json()
        events.sort(key=lambda k: k.get('__time__'))

        if not events:
            return []

        while True:
            yield events

            last = events[-1]
            self.client.set_request_filter(last['__time__'])
            self.client.prepare_request()
            response = self.call()

            events = response.json()
            events.sort(key=lambda k: k.get('__time__'))

            if not events:
                break


def canonicalized_log_headers(headers):
    content = ''
    for key in sorted(six.iterkeys(headers)):
        if key[:6].lower() in ('x-log-', 'x-acs-'):  # x-log- header
            content += key + ':' + str(headers[key]) + "\n"
    return content


def canonicalized_resource(resource, params):
    if params:
        urlString = ''
        for key, value in sorted(six.iteritems(params)):
            urlString += u"{0}={1}&".format(
                key, value.decode('utf8') if isinstance(value, six.binary_type) else value)
        resource += '?' + urlString[:-1]
        if six.PY3:
            return resource
        else:
            return resource.encode('utf8')

    return resource


def base64_encodestring(s):
    if six.PY2:
        return base64.encodestring(s)
    else:
        if isinstance(s, str):
            s = s.encode('utf8')
        return base64.encodebytes(s).decode('utf8')


def hmac_sha1(content, key):
    if isinstance(content, six.text_type):  # hmac.new accept 8-bit str
        content = content.encode('utf-8')
    if isinstance(key, six.text_type):  # hmac.new accept 8-bit str
        key = key.encode('utf-8')

    hashed = hmac.new(key, content, hashlib.sha1).digest()
    return base64_encodestring(hashed).rstrip()


def get_request_authorization(resource, key, req_params, req_headers):
    """ :return bytes (PY2) or string (PY2) """
    content = 'GET\n\n\n'
    content += req_headers['Date'] + "\n"
    content += canonicalized_log_headers(req_headers)
    content += canonicalized_resource(resource, req_params)
    return hmac_sha1(content, key)


def get_alibaba_timestamp_format(value):
    timestamp: Optional[datetime]
    if isinstance(value, int):
        return value
    if not isinstance(value, datetime):
        timestamp = dateparser.parse(value)
    if timestamp is None:
        raise TypeError(f'after is not a valid time {value}')
    return int(time.mktime(timestamp.timetuple()))


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()

    project_name = demisto_params.get('project_name')
    endpoint = demisto_params.get('endpoint')
    logstore_name = demisto_params.get('logstore_name')
    access_key = demisto_params.get('access_key').get('password')
    access_key_id = demisto_params.get('access_key_id').get('password')
    query = demisto_params.get('query')
    events_to_add_per_request = int(demisto_params.get('events_to_add_per_request'))
    from_ = get_alibaba_timestamp_format(demisto_params.get('from'))

    headers = {'Content-Length': '0',
               'x-log-bodyrawsize': '0',
               'x-log-apiversion': API_VERSION,
               'x-log-signaturemethod': 'hmac-sha1',
               'Host': f'{project_name}.{endpoint}',
               'x-log-date': ''}

    params = {'from': from_,
              'to': from_ + 3600,
              'type': 'log',
              'offset': 0,
              'reverse': False,
              'powerSql': False,
              'query': query}

    demisto_params['method'] = Method.GET
    demisto_params['url'] = f'http://{project_name}.{endpoint}:80/logstores/{logstore_name}'
    demisto_params['headers'] = headers
    demisto_params['params'] = params

    request = IntegrationHTTPRequest(**demisto_params)

    options = IntegrationOptions.parse_obj(demisto_params)

    client = AlibabaEventsClient(request, options, access_key=access_key,
                                 access_key_id=access_key_id, logstore_name=logstore_name)

    get_events = AlibabaGetEvents(client, options)

    command = demisto.command()
    try:
        if command == 'test-module':
            get_events.client.options.limit = 1
            get_events.run()
            return_results('ok')
        elif command in ('alibaba-get-events', 'fetch-events'):
            events = get_events.run()

            if command == 'fetch-events':
                if events:
                    demisto.setLastRun(AlibabaGetEvents.get_last_run(events))
                else:
                    send_events_to_xsiam([], 'alibaba', demisto_params.get('product'))

            elif command == 'alibaba-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('alibaba Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='alibaba.Logs',
                    outputs_key_field='event.eventid',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)

            while len(events) > 0:
                send_events_to_xsiam(events[:events_to_add_per_request], 'alibaba',
                                     demisto_params.get('product'))
                events = events[events_to_add_per_request:]

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
