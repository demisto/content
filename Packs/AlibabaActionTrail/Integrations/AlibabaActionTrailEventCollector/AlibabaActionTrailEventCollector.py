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
VENDOR = "alibaba"
PRODUCT = "action-trail"
urllib3.disable_warnings()


class AlibabaParams(BaseModel):
    from_: str = Field(alias='from')
    to: int
    type: str = 'log'
    offset: int = 0
    reverse: bool = False
    powerSql: bool = False
    query: str


class AlibabaEventsClient(IntegrationEventsClient):
    def __init__(self, request: IntegrationHTTPRequest, options: IntegrationOptions, access_key: str,
                 access_key_id: str, logstore_name: str):
        self.access_key = access_key
        self.access_key_id = access_key_id
        self.logstore_name = logstore_name
        super().__init__(request=request, options=options)

    def set_request_filter(self, after: Any):
        from_time = int(after)

        self.request.params.from_ = from_time + 1  # type: ignore
        self.request.params.to = from_time + 3600  # type: ignore

    def call(self, request: IntegrationHTTPRequest) -> requests.Response:
        try:
            response = self.session.request(**self.request.dict(by_alias=True))
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            demisto.debug(msg)
            raise DemistoException(msg) from exc

    def prepare_request(self):
        headers = self.request.headers

        del headers['x-log-date']
        headers['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        signature = get_request_authorization(f'/logstores/{self.logstore_name}', self.access_key,
                                              self.request.params.dict(by_alias=True), headers)  # type: ignore

        headers['Authorization'] = "LOG " + self.access_key_id + ':' + signature
        headers['x-log-date'] = headers['Date']
        del headers['Date']

        self.request.headers = headers


class AlibabaGetEvents(IntegrationGetEvents):
    client: AlibabaEventsClient

    def __init__(self, client: AlibabaEventsClient, options: IntegrationOptions):
        super().__init__(client=client, options=options)

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
            urlString += "{}={}&".format(
                key, value.decode('utf8') if isinstance(value, six.binary_type) else value)
        resource += '?' + urlString[:-1]
    return resource


def base64_encodestring(s):
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
    content = 'GET\n\n\n'
    content += req_headers['Date'] + "\n"
    content += canonicalized_log_headers(req_headers)
    content += canonicalized_resource(resource, req_params)
    return hmac_sha1(content, key)


def get_alibaba_timestamp_format(value):
    timestamp: datetime
    if isinstance(value, int):
        return value
    if not isinstance(value, datetime):
        timestamp = dateparser.parse(value)  # type: ignore
    return int(time.mktime(timestamp.timetuple()))


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()

    project_name = demisto_params.get('project_name')
    endpoint = demisto_params.get('endpoint')
    logstore_name = demisto_params.get('logstore_name')
    access_key = demisto_params.get('access_key').get('password')
    access_key_id = demisto_params.get('access_key').get('identifier')
    query = demisto_params.get('query')
    from_ = get_alibaba_timestamp_format(demisto_params.get('from'))
    should_push_events = argToBoolean(demisto_params.get('should_push_events', 'false'))

    headers = {'Content-Length': '0',
               'x-log-bodyrawsize': '0',
               'x-log-apiversion': API_VERSION,
               'x-log-signaturemethod': 'hmac-sha1',
               'Host': f'{project_name}.{endpoint}',
               'x-log-date': ''}

    params = {'from': str(from_),
              'to': str(from_ + 3600),
              'query': query}

    demisto_params['method'] = Method.GET
    demisto_params['url'] = f'http://{project_name}.{endpoint}:80/logstores/{logstore_name}'
    demisto_params['headers'] = headers

    request = IntegrationHTTPRequest(**demisto_params)
    request.params = AlibabaParams.model_validate(params)  # type: ignore[attr-defined,assignment]

    options = IntegrationOptions.model_validate(demisto_params)  # type: ignore[attr-defined]

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
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if events:
                    demisto.setLastRun(AlibabaGetEvents.get_last_run(events))

            elif command == 'alibaba-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('alibaba Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='alibaba.Logs',
                    outputs_key_field='event.eventid',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)

                if should_push_events:
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
