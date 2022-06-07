from CommonServerPython import *
import demistomock as demisto
from collections.abc import Generator
from SiemApiModule import *  # noqa: E402
import urllib3
import json
import os
import base64
import uuid
import datetime
import hashlib
import hmac
from zipfile import ZipFile
import io
import tempfile
import re

urllib3.disable_warnings()

SIEM_LAST_RUN = 'siem_last_run'
AUDIT_LAST_RUN = 'audit_last_run'
AUDIT_EVENT_DEDUP_LIST = 'audit_event_dedup_list'

LOCAL_LAST_RUN = {'siem_last_run': '',
                  'audit_last_run': '',
                  'audit_event_dedup_list': []
                  }

AUDIT_EVENT_PAGE_SIZE = 500


class MimecastOptions(IntegrationOptions):
    app_key: str
    secret_key: str
    app_id: str
    access_key: str
    base_url: str
    verify: Optional[bool] = False


class MimecastClient(IntegrationEventsClient):

    def __init__(self, request: IntegrationHTTPRequest, options: MimecastOptions):  # pragma: no cover
        super().__init__(request=request, options=options)

    def prepare_headers(self, uri):
        """
        Args -
        """
        # Create variables required for request headers
        request_id = str(uuid.uuid4())
        request_date = self.get_hdr_date()

        unsigned_auth_header = '{date}:{req_id}:{uri}:{app_key}'.format(
            date=request_date,
            req_id=request_id,
            uri=uri,
            app_key=self.options.app_key
        )
        hmac_sha1 = hmac.new(
            base64.b64decode(self.options.secret_key),
            unsigned_auth_header.encode(),
            digestmod=hashlib.sha1).digest()
        sig = base64.encodebytes(hmac_sha1).rstrip()
        headers = {
            'Authorization': 'MC ' + self.options.access_key + ':' + sig.decode(),
            'x-mc-app-id': self.options.app_id,
            'x-mc-date': request_date,
            'x-mc-req-id': request_id,
            'Content-Type': 'application/json'
        }
        return headers

    @staticmethod
    def get_hdr_date():
        return datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S UTC")

    def set_request_filter(self, after: Any):
        pass


class MimecastGetSiemEvents(IntegrationGetEvents):

    def __init__(self, client: MimecastClient, options: IntegrationOptions):  # pragma: no cover
        super().__init__(client=client, options=options)
        self.token: str = ''
        self.uri = '/api/audit/get-siem-logs'

    @staticmethod
    def get_last_run(events: list) -> dict:
        pass

    def _iter_events(self):  # pragma: no cover
        self.client.request = IntegrationHTTPRequest(**(self.get_req_object_siem()))
        response = self.call()
        events = self.process_siem_response(response)
        # TODO: handle later error handeling
        if not events:
            return []

        if demisto.command() == 'test-module':
            self.client.options.limit = 1
            yield events

        while True:
            demisto.debug(f'\n {len(events)} Siem logs were fetched from mimecast \n')
            yield events

            # self.client.set_request_filter('after')    # set here the last run between runs
            self.client.request = IntegrationHTTPRequest(**(self.get_req_object_siem()))
            response = self.call()
            events = self.process_siem_response(response)
            if not events:
                break

    def process_siem_response(self, response):
        resp_body = response.content
        resp_headers = response.headers
        content_type = resp_headers['Content-Type']

        # End if response is JSON as there is no log file to download
        if content_type == 'application/json':
            demisto.debug('No more logs available')
            return []
        # Process log file
        elif content_type == 'application/octet-stream':
            file_name = resp_headers['Content-Disposition'].split('=\"')
            file_name = file_name[1][:-1]

            # Save the logs
            events = self.write_file(file_name, resp_body)
            # events = self.write_file2(resp_body)
            # Save mc-siem-token page token to check point directory
            if events:
                self.token = resp_headers['mc-siem-token']

            # return true to continue loop
            return events
        else:
            # Handle errors
            demisto.debug('Unexpected response from siem logs')
            headers_list = []
            for header in resp_headers:
                headers_list.append(header)
                return_error(f'headers of failed request for siem errors: {headers_list}')
            return False

    def get_req_object_siem(self):
        req_obj = {
            'headers': self.client.prepare_headers(self.uri),
            'data': self.prepare_siem_log_data(),
            'method': Method.POST,
            'url': self.options.base_url + self.uri,
            'verify': self.options.verify,
        }
        return req_obj

    def prepare_siem_log_data(self):
        # Build post body for request
        post_body = dict()
        post_body['data'] = [{}]
        post_body['data'][0]['type'] = 'MTA'
        post_body['data'][0]['compress'] = True
        post_body['data'][0]['fileFormat'] = 'json'
        if self.token:
            post_body['data'][0]['token'] = self.token
        return json.dumps(post_body)

    @staticmethod
    def write_file(file_name, data_to_write):
        if '.zip' in file_name:
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    byte_content = io.BytesIO(data_to_write)
                    zip_file = ZipFile(byte_content)
                    zip_file.extractall(tmpdir)
                    extracted_logs_list = []
                    for file in os.listdir(tmpdir):
                        with open(os.path.join(tmpdir, file)) as json_res:
                            extracted_logs_list.append(json.load(json_res))
                    return extracted_logs_list
            except Exception as e:
                return_error('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))

        else:
            try:
                with open(file_name, 'w') as f:
                    f.write(data_to_write)
            except Exception as e:
                return_error('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))

    def write_file2(self, data_to_write):
        my_json = data_to_write.decode('utf8')
        event = [json.loads(my_json)]
        return event


class MimecastGetAuditEvents(IntegrationGetEvents):

    def __init__(self, client: MimecastClient, options: IntegrationOptions):  # pragma: no cover
        super().__init__(client=client, options=options)
        self.page_token = ''
        self.start_time = ''
        self.end_time = self.to_audit_time_format(datetime.datetime.now().astimezone().replace(microsecond=0).isoformat())
        self.uri = '/api/audit/get-audit-events'

    @staticmethod
    def get_last_run(events: list) -> dict:
        pass

    def _iter_events(self):
        self.client.request = IntegrationHTTPRequest(**(self.get_req_object_audit()))
        response = self.call()
        events = self.process_audit_response(response)
        if not events:
            return []

        if demisto.command() == 'test-module':
            self.client.options.limit = 1
            yield events

        while True:
            demisto.debug(f'\n {len(events)} Audit logs were fetched from mimecast \n')
            yield events

            # self.client.set_request_filter('after')    # set here the last run between runs
            self.client.request = IntegrationHTTPRequest(**(self.get_req_object_audit()))
            response = self.call()
            events = self.process_audit_response(response)
            if not events:
                break

    def process_audit_response(self, response: requests.Response):
        """
        Args:
            response (requests.Response) - This method gets the response from the get Audit events.
        Returns:
            event_list (list) - The processed audit events
        """
        res = json.loads(response.text)
        if res.get('fail', []):
            return_error(f'The was an error with audit events call {res.get("fail")}')
        data = res.get('data', [])
        pagination = res.get('meta', {}).get('pagination', {})
        event_list = []

        for event in data:
            event_list.append(event)

        if next_token := pagination.get('next', ''):
            # there are more pages to process
            self.page_token = next_token
        else:
            return []

        return event_list

    def get_req_object_audit(self):
        return {
            'headers': self.client.prepare_headers(self.uri),
            'data': self.prepare_audit_events_data(),
            'method': Method.POST,
            'url': self.options.base_url + self.uri,
            'verify': self.options.verify,
        }

    def prepare_audit_events_data(self):
        """
        prepares the data section of the audit events api call.
        """
        # no pagination we move the time
        payload = {
            'data': [
                {
                    'startDateTime': self.start_time,
                    'endDateTime': self.end_time
                }
            ],
            "meta": {
                "pagination": {
                    "pageSize": AUDIT_EVENT_PAGE_SIZE,
                }
            }
        }
        if self.page_token:
            payload['meta']['pagination']['pageToken'] = self.page_token

        return json.dumps(payload)

    @staticmethod
    def to_audit_time_format(time_to_convert):
        """
        converts the iso8601 format (e.g. 2011-12-03T10:15:30+00:00),
        to be mimecast compatible (e.g. 2011-12-03T10:15:30+0000)
        """
        regex = r'(?!.*:)'
        find_last_colon = re.search(regex, time_to_convert)
        index = find_last_colon.start()
        audit_time_format = time_to_convert[:index - 1] + time_to_convert[index:]
        return audit_time_format


def handle_last_run_entrance(user_inserted_last_run, audit_event_handler: MimecastGetAuditEvents,
                             siem_event_handler: MimecastGetSiemEvents):
    start_time = arg_to_datetime(user_inserted_last_run)
    start_time_iso = start_time.astimezone().replace(microsecond=0).isoformat()
    if not demisto.getLastRun():
        # first time to enter init with user specified time.
        audit_event_handler.start_time = audit_event_handler.to_audit_time_format(start_time_iso)
        demisto.debug('first time setting last run')
    else:
        demisto_last_run = demisto.getLastRun()
        audit_event_handler.start_time = demisto_last_run.get(AUDIT_LAST_RUN)
        siem_event_handler.token = demisto_last_run.get(SIEM_LAST_RUN)
        demisto.debug(f'\n handle_last_run_entrance \n audit start time: {audit_event_handler.start_time} \n'
                      f'siem next token: {siem_event_handler.token}\n'
                      f'duplicate list last run {demisto_last_run.get(AUDIT_EVENT_DEDUP_LIST)}\n')


def dedup_audit_events(audit_events: list, last_run_potential_dup: list) -> list:
    """
    This function gets the audit_events list and removes from it duplicates from the prev run
    Args:
        audit_events (list): The list of events from this run
        last_run_potential_dup (list) : potential duplicates from prev run
    Returns:
        list: A filtered dedup list of the events.
    """
    if not last_run_potential_dup or not audit_events:
        return audit_events
    else:
        i = len(audit_events) - 1
        while i > -1:
            if audit_events[i].get('id') in last_run_potential_dup:
                del audit_events[i]
                i -= 1
            else:
                break
    return audit_events


def set_audit_next_run(audit_events: list) -> str:
    """
    Return the first element in the audit_events list (were latest event is stored).
    """
    if not audit_events:
        return ''
    else:
        return audit_events[0].get('eventTime')


def handle_last_run_exit(siem_event_handler: MimecastGetSiemEvents, audit_events: list):
    """
    This function removes duplicates from audit_events.
    prepares the next dedup audit event list
    sets the new demisto.LastRun

    Args:
        siem_event_handler (MimecastGetSiemEvents): the siem event handler.
        audit_events (list): the audit events of this run.
    Returns:
        None
    """
    demisto_last_run = demisto.getLastRun()
    audit_events = dedup_audit_events(audit_events, demisto_last_run.get(AUDIT_EVENT_DEDUP_LIST, []))
    audit_next_run = set_audit_next_run(audit_events) if set_audit_next_run(audit_events) else demisto_last_run.get(
        AUDIT_LAST_RUN)
    siem_next_run = siem_event_handler.token if siem_event_handler.token else demisto_last_run.get(SIEM_LAST_RUN)
    potential_duplicates = prepare_potential_duplicates_for_next_run(audit_events, audit_next_run)
    audit_dedup_next_run = potential_duplicates if potential_duplicates else demisto_last_run.get(
        AUDIT_EVENT_DEDUP_LIST)
    next_run_obj = {SIEM_LAST_RUN: siem_next_run,
                    AUDIT_LAST_RUN: audit_next_run,
                    AUDIT_EVENT_DEDUP_LIST: audit_dedup_next_run}
    demisto.setLastRun(next_run_obj)
    demisto.debug(f'\naudit events next run: {audit_next_run} \n siem next run: {siem_next_run} \n'
                  f'audit potential dups: {audit_dedup_next_run}')


def prepare_potential_duplicates_for_next_run(audit_events: list, next_run_time: str) -> list:
    """
    Notice: This function modifies the audit_events list
    The list is sorted s.t. Latest events are in the start,
    if no more events with the same time are found break the search.

    Args:
        audit_events (list): the list of the audit events
        next_run_time (str): the new last_run type for next run

    Return:
        list: The event list for next run to check against duplicates.
    """
    if not audit_events or not next_run_time:
        return []
    same_time_events = []
    for event in audit_events:
        if event.get('eventTime', '') == next_run_time:
            same_time_events.append(event.get('id'))
        else:
            break

    return same_time_events


def gather_events(siem_events: list, audit_events: list) -> list:
    """
    Args:
        siem_events (list): a list of siem events
        audit_events (list): a list of audit_events
    Returns:
        list: unified event list of audit and siem events
    """
    events = []
    events.extend(siem_events)
    events.extend(audit_events)
    return events


def main():
    # Args is always stronger. Get last run even stronger
    demisto.debug('\n started running main\n')
    demisto_params = demisto.params() | demisto.args()
    should_push_events = argToBoolean(demisto_params.get('should_push_events', 'false'))
    options = MimecastOptions(**demisto_params)
    empty_first_request = IntegrationHTTPRequest(method=Method.GET, url='http://bla.com', headers={})
    client = MimecastClient(empty_first_request, options)
    siem_event_handler = MimecastGetSiemEvents(client, options)
    audit_event_handler = MimecastGetAuditEvents(client, options)
    command = demisto.command()
    handle_last_run_entrance(demisto.params().get('after'), audit_event_handler, siem_event_handler)
    try:
        events_audit = audit_event_handler.run()
        demisto.debug(f'\n Total of {len(events_audit)} Audit Logs were fetched in this run')
        events_siem = siem_event_handler.run()
        demisto.debug(f'\n Total of {len(events_siem)} Siem Logs were fetched in this run')

        if command == 'test-module':
            return_results('ok')

        elif command in ('mimecast-get-events', 'fetch-events'):
            if command == 'fetch-events':
                handle_last_run_exit(siem_event_handler, events_audit)
                events = gather_events(events_siem, events_audit)
                send_events_to_xsiam(events, demisto_params.get('vendor', 'mimecast'),
                                     demisto_params.get('product', 'mimecast'))

            else:
                command_results_siem = CommandResults(
                    readable_output=tableToMarkdown('Mimecast Siem Logs', events_siem),
                    outputs_prefix='Mimecast.SiemLogs',
                    outputs=events_siem,
                    raw_response=events_siem,
                )
                command_results_audit = CommandResults(
                    readable_output=tableToMarkdown('Mimecast Audit Logs', events_audit),
                    outputs_prefix='Mimecast.AuditLogs',
                    outputs_key_field='id',
                    outputs=events_audit,
                    raw_response=events_audit,
                )
                return_results([command_results_siem, command_results_audit])
                if should_push_events:
                    events = gather_events(events_siem, events_audit)
                    send_events_to_xsiam(events, demisto_params.get('vendor', 'mimecast'),
                                         demisto_params.get('product', 'mimecast'))
                    handle_last_run_exit(siem_event_handler, events_audit)

    except Exception as exc:
        raise exc
        return_error(f'Failed to execute {command} command.\nError:\n{str(exc)}', error=exc)


if __name__ == "__main__":
    main()
