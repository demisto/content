from CommonServerPython import *  # noqa: F401, N999
from SiemApiModule import *  # noqa: E402
import urllib3
import json
import os
import base64
import uuid
import hashlib
import hmac
from zipfile import ZipFile
import io
import tempfile
import re
from requests import Response

urllib3.disable_warnings()

SIEM_LAST_RUN = 'siem_last_run'
SIEM_EVENTS_FROM_LAST_RUN = 'siem_events_from_last_run'
AUDIT_LAST_RUN = 'audit_last_run'
AUDIT_EVENT_DEDUP_LIST = 'audit_event_dedup_list'

LOCAL_LAST_RUN = {SIEM_LAST_RUN: '',
                  SIEM_EVENTS_FROM_LAST_RUN: '',
                  AUDIT_LAST_RUN: '',
                  AUDIT_EVENT_DEDUP_LIST: []
                  }

AUDIT_EVENT_PAGE_SIZE = 500
SIEM_LOG_LIMIT = 350
VENDOR = "mimecast"
PRODUCT = "mimecast"


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

    def prepare_headers(self, uri: str):  # pragma: no cover
        """
        Args:
            uri (str): The uri of the end point

        Returns:
            The headers part of the request to send to mimecast
        """
        # Create variables required for request headers
        request_id = str(uuid.uuid4())
        request_date = self.get_hdr_date()

        unsigned_auth_header = '{date}:{req_id}:{uri}:{app_key}'.format(
            date=request_date,
            req_id=request_id,
            uri=uri,
            app_key=self.options.app_key  # type: ignore[attr-defined]
        )
        hmac_sha1 = hmac.new(
            base64.b64decode(self.options.secret_key),  # type: ignore[attr-defined]
            unsigned_auth_header.encode(),
            digestmod=hashlib.sha1).digest()
        sig = base64.encodebytes(hmac_sha1).rstrip()
        headers = {
            'Authorization': 'MC ' + self.options.access_key + ':' + sig.decode(),  # type: ignore[attr-defined]
            'x-mc-app-id': self.options.app_id,  # type: ignore[attr-defined]
            'x-mc-date': request_date,
            'x-mc-req-id': request_id,
            'Content-Type': 'application/json'
        }
        return headers

    @staticmethod
    def get_hdr_date():  # pragma: no cover
        return datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S UTC")

    def set_request_filter(self, after: Any):  # noqa: F841  # pragma: no cover
        pass


class MimecastGetSiemEvents(IntegrationGetEvents):

    def __init__(self, client: MimecastClient, options: IntegrationOptions):  # pragma: no cover
        super().__init__(client=client, options=options)
        self.token: str = ''
        self.uri: str = '/api/audit/get-siem-logs'
        self.events_from_prev_run: list = []

    @staticmethod
    def get_last_run(events: list):
        pass

    def run(self):
        """
        Always takes SIEM_LOG_LIMIT amount of events.
        If the limit is reached, the extra events will be saved in the self.events_from_prev_run.
        Returns:
             - stored (list): A list of this run siem events.
        """
        limit = 1 if demisto.command() == 'test-module' else SIEM_LOG_LIMIT
        stored = []

        if self.events_from_prev_run:
            # In order to ensure no bc break and missing events V2.5.0
            stored.extend(self.events_from_prev_run)
            self.events_from_prev_run = []

        for logs in self._iter_events():
            stored.extend(logs)
            if len(stored) >= limit:
                demisto.info(
                    f'Reached more then {limit} siem events'
                )
                break

        return stored

    def _iter_events(self):  # pragma: no cover
        while True:
            self.client.request = IntegrationHTTPRequest(**(self.get_req_object_siem()))
            response = self.call()
            events = self.process_siem_response(response)
            demisto.info(f'\n {len(events)} Siem logs were fetched from Mimecast \n')
            if not events:
                return []

            yield events

    def process_siem_response(self, response: Response) -> list:
        """
        Args:
            response (Request.Response) - The response from the mimecast API

        Returns:
            The events after process and modification.
        """
        resp_body = response.content
        resp_headers = response.headers
        content_type = str(resp_headers['Content-Type']).lower()

        # End if response is JSON as there is no log file to download
        if content_type == 'application/json':
            decoded_response = resp_body.decode('utf8')
            json_response = json.loads(decoded_response)

            if fail_reason := json_response.get('fail', []):
                raise DemistoException(f'There was an error with siem events call {fail_reason}')

            demisto.info('No siem logs available')
            return []
        # Process log file
        elif content_type == 'application/octet-stream':
            file_name = resp_headers['Content-Disposition'].split('=\"')
            file_name = file_name[1][:-1]

            # Save the logs
            events = self.write_file(file_name, resp_body)
            # Save mc-siem-token page token to check point directory
            if events:
                self.token = resp_headers['mc-siem-token']

            return events

        else:
            # Handle errors
            demisto.info('Unexpected response from siem logs')
            headers_list = list(resp_headers)
            raise DemistoException(f'headers of failed request for siem errors: {headers_list}')

    def process_siem_events(self, siem_json_resp: dict) -> list:
        """
        Args:
            - siem_json_resp (list): a list of the siem events after extracted as json format

        Returns:
            - list: A flattened list of all fields before under the data part of the resopnse with some
                        additional fields.
        """
        siem_log_type = siem_json_resp.get('type')
        data: list = siem_json_resp.get('data', [])
        events = []
        for event in data:
            event['type'] = siem_log_type
            event['xsiem_classifier'] = 'siem_log'
            self.convert_field_to_xdm_type(event)
            events.append(event)

        return events

    @staticmethod
    def convert_field_to_xdm_type(event: dict):
        """
        Args:
            event (dict) - a siem event dict

        Returns:
            (None) this method works on the response as reference. If the event had one of the following fields
                    'IP', 'SourceIP', 'Recipient', 'Rcpt' the specified filed will be wrapped with an array.
        """
        for key in ['IP', 'SourceIP', 'Recipient', 'Rcpt']:
            if key in event and not isinstance(event[key], list):
                event[key] = [event[key]]

    def get_req_object_siem(self):
        """
        Returns all data needed for the siem http request.
        """
        req_obj = {
            'headers': self.client.prepare_headers(self.uri),  # type: ignore
            'data': self.prepare_siem_request_body(),
            'method': Method.POST,
            'url': self.options.base_url + self.uri,  # type: ignore[attr-defined]
            'verify': self.options.verify,  # type: ignore[attr-defined]
        }
        return req_obj

    def prepare_siem_request_body(self):
        """
        Return the data parameter for the http siem request
        """
        # Build post body for request
        post_body: dict = {}
        post_body['data'] = [{}]
        post_body['data'][0]['type'] = 'MTA'
        post_body['data'][0]['compress'] = True
        post_body['data'][0]['fileFormat'] = 'json'
        # If token is not included the earliest available log will be returned by the API.
        if self.token:
            post_body['data'][0]['token'] = self.token

        return json.dumps(post_body)

    def write_file(self, file_name: str, data_to_write: bytes) -> list:  # pragma: no cover
        """
        Args:
            - file_name (str): The name of the file returned form the api response header
            - data_to_write (bytes): The byte's representation of the zip file.

        Returns:
             The events that were stored in the zip-file files.
        """
        if '.zip' in file_name:
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    byte_content = io.BytesIO(data_to_write)
                    zip_file = ZipFile(byte_content)
                    zip_file.extractall(tmpdir)
                    extracted_logs_list = []
                    for file in os.listdir(tmpdir):
                        with open(os.path.join(tmpdir, file)) as json_res:
                            extracted_logs_list.extend(self.process_siem_events(json.load(json_res)))

                    return extracted_logs_list

            except Exception as e:
                raise DemistoException('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))

        else:
            raise DemistoException(f'Only compressed siem log files are supported. file_name: {file_name}')


class MimecastGetAuditEvents(IntegrationGetEvents):

    def __init__(self, client: MimecastClient, options: IntegrationOptions):  # pragma: no cover
        super().__init__(client=client, options=options)
        self.page_token: str = ''
        self.start_time: str = ''
        self.end_time: str = self.to_audit_time_format(
            datetime.now().astimezone().replace(microsecond=0).isoformat())
        self.uri: str = '/api/audit/get-audit-events'

    @staticmethod
    def get_last_run(events: list):
        pass

    def run(self):
        self.options.limit = 1 if demisto.command() == 'test-module' else None
        return super().run()

    def _iter_events(self):
        self.client.request = IntegrationHTTPRequest(**(self.get_req_object_audit()))
        response = self.call()
        events = self.process_audit_response(json.loads(response.text))
        if not events:
            return []

        while True:
            demisto.info(f'\n {len(events)} Audit logs were fetched from Mimecast \n')
            yield events

            self.client.request = IntegrationHTTPRequest(**(self.get_req_object_audit()))
            response = self.call()
            events = self.process_audit_response(json.loads(response.text))
            if not events:
                break

    def process_audit_response(self, res: dict):
        """
        Args:
            res (dict) - The response.text from the get Audit events.
        Returns:
            event_list (list) - The processed Audit events
        """
        if res.get('fail', []):
            raise DemistoException(f'There was an error with audit events call {res.get("fail")}')

        data = res.get('data', [])
        pagination = res.get('meta', {}).get('pagination', {})
        event_list = []

        for event in data:
            event['xsiem_classifier'] = 'audit_event'
            event_list.append(event)

        if next_token := pagination.get('next', ''):
            # there are more pages to process
            self.page_token = next_token
        else:
            return []

        return event_list

    def get_req_object_audit(self):
        """
        Returns all the parameters needed for the audit API call
        """
        return {
            'headers': self.client.prepare_headers(self.uri),  # type: ignore
            'data': self.prepare_audit_events_data(),
            'method': Method.POST,
            'url': self.options.base_url + self.uri,  # type: ignore[attr-defined]
            'verify': self.options.verify,  # type: ignore[attr-defined]
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
            payload['meta']['pagination']['pageToken'] = self.page_token  # type: ignore

        return json.dumps(payload)

    @staticmethod
    def to_audit_time_format(time_to_convert: str) -> str:
        """
        converts the iso8601 format (e.g. 2011-12-03T10:15:30+00:00),
        to be mimecast compatible (e.g. 2011-12-03T10:15:30+0000).
        Removes last colon from the time format.
        """
        regex = r'(?!.*:)'
        find_last_colon = re.search(regex, time_to_convert)
        index = find_last_colon.start()  # type: ignore
        audit_time_format = time_to_convert[:index - 1] + time_to_convert[index:]
        return audit_time_format


def handle_last_run_entrance(user_inserted_last_run: str, audit_event_handler: MimecastGetAuditEvents,
                             siem_event_handler: MimecastGetSiemEvents):
    start_time = arg_to_datetime(user_inserted_last_run)
    start_time_iso = start_time.astimezone().replace(microsecond=0).isoformat()  # type: ignore
    if not demisto.getLastRun():
        # first time to enter init with user specified time.
        audit_event_handler.start_time = audit_event_handler.to_audit_time_format(start_time_iso)
        demisto.info('first time setting last run')
    else:
        demisto_last_run: dict = demisto.getLastRun()
        audit_event_handler.start_time = demisto_last_run.get(AUDIT_LAST_RUN, '')
        siem_event_handler.token = demisto_last_run.get(SIEM_LAST_RUN, '')
        # starting version 2.5.0 siem_events_from_last_run should always be empty list.
        # we dont save any more events in the context between fetch executions.
        siem_event_handler.events_from_prev_run = demisto_last_run.get(SIEM_EVENTS_FROM_LAST_RUN, [])
        demisto.info(f'handle_last_run_entrance \naudit start time: {audit_event_handler.start_time} \n'
                     f'siem next token: {siem_event_handler.token}\n'
                     f'duplicate list last run {demisto_last_run.get(AUDIT_EVENT_DEDUP_LIST, [])}\n')


def dedup_audit_events(audit_events: list, last_run_potential_dup: list) -> list:
    """
    This function gets the audit_events list and removes from it duplicates from the prev run
    Args:
        audit_events (list): The list of events from this run
        last_run_potential_dup (list) : potential duplicates from prev run
    Returns:
        list: A filtered de dup list of the events.
    """
    if not last_run_potential_dup or not audit_events:
        return audit_events
    return [event for event in audit_events if event.get('id') not in last_run_potential_dup]


def set_audit_next_run(audit_events: list) -> str:
    """
    Return the first element in the audit_events list (were latest event is stored).
    """
    next_run = '' if not audit_events else audit_events[0].get('eventTime', '')
    return next_run


def handle_last_run_exit(audit_next_run: str, duplicates_audit: list, siem_next_run: str):
    """Sets the next_run object

    Args:
        audit_next_run (str): audit next start time to fetch from.
        duplicates_audit (list): Potential duplicate audit events for next run.
        siem_next_run (str): siem token to continue the fetch in the next run.
        siem_fetched_events_for_next_run (list): remaining siem events to digest on the next run.

    Returns:
        next_run_object (dict): The next run object.
    """
    next_run_object = {SIEM_LAST_RUN: siem_next_run,
                       SIEM_EVENTS_FROM_LAST_RUN: [],
                       AUDIT_LAST_RUN: audit_next_run,
                       AUDIT_EVENT_DEDUP_LIST: duplicates_audit}
    demisto.info(f'last_run_exit\naudit events next run: {audit_next_run} \n siem next run: {siem_next_run} \n'
                 f'audit potential dups: {duplicates_audit}\n')
    return next_run_object


def siem_events_last_run(siem_event_handler: MimecastGetSiemEvents, demisto_last_run: dict):
    """

    Args:
        siem_event_handler (MimecastGetSiemEvents): the siem event handler.
        audit_events (list): the audit events of this run.
    Returns:
        siem_next_run (str): The token to continue fetch on the next run.
        siem_fetched_events_for_next_run (list): list of events for next run.
    """
    siem_next_run = siem_event_handler.token if siem_event_handler.token else demisto_last_run.get(SIEM_LAST_RUN, '')
    return siem_next_run


def prepare_potential_audit_duplicates_for_next_run(audit_events: list, next_run_time: str) -> list:
    """
    Notice: This function modifies the audit_events list
    The list is sorted s.t. Latest events are in the start,
    if no more events with the same time are found break the search.

    Args:
        audit_events (list): the list of the audit events
        next_run_time (str): the new last_run time for next run

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


def audit_events_last_run(audit_event_handler: MimecastGetAuditEvents, audit_events: list, demisto_last_run: dict):
    """ de dup events same events from previous round.
        set audit next run time to be the latest event time if no event then the end_time.
        prepare all event

    Args:
        audit_event_handler (MimecastGetAuditEvents): The audit event class
        audit_events (list): The fetched audit events.
        demisto_last_run (dict): The last run object.

    Returns:
        (audit_events) : De dup list of audit events.
        (audit_next_run): The next run for audit event type.
        (duplicates_audit): Potential duplicate list of events for next run.
    """
    # de dup with events from previous round.
    audit_events = dedup_audit_events(audit_events, demisto_last_run.get(AUDIT_EVENT_DEDUP_LIST, []))
    # set next audit event type next query start time.
    audit_next_run = set_audit_next_run(audit_events) if audit_events else audit_event_handler.end_time
    # prepare all events with the same last run time.
    duplicates_audit = prepare_potential_audit_duplicates_for_next_run(audit_events, audit_next_run)
    demisto.info(f'{len(audit_events)} Audit events remain after de dup.')
    return audit_events, audit_next_run, duplicates_audit


def main():  # pragma: no cover
    # Args is always stronger. Get last run even stronger
    demisto.info('\n started running main\n')
    demisto_params: dict = demisto.params() | demisto.args()
    demisto_params['secret_key'] = demisto_params.get('credentials_secret_key', {}).get('password')
    demisto_params['access_key'] = demisto_params.get('credentials_access_key', {}).get('password')
    demisto_params['app_id'] = demisto_params.get('credentials_app', {}).get('identifier')
    demisto_params['app_key'] = demisto_params.get('credentials_app', {}).get('password')
    should_push_events = argToBoolean(demisto_params.get('should_push_events', 'false'))
    options = MimecastOptions(**demisto_params)
    empty_first_request = IntegrationHTTPRequest(method=Method.GET, url='https://api.mimecast.com', headers={})     # type: ignore
    client = MimecastClient(empty_first_request, options)
    siem_event_handler = MimecastGetSiemEvents(client, options)
    audit_event_handler = MimecastGetAuditEvents(client, options)
    command = demisto.command()
    handle_last_run_entrance(demisto_params.get('after', 'now'), audit_event_handler, siem_event_handler)
    try:
        events_audit = audit_event_handler.run()
        demisto.info(f'\n Total of {len(events_audit)} Audit Logs were fetched in this run')
        events_siem = siem_event_handler.run()
        demisto.info(f'\n Total of {len(events_siem)} Siem Logs were fetched in this run')

        demisto_last_run: dict = demisto.getLastRun()
        events_audit, audit_next_run, duplicates_audit = audit_events_last_run(
            audit_event_handler, events_audit, demisto_last_run)
        siem_next_run = siem_events_last_run(
            siem_event_handler, demisto_last_run)

        events = events_siem + events_audit

        if command == 'test-module':
            # End points are already tested as part of the event_handlers run method.
            # If we reach this point the requests were executed successfully.
            return_results('ok')

        elif command == 'fetch-events':
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            next_run_obj = handle_last_run_exit(audit_next_run, duplicates_audit, siem_next_run)
            demisto.setLastRun(next_run_obj)

        elif command == 'mimecast-get-events':
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
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                next_run_obj = handle_last_run_exit(audit_next_run, duplicates_audit, siem_next_run)
                demisto.setLastRun(next_run_obj)

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as exc:
        exc_message = str(exc)
        if '401' in exc_message:
            exc_message = exc_message + '\nTry checking your Application key, Access Key, or secret Key'
        if 'multiple of 4' in exc_message:
            exc_message = exc_message + '\n Try checking your Secret key - (wrong Secret key length)'
        if 'HTTPSConnectionPool' in exc_message:
            exc_message = exc_message + '\n Try checking your Base url'

        return_error(f'Failed to execute {command} command.\nError:\n{exc_message}', error=str(exc))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
