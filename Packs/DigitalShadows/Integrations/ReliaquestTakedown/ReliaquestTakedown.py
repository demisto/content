import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from time import monotonic, sleep
import urllib3
import json

"""Digital Shadows for Cortex XSOAR."""

''' IMPORTS '''

# Disable insecure warnings
urllib3.disable_warnings()

''' Utils'''

JSON_HEADERS = {'Accept': 'application/json'}
DS_BASE_URL = 'https://portal-digitalshadows.com'


@dataclass(frozen=True)
class RQPollResult:
    does_all_fetched: bool
    takedown_data: Any


def test_module(client):
    status, message = client.test_client()
    if status == 200:
        return 'ok'
    else:
        return 'Test failed because ......' + message


''' Rate Limiter'''


class RateLimiter:
    """Rate limiter for HTTP responses based on standard rate-limit response headers.

    This class implements just-enough to work with the SearchLight API and
    isn't intended to cope with the entirety of
    https://tools.ietf.org/id/draft-polli-ratelimit-headers-00.html

    Params specifit to this class:
    :param ratelimit: the number of requests per time-window
    :param window: time-window in seconds
    :param clock: function which returns the current time. Exposed for testing.
    """

    def __init__(self, ratelimit: int = 100, window: int = 60, clock=monotonic):
        self.ratelimit = ratelimit  # preserve as we might recalculate later
        self.window = window  # preserve as we might recalculate later
        self.rate_factor = 0.75  # factor that allows us to run ahead of any advertised rate limit
        self.period_s: float = self.rate_factor * (float(window) / float(ratelimit))
        self.clock = clock
        # initialise last_call such that the first call will happen immediately
        self.last_call = self.clock() - self.period_s
        self.lock = RLock()

    def handle_response(self, resp):
        # re-initialise rate limit config if we find the header has changed
        if 'ratelimit-limit' in resp.headers:
            self.__set_ratelimit_from_header(resp.headers['ratelimit-limit'])
        # check the remaining count and if it is getting too low, ensure we delay
        # our next request
        if 'ratelimit-remaining' in resp.headers:
            remaining = int(resp.headers.get('ratelimit-remaining', ''))
            if remaining <= 4:
                # find the remaining seconds and backoff for that long so we don't hit the limit
                reset_s = int(resp.headers.get('ratelimit-reset', ''))
                # push the last_call for this url out a bit further to avoid the next call breaking
                # the limit
                self.last_call = self.clock() + reset_s
        # now rate-limit ourselves before we return
        with self.__acquire():
            return resp

    def __set_ratelimit_from_header(self, headerval: str):
        """
        Set a new value for the rate-limit.

        Useful if initialised with a default value to start and replaced with a header-value
        later on.

        :param ratelimit: rate limit
        """
        # we know that SearchLight just returns an int and not the quota-policy stuff
        val = int(headerval)
        if val != self.ratelimit:
            self.ratelimit = val
            self.period_s = self.rate_factor * (float(val) / self.window)

    def __ready_time(self):
        time_elapsed_s = self.clock() - self.last_call
        return self.period_s - time_elapsed_s

    @contextmanager
    def __acquire(self):
        with self.lock:
            ready_time = self.__ready_time()
            while ready_time > 0:
                sleep(ready_time + 0.5)
                ready_time = self.__ready_time()
            try:
                yield
            finally:
                self.last_call = self.clock()


''' Client '''


class Client(BaseClient):
    def __init__(self, base_url, account_id, access_key, secret_key, verify, proxy, user_agent='unknown', **kwargs):
        headers = {'Accept': 'application/json', 'searchlight-account-id': account_id, 'User-Agent': user_agent}
        super().__init__(base_url, auth=(access_key, secret_key), verify=verify, proxy=proxy, headers=headers, **kwargs)
        self.ratelimiter = RateLimiter(**kwargs)
        demisto.info(f"hdeaders -------> {headers}")

    def get(self, url, headers={}, params={}, **kwargs):
        """
        Http Get call
        Args:
            url: url for get api
            headers: dict
            params: dict
            **kwargs: dict

        Returns: response object

        """
        r = self._http_request('GET', url_suffix=url, resp_type='response', params=params, headers=headers, **kwargs)
        return self.rate_limit_response(r)

    def post(self, url, headers={}, data=None, **kwargs):
        """
        Http post call
        Args:
            url: url for post api
            headers: dict
            data: dict
            **kwargs: dict

        Returns: response object

        """
        r = self._http_request("POST", url_suffix=url, resp_type='response', json_data=data, headers=headers, **kwargs)
        return self.rate_limit_response(r)

    def rate_limit_response(self, response):
        """
        Handle rete limit
        Args:
            response: input response object

        Returns: response object

        """
        return self.ratelimiter.handle_response(response)

    def test_client(self):
        demisto.info("making test call------->")
        try:
            r = self.get('/v1/test')
        except DemistoException as e:
            return 400, e.message
        except Exception:
            demisto.info("Exception : {ex}")
            return 400, "Something went wrong"
        r_data = r.json()
        demisto.info(f"response------->{json.dumps(r_data)}")
        if r_data.get('message') and "'accountId' is invalid" in r_data.get('message'):
            return 400, "Account Id invalid"
        if not r_data.get("api-key-valid"):
            return 400, "Invalid API Key"
        if not r_data.get("access-account-enabled"):
            return 400, "Account access disabled"
        if not r_data.get("account-api-enabled"):
            return 400, "Account API disabled"
        if not r_data.get("account-id-valid"):
            return 400, "Account Id invalid"
        return r.status_code, r_data


'''Takwdowns'''


def get_takedowns(request_handler: Client, event_num_start, limit, takedown_list=None, **kwargs) -> list:
    """
    Fetch takedown items
    Args:
        request_handler: client
        event_num_start: offset for takedown
        limit: how any takedown item should be fetched
        takedown_list: takedown ids to be fetch
        **kwargs: dict
    Returns: response json
    """
    demisto.info(f"Fetching takedown ids: {takedown_list}")
    # if not takedown_list:
    #     return []
    params = {'offset': event_num_start, 'limit': limit}
    r = request_handler.get('/v1/takedowns', params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_takedown_comments(request_handler: Client, takedown_ids=[], **kwargs) -> list:
    """
    Fetch triage item comments
    Args:
        request_handler: client
        takedown_ids: triage item ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching takedown comments for ids: {takedown_ids}")
    if not takedown_ids:
        return []
    data = []
    for takedown_id in takedown_ids:
        r = request_handler.get(f'/v1/takedowns/{takedown_id}/comments', params={}, **kwargs)
        r.raise_for_status()
        data.extend(r.json())
    return data


def get_takedown_attachments(request_handler: Client, takedown_ids=[], **kwargs) -> list:
    """
    Fetch triage item attachments
    Args:
        request_handler: client
        takedown_ids: triage item ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching takedown attachments for ids: {takedown_ids}")
    if not takedown_ids:
        return []
    data = []
    for takedown_id in takedown_ids:
        r = request_handler.get(f'/v1/takedowns/{takedown_id}/attachments', params={}, **kwargs)
        r.raise_for_status()
        attachments = r.json()
        demisto.info(f'attachments: {attachments}')
        for attachment in attachments:
            attachment.update({'takedown-id': takedown_id})
        demisto.info(f'attachments after: {attachments}')
        data.extend(attachments)
    return data


'''SearchLightTriagePoller'''


def flatten_comments(comments):
    comments_flattened = []
    for comment in comments:
        if comment.get('user'):
            comment['userid'] = comment['user'].pop('id')
            comment['username'] = comment['user'].pop('name')
            comment.pop('user')
        comments_flattened.append(comment)
    return comments_flattened


class SearchLightTakedownPoller:
    """
    SearchLight takedown poller polls calls takedown apis
    """

    def __init__(self, request_handler: Client):
        self.request_handler = request_handler

    def poll_takedowns(self, event_num_start=0, limit=50):
        """
        A single poll of the takedown API for new takedown, fully populating any new takedown found.

        Calls a provided callback method with the fully-populated data.

        Returns the largest event-num from the triage item events that were processed.
        """
        demisto.info(f"Polling takedown. Event num start: {event_num_start}, Limit: {limit}")

        takedowns = get_takedowns(self.request_handler, event_num_start=event_num_start, limit=limit)
        takedown_ids = [x['id'] for x in takedowns]

        # Get comments
        comments = get_takedown_comments(self.request_handler, takedown_ids)
        updated_comments = flatten_comments(comments)

        # Get attachments
        attachments = get_takedown_attachments(self.request_handler, takedown_ids)
        if not takedowns:
            demisto.info(f"No takedown were fetched. Event num start: {event_num_start}, Limit: {limit}")
            return RQPollResult(True, [])

        takedown_data = self.merge_data(takedowns, updated_comments, attachments)
        if len(takedowns) < limit:
            RQPollResult(True, takedown_data)
        return RQPollResult(False, takedown_data)

    def merge_data(self, takedowns, comments, attachments):
        """
        Merge the triage item data together with the found alert, incident and asset information.
        """
        data = []

        comments_map = {comment['takedown-id']: comment for comment in comments}
        attchment_map = {attachment['takedown-id']: attachment for attachment in attachments}
        for takedown in takedowns:
            takedown['comments'] = comments_map.get(takedown['id'])
            takedown['attachments'] = attchment_map.get(takedown['id'])
            takedown['dbotMirrorDirection'] = "In"
            takedown['dbotMirrorInstance'] = demisto.integrationInstance()
            takedown['dbotMirrorId'] = takedown['id']
            data.append(takedown)

        return data


'''Create takedown'''


def create_takedown(request_handler: Client, args):
    """
    Perform a textual search against the available record types
    Arguments:
      request_handler (HttpRequestHandler): the request handler to use to make HTTP requests
      args: arguments sent in the command as input
    """
    brand_id = args.get('brandId')
    target = args.get('target')
    type = args.get('type')
    portal_id = args.get('portalId')

    url = '/v1/takedowns'
    payload = {
        "brand": brand_id,
        "type": type,
        "target": {
            "url": target,
        }
    }
    if portal_id:
        payload['target'].update({"alert": {"portal-id": portal_id}})
    demisto.info(f"creating takedown with payload: {payload}")
    r = request_handler.post(url, data=payload)
    r.raise_for_status()
    json_data = r.json()
    return json_data


def list_brands(request_handler: Client, args, **kwargs) -> list:
    """
    Return takedown brands for given customer
    Arguments:
      request_handler (HttpRequestHandler): the request handler to use to make HTTP requests
      args: arguments sent in the command as input
    """
    url = '/v1/takedown-brands'
    r = request_handler.get(url, params={}, **kwargs)
    r.raise_for_status()
    json_data = r.json()
    return json_data


def create_comment(request_handler: Client, args, **kwargs) -> list:
    """
    Crate takedown comment for given takedown id
    Arguments:
      request_handler (HttpRequestHandler): the request handler to use to make HTTP requests
      args: arguments sent in the command as input
    """
    takedown_id = args.get('takedownId')
    comment = args.get('comment')
    payload = {
        "content": comment
    }
    url = f'/v1/takedowns/{takedown_id}/comments'
    demisto.info(f"creating takedown comment with payload: {payload}")
    r = request_handler.post(url, data=payload)
    r.raise_for_status()
    json_data = r.json()
    return json_data


def upload_attachment(request_handler: Client, args, **kwargs) -> list:
    """
    Upload file as a attachment to the takedown
    Arguments:
      request_handler (HttpRequestHandler): the request handler to use to make HTTP requests
      args: arguments sent in the command as input
    """

    file_id = demisto.args().get("fileId")
    takedown_id = args.get('takedownId')

    result = demisto.getFilePath(file_id)

    with open(result['path'], 'rb') as file:
        # Prepare the files dictionary for the POST request
        files = {
            'file': (result['name'], file, 'application/octet-stream')  # (field_name, file_object, mime_type)
        }
        url = f'/v1/takedowns/{takedown_id}/attachments'

        response = request_handler.post(url, files=files, data={})
        if response.status_code == 200:
            return response.json()
        else:
            return response.text


def download_attachment(request_handler: Client, args, **kwargs) -> list:
    """
    Download file as a attachment from the takedown
    Arguments:
      request_handler (HttpRequestHandler): the request handler to use to make HTTP requests
      args: arguments sent in the command as input
    """
    attachment_id = args.get('attachmentId')

    url = f'/v1/takedowns/attachments/{attachment_id}/download'
    demisto.info(f"downloading file for attachment: {attachment_id}")
    r = request_handler.get(url, data={})
    r.raise_for_status()

    path = r.headers.get('Content-Disposition').split(";")[-1].split("=")[-1].replace('"', "")
    with open(path, 'wb') as file:
        for chunk in r.iter_content(chunk_size=8192):  # Download in chunks
            file.write(chunk)

    file_entry = fileResult(path, open(path, 'rb').read())
    return file_entry


''' FETCH INCIDENT '''


def fetch_takedowns(fetch_limit, last_run, search_light_client):
    """
    fetch takedown will take config for fetching and ingesting takedown in xsoar
    Args:
        fetch_limit: no of takedowns needs to fetch per iteration
        last_run: last run offset
        search_light_client: Search light client
    """
    last_event_num = last_run.get('takedown', {}).get('last_fetch', 0)
    demisto.info(f"fetch_incidents last run: {last_event_num}")
    seachlight_takwdown_poller = SearchLightTakedownPoller(search_light_client)
    poll_result = seachlight_takwdown_poller.poll_takedowns(event_num_start=last_event_num, limit=fetch_limit)
    data = poll_result.takedown_data

    if poll_result.does_all_fetched:
        demisto.info(f"Polling done. last_event_num: {last_event_num}")
        return {'takedown': {'last_fetch': last_event_num}}, []

    if data:
        takedowns = [
            {
                'name': item["type"],
                'occurred': item['created'],
                'rawJSON': json.dumps(item)
            }
            for item in data
        ]
        demisto.info(f"data found for iteration last_polled_number:{last_event_num}")
    else:
        takedowns = []
        demisto.info(f"No data found for iteration last_polled_number:{last_event_num}")

    return {'takedown': {'last_fetch': last_event_num + len(data)}}, takedowns


def get_remote_data_command(client, args):
    parsed_args = GetRemoteDataArgs(args)
    demisto.info(f'Running get_remote_data_command for takedown {parsed_args.remote_incident_id}')

    takedown_response = client.get(f'/v1/takedowns/{parsed_args.remote_incident_id}')
    takedown_response.raise_for_status()
    takedown_res = takedown_response.json()
    demisto.info(f"get_remote_data takedown response: {takedown_response.json()}")

    comment = client.get(f'/v1/takedowns/{parsed_args.remote_incident_id}/comments')
    demisto.info(f"mirror comment response: {comment.json()}")

    attachments = client.get(f'/v1/takedowns/{parsed_args.remote_incident_id}/attachments')

    latest_takedown_data = {"status": takedown_res["status"], "comments": comment.json(), "attachments": attachments.json()}
    demisto.info(f"result to get latest takedown data: {latest_takedown_data}")
    return GetRemoteDataResponse(
        mirrored_object=latest_takedown_data, entries=[])


def get_modified_remote_data_command(client, mirroring_last_update):
    NO_OF_EVENT_TO_FETCH = 10
    demisto.info("inside get_modified_remote_data_command")
    takedown_events = client.get(f'/v1/takedown-events?limit={NO_OF_EVENT_TO_FETCH}&event-num-after={mirroring_last_update}')
    takedown_events.raise_for_status()
    takedown_events = takedown_events.json()
    takedown_ids = []
    demisto.info(f"after api call response: {takedown_events}")
    max_event_num = mirroring_last_update
    if type(mirroring_last_update) == str:
        mirroring_last_update = int(mirroring_last_update)
    if takedown_events:
        max_event_num = max(max([int(t['event-num']) for t in takedown_events]), mirroring_last_update)
        takedown_ids.extend([t['takedown-id'] for t in takedown_events])

    return GetModifiedRemoteDataResponse(takedown_ids), max_event_num


''' MAIN FUNCTION '''


def get_base_url(command):
    """
    Returns base url for client
    """
    if command == 'ds-search':
        return DS_BASE_URL
    else:
        return demisto.params()['searchLightUrl']


def main() -> None:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    demisto.info(f'input config------: {demisto.params()}')
    secretKey = demisto.params()["apiSecret"]['password']
    accessKey = demisto.params()['apiKey']['password']
    accountId = demisto.params()['accountId']
    verify_certificate = not demisto.params().get('insecure', False)
    fetchLimit: int = arg_to_number(demisto.params()['max_fetch'], "max_fetch", True)  # type:ignore
    if fetchLimit > 100:
        raise DemistoException("fetch limit must be less than 100")
    if fetchLimit < 0:
        raise DemistoException("fetch limit must be greater than 0")
    proxy = demisto.params().get('proxy', False)

    first_fetch_datetime = arg_to_datetime(
        arg=demisto.params()["first_fetch"], arg_name="First fetch time", required=True
    )
    if not isinstance(first_fetch_datetime, datetime):
        raise ValueError("Failed to get first fetch time.")

    if first_fetch_datetime > datetime.now():
        raise DemistoException("Since date should not be greate than current date")
    demisto.info(f'Command being called is {demisto.command()}')
    try:
        base_url = get_base_url(demisto.command())
        rq_client = Client(
            base_url=base_url,
            account_id=accountId,
            access_key=accessKey,
            secret_key=secretKey,
            verify=verify_certificate,
            proxy=proxy
        )
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(rq_client))
        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_takedowns(fetchLimit, demisto.getLastRun(), rq_client)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif demisto.command() == 'create-takedown':
            return_results(create_takedown(rq_client, demisto.args()))
        elif demisto.command() == 'list-brand':
            return_results(list_brands(rq_client, demisto.args()))
        elif demisto.command() == 'create-comment':
            return_results(create_comment(rq_client, demisto.args()))
        elif demisto.command() == 'upload-attachment':
            return_results(upload_attachment(rq_client, demisto.args()))
        elif demisto.command() == 'download-attachment':
            return_results(download_attachment(rq_client, demisto.args()))
        elif demisto.command() == "get-remote-data":
            return_results(get_remote_data_command(rq_client, demisto.args()))
        elif demisto.command() == 'get-modified-remote-data':
            last_run_mirroring: Dict[Any, Any] = get_last_mirror_run() or {}
            modified_incidents, next_mirroring_event_num = get_modified_remote_data_command(
                rq_client, mirroring_last_update=last_run_mirroring.get('lastEventNum', 0))
            timestamp = datetime.utcnow().isoformat() + "Z"
            payload = {
                "lastMirrorTime": timestamp,
                "lastEventNum": str(next_mirroring_event_num)
            }
            try:
                json.dumps(payload)
                demisto.debug(f"before set last mirror: {payload}")
                demisto.setLastMirrorRun(payload)
            except Exception as e:
                demisto.debug("Payload is not JSON serializable:", str(e))
            return_results(modified_incidents)
        else:
            raise NotImplementedError(f'ReliaquestTakedown error: '
                                      f'command {demisto.command()} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
