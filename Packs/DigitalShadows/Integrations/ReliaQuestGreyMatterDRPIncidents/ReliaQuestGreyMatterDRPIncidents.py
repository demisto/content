"""Digital Shadows for Cortex XSOAR."""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from time import monotonic, sleep

import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

''' IMPORTS '''

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
utc_tzinfo = timezone(timedelta(), name='UTC')
THREAT_INTELLIGENCE = "Threat Intelligence"

# STATUS Constants
AUTO_CLOSED = 'auto-closed'

RISK_TYPE_ALL = "all"
RISK_LEVEL_ALL = "all"

NON_INGESTIBLE_TRIAGE_ITEM_STATES = ['rejected', 'closed', 'resolved']

# FIELDS Constants
UPDATED = 'updated'

STATE = 'state'

EVENT_ACTION_CREATE = 'create'

EVENT_ACTION = 'event-action'

ALERT = 'alert'

INCIDENT_ID = 'incident-id'

COMMENTS = 'comments'

ID = 'id'

EXPOSED_ACCESS_KEY = 'exposed-access-key'

UNAUTHORIZED_CODE_COMMIT = 'unauthorized-code-commit'

IMPERSONATING_SUBDOMAIN = 'impersonating-subdomain'

IMPERSONATING_DOMAIN = 'impersonating-domain'

EXPOSED_CREDENTIAL = 'exposed-credential'

ALERT_ID = 'alert-id'

SOURCE = 'source'

TRIAGE_ITEM_ID = 'triage-item-id'

RISK_ASSESSMENT = 'risk-assessment'

CLASSIFICATION = 'classification'

EVENT = 'event'

RISK_TYPE = 'risk-type'

RISK_LEVEL = 'risk-level'

ASSETS = 'assets'

INCIDENT = 'incident'

TRIAGE_ITEM = 'triage_item'

ALERT_FIELD = 'alert'

DS_BASE_URL = 'https://portal-digitalshadows.com'

''' Utils'''


@dataclass(frozen=True)
class RQPollResult:
    max_event_number: int
    triage_data: Any


def chunks(lst, n):
    """
    Yield successive n-sized chunks from lst.

    From: https://stackoverflow.com/a/312464
    """
    to_chunk = lst
    if not hasattr(lst, '__getitem__'):
        # not subscriptable so push into a list
        to_chunk = list(lst)
    for i in range(0, len(to_chunk), n):
        yield to_chunk[i:i + n]


def removing_unwanted_data(data_item):
    """
    Removed unwanted data from response
    Args:
        data_item: dict

    Returns: dict

    """
    # Removing source from triage as source already merged into triage
    data_item[TRIAGE_ITEM].pop('source')

    # Removing risk-level, classification and risk-type from triage-item and event
    if data_item.get(ALERT_FIELD) and data_item[ALERT_FIELD].get(ASSETS):
        data_item[ALERT_FIELD].pop(ASSETS)
        data_item[ALERT_FIELD].pop(RISK_ASSESSMENT)
        data_item[ALERT_FIELD].pop(RISK_TYPE)
        if data_item[ALERT_FIELD].get(CLASSIFICATION):
            data_item[ALERT_FIELD].pop(CLASSIFICATION)
    elif data_item.get(INCIDENT) and data_item[INCIDENT].get(ASSETS):
        data_item[INCIDENT].pop(ASSETS)
        data_item[INCIDENT].pop(RISK_LEVEL)
        data_item[INCIDENT].pop(RISK_TYPE)
        data_item[INCIDENT].pop(CLASSIFICATION)

    if data_item.get(EVENT):
        data_item[EVENT].pop(RISK_LEVEL)
        data_item[EVENT].pop(RISK_TYPE)
        data_item[EVENT].pop(CLASSIFICATION)
    return data_item


def get_comments_map(triage_item_comments):
    """
    Create comments map with latest 10 comments
    Args:
        triage_item_comments:

    Returns:

    """
    comment_map: Dict[str, list] = {}
    for comment in triage_item_comments:
        if comment[TRIAGE_ITEM_ID] in comment_map:
            comment_map[comment[TRIAGE_ITEM_ID]].append(comment)
        else:
            comment_map[comment[TRIAGE_ITEM_ID]] = [comment]
    sorted_comment_map = {key: sorted(comments, key=lambda x: x[UPDATED], reverse=True) for key, comments in
                          comment_map.items()}
    # Keeping only latest 10 comments
    latest_10_comments_map = {key: comments[:10] for key, comments in
                              sorted_comment_map.items()}

    return latest_10_comments_map


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


'''Incidents'''


def get_incidents(request_handler: Client, incident_ids=[], **kwargs) -> list:
    """
    Fetch incidents from searchlight
    Args:
        request_handler: client
        incident_ids: incident ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching incidents for ids: {incident_ids}")
    if not incident_ids:
        return []
    params = {'id': incident_ids}
    r = request_handler.get('/v1/incidents', params=params, **kwargs)
    r.raise_for_status()
    return r.json()


'''Assets'''


def get_assets(request_handler: Client, asset_ids=[], **kwargs) -> list:
    """
    Fetch assets from searchlight
    Args:
        request_handler: client
        asset_ids: asset ids to be fetch
        **kwargs: dict

    Returns: assets list

    """
    demisto.info(f"Fetching assets for ids: {asset_ids}")
    if not asset_ids:
        return []
    results = []
    for chunk in chunks(asset_ids, 100):
        params = {'id': chunk}
        r = request_handler.get('/v1/assets', params=params, **kwargs)
        r.raise_for_status()
        results.extend(r.json())
    return results


'''Triage'''


def get_triage_item_events(request_handler: Client, event_created_after: datetime, risk_types, event_num_after=0, limit=100,
                           **kwargs) -> list:
    """Retrieve a batch of triage item events

    Args:
        request_handler (HttpRequestHandler): the request_handler to use for HTTP requests
        demisto.infoger (demisto.infoger): demisto.infoger used for demisto.infoging
        event_num_after (int): only return events with a higher event-num than this value, default 0
        event_created_after (datetime): only return events created after this value
        limit (int): return up to this number of events, default 100
    """
    params: dict[str, Any] = {'event-num-after': event_num_after, 'limit': limit}
    if event_created_after is not None:
        utc_datetime = event_created_after.astimezone(utc_tzinfo)
        params['event-created-after'] = utc_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    if len(risk_types) > 0:
        params['risk-type'] = risk_types
    r = request_handler.get('/v1/triage-item-events', params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_triage_items(request_handler: Client, triage_item_ids, **kwargs) -> list:
    """
    Fetch triage items
    Args:
        request_handler: client
        triage_item_ids: triage ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching triage items for ids: {triage_item_ids}")
    if not triage_item_ids:
        return []
    params = {'id': triage_item_ids}
    r = request_handler.get('/v1/triage-items', params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_triage_item_comments(request_handler: Client, triage_item_ids=[], **kwargs) -> list:
    """
    Fetch triage item comments
    Args:
        request_handler: client
        triage_item_ids: triage item ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching triage item comments for ids: {triage_item_ids}")
    if not triage_item_ids:
        return []
    data = []
    for chunk in chunks(triage_item_ids, 10):
        params = {'id': chunk}
        r = request_handler.get('/v1/triage-item-comments', params=params, **kwargs)
        r.raise_for_status()
        data.extend(r.json())
    return data


'''Alerts'''


def get_alerts(request_handler: Client, alert_ids=[], **kwargs) -> list:
    """
    Fetch alerts
    Args:
        request_handler: client
        alert_ids: alert ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching alert ids: {alert_ids}")
    if not alert_ids:
        return []
    params = {'id': alert_ids}
    r = request_handler.get("/v1/alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_credential_exposure_alerts(request_handler: Client, alert_ids=[], **kwargs) -> list:
    """
    Fetch credential exposure alerts
    Args:
        request_handler: client
        alert_ids: alert ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching credential exposure alerts for alert ids: {alert_ids}")
    if not alert_ids:
        return []
    params = {'id': alert_ids}
    r = request_handler.get("/v1/exposed-credential-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_impersonating_domain_alerts(request_handler: Client, alert_ids=[],
                                    **kwargs) -> list:
    """
    Fetch impersonating domain alerts
    Args:
        request_handler: client
        alert_ids: alert ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching impersonating domain alerts for alert ids: {alert_ids}")
    if not alert_ids:
        return []
    params = {'id': alert_ids}
    r = request_handler.get("/v1/impersonating-domain-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_impersonating_subdomain_alerts(request_handler: Client, alert_ids=[],
                                       **kwargs) -> list:
    """
    Fetch impersonating subdomain alerts
    Args:
        request_handler: client
        alert_ids: alert ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching impersonating subdomain alerts for alert ids: {alert_ids}")
    if not alert_ids:
        return []
    params = {'id': alert_ids}
    r = request_handler.get("/v1/impersonating-subdomain-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_unauthorized_code_commit(request_handler: Client, alert_ids=[], **kwargs) -> list:
    """
    Fetch unauthorized code commit
    Args:
        request_handler: client
        alert_ids: alert ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching unauthorized code commit for alert ids: {alert_ids}")
    if not alert_ids:
        return []
    params = {'id': alert_ids}
    r = request_handler.get("/v1/unauthorized-code-commit-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_exposed_access_key_alerts(request_handler: Client, alert_ids=[], **kwargs) -> list:
    """
    Fetch exposed access key alerts
    Args:
        request_handler: client
        alert_ids: alert ids to be fetch
        **kwargs: dict

    Returns: response json

    """
    demisto.info(f"Fetching exposed access key alerts for alert ids: {alert_ids}")
    if not alert_ids:
        return []
    params = {'id': alert_ids}
    r = request_handler.get("/v1/exposed-access-key-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


'''DS-Find command'''


def search_find(request_handler: Client, args):
    """
    Perform a textual search against the available record types
    Arguments:
      request_handler (HttpRequestHandler): the request handler to use to make HTTP requests
      args: arguments sent in the command as input
    """
    url = '/api/search/find'
    payload = {
        "facets": [
            "RESULTS_TYPE"
        ],
        "filter": {
            "dateRange": "P6M",
            "tags": [],
            "types": [
                "ACTORS",
                "BLOG_POST",
                "CAMPAIGNS",
                "CHAT_MESSAGE",
                "CLIENT_INCIDENT",
                "CLOSED_SOURCES",
                "DOMAIN_WHOIS",
                "DNS_LOOKUP",
                "EVENT",
                "FORUM_POST",
                "INCIDENTS",
                "INTEL_INCIDENT",
                "INTELLIGENCE",
                "LOCATION",
                "MARKETPLACE_LISTING",
                "PASTE",
                "PHISHING_WEB_PAGE",
                "MALWARE_DOWNLOAD",
                "SPECIFIC_TTP",
                "TECHNICAL_SOURCE",
                "STIX_PACKAGE",
                "WEB_PAGE",
                "WEB_SOURCE",
                "WHOIS",
                "IP_WHOIS",
                "VULNERABILITY",
                "EXPLOIT",
                "VULNERABILITY_EXPLOIT",
                "INDICATOR_FEED",
                "TECHNIQUE"
            ]
        },
        "pagination": {
            "offset": 0,
            "size": 20
        },
        "sort": {
            "direction": "DESCENDING",
            "property": "relevance"
        }
    }
    payload.update({"query": args.get('query')})
    r = request_handler.post(url, data=payload)
    r.raise_for_status()
    json_data = r.json()
    return json_data


'''SearchLightTriagePoller'''


def flatten_comments(comments):
    """
    This method will flatten up the comments
    """
    return [{"id": x["id"], "content": x['content'], "userid": x['user']['id'] if x.get('user') else None,
             "username": x['user']['name'] if x.get('user') else None,
             "created": x['created'], "updated": x['updated']} for x in comments]


class SearchLightTriagePoller:
    """
    SearchLight triage poller polls calls various api, merge data and prepare incident object
    """

    def __init__(self, request_handler: Client):
        self.request_handler = request_handler

    def get_alerts(self, alert_triage_items=[]):
        """
        Retrieve Alert details from SearchLight API

        Uses API endpoints that provide additional details where provided for
        a given triage item classification.

        :param alert_triage_items: triage item from which we extract alert ids
        :param alert_risk_types: alert risk types to be fetched
        """
        if not alert_triage_items:
            return []
        cred_alert_ids = set()
        domain_alert_ids = set()
        subdomain_alert_ids = set()
        code_commit_alert_ids = set()
        access_key_alert_ids = set()
        other_alert_ids = set()
        for ti in alert_triage_items:
            if ti[RISK_TYPE] == EXPOSED_CREDENTIAL:
                cred_alert_ids.add(ti[SOURCE][ALERT_ID])
            elif ti[RISK_TYPE] == IMPERSONATING_DOMAIN:
                domain_alert_ids.add(ti[SOURCE][ALERT_ID])
            elif ti[RISK_TYPE] == IMPERSONATING_SUBDOMAIN:
                subdomain_alert_ids.add(ti[SOURCE][ALERT_ID])
            elif ti[RISK_TYPE] == UNAUTHORIZED_CODE_COMMIT:
                code_commit_alert_ids.add(ti[SOURCE][ALERT_ID])
            elif ti[RISK_TYPE] == EXPOSED_ACCESS_KEY:
                access_key_alert_ids.add(ti[SOURCE][ALERT_ID])
            else:
                other_alert_ids.add(ti[SOURCE][ALERT_ID])

        other_alert_ids.difference(cred_alert_ids) \
            .difference(domain_alert_ids) \
            .difference(subdomain_alert_ids) \
            .difference(code_commit_alert_ids) \
            .difference(access_key_alert_ids)

        cred_alerts = get_credential_exposure_alerts(self.request_handler, cred_alert_ids)
        domain_alerts = get_impersonating_domain_alerts(self.request_handler, domain_alert_ids)
        subdomain_alerts = get_impersonating_subdomain_alerts(self.request_handler, subdomain_alert_ids)
        code_commit_alerts = get_unauthorized_code_commit(self.request_handler, code_commit_alert_ids)
        access_key_alerts = get_exposed_access_key_alerts(self.request_handler, access_key_alert_ids)
        other_alerts = get_alerts(self.request_handler, other_alert_ids)
        return [*cred_alerts, *domain_alerts, *subdomain_alerts, *code_commit_alerts, *access_key_alerts, *other_alerts]

    def merge_data(self, events, triage_items, triage_item_comments, alerts, incidents, assets, should_ingest_closed):
        """
        Merge the triage item data together with the found alert, incident and asset information.
        """
        data = []

        event_map = {event[TRIAGE_ITEM_ID]: event for event in events}
        alert_map = {alert[ID]: alert for alert in alerts}
        incident_map = {incident[ID]: incident for incident in incidents}
        asset_map = {asset[ID]: asset for asset in assets}
        comment_map = get_comments_map(triage_item_comments)
        for triage_item in triage_items:
            event = event_map[triage_item[ID]]
            if not should_ingest_closed and triage_item[STATE] in NON_INGESTIBLE_TRIAGE_ITEM_STATES:
                demisto.info(f"skipping triage item as its in closed state triage id: {triage_item[ID]}")
                continue
            # Overriding the state and risk level as event data is source of truth
            triage_item[RISK_LEVEL] = event[RISK_LEVEL]
            triage_item[STATE] = event[STATE]

            data_item = {TRIAGE_ITEM: triage_item, ASSETS: [], EVENT: event}

            if triage_item[ID] in comment_map:
                data_item[COMMENTS] = flatten_comments(comment_map[triage_item[ID]])

            alert_or_incident = None
            if ALERT_ID in triage_item[SOURCE] and triage_item[SOURCE][ALERT_ID]:
                # will KeyError if missing - intentional, shouldn't be
                if triage_item[SOURCE][ALERT_ID] not in alert_map:
                    continue
                alert = alert_map[triage_item[SOURCE][ALERT_ID]]
                data_item[ALERT] = alert
                alert_or_incident = alert
            elif INCIDENT_ID in triage_item[SOURCE] and triage_item[SOURCE][INCIDENT_ID]:
                # will KeyError if missing - intentional, shouldn't be
                if triage_item[SOURCE][INCIDENT_ID] not in incident_map:
                    continue
                incident = incident_map[triage_item[SOURCE][INCIDENT_ID]]
                data_item[INCIDENT] = incident
                alert_or_incident = incident
            if alert_or_incident:
                # merge assets on (where available)
                for asset_id_holder in alert_or_incident[ASSETS]:
                    # assets can be missing if deleted
                    asset = asset_map.get(asset_id_holder[ID], None)
                    if asset:
                        approval_state = asset["approval-state"]
                        display_value = asset["display-value"]
                        asset.update({"approvalstate": approval_state, "displayvalue": display_value})
                        data_item[ASSETS].append(asset)
            # a new boolean field “auto-closed”, is added → where the triage-event indicates that the triage item is\
            # auto-rejected, this is set to true. Otherwise, it is false
            # based on event-action="create" and status="rejected" on the triage item event
            auto_closed = data_item[EVENT][EVENT_ACTION] == EVENT_ACTION_CREATE and data_item[TRIAGE_ITEM][
                STATE] == NON_INGESTIBLE_TRIAGE_ITEM_STATES
            data_item[AUTO_CLOSED] = auto_closed
            data_item = removing_unwanted_data(data_item)
            data.append(data_item)
        return data

    def poll_triage(self, event_created_after, event_num_start=0, limit=100, alert_risk_types=[RISK_TYPE_ALL],
                    risk_level=[RISK_LEVEL_ALL], should_ingest_closed=True):
        """
        A single poll of the triage API for new events, fully populating any new events found.

        Calls a provided callback method with the fully-populated data.

        Returns the largest event-num from the triage item events that were processed.
        """
        demisto.info(
            "Polling triage items. Event num start: {}, Event created after: {}, Limit: {} risk_level: {} "
            "alert_risk_types: {}".format(
                event_num_start,
                event_created_after,
                limit, risk_level, alert_risk_types))
        risk_types_filter = []

        if RISK_TYPE_ALL not in alert_risk_types and len(alert_risk_types) > 0:
            risk_types_filter = alert_risk_types

        events = get_triage_item_events(self.request_handler, event_created_after=event_created_after,
                                        risk_types=risk_types_filter, event_num_after=event_num_start, limit=limit)
        if not events:
            demisto.info(
                "No events were fetched. Event num start: {}, Event created after: {}, Limit: {}, "
                "risk_level: {}, alert_risk_types: {}".format(
                    event_num_start, event_created_after, limit, risk_level, alert_risk_types))
            return RQPollResult(event_num_start, [])

        else:
            max_event_num = max([e['event-num'] for e in events])
            # Only ingesting events with create action event
            events = [event for event in events if event[EVENT_ACTION].lower() == EVENT_ACTION_CREATE]

        risk_level_filter = []

        if RISK_LEVEL_ALL not in risk_level and len(risk_level) > 0:
            risk_level_filter = risk_level

        # filtering events by risk level
        if risk_level_filter:
            events = [event for event in events if event[RISK_LEVEL] in risk_level_filter]

        triage_item_ids = [e[TRIAGE_ITEM_ID] for e in events]
        triage_items = get_triage_items(self.request_handler, triage_item_ids)

        if not triage_items:
            # if a triage item is deleted it is not returned to the list - outside chance that all could be deleted
            # so validate before proceeding
            demisto.info("No triage items were fetched. Event num start: {}, Event created after: {}, Limit: {},  "
                         "risk_level: {}, alert_risk_types: {}"
                         .format(event_num_start, event_created_after, limit, risk_level, alert_risk_types))
            return RQPollResult(max_event_num, [])

        triage_item_comments = get_triage_item_comments(self.request_handler, triage_item_ids=triage_item_ids)

        alert_triage_items = [ti for ti in triage_items if ALERT_ID in ti[SOURCE] and ti[SOURCE][ALERT_ID]]

        # get summary details of alerts and incidents.
        # note that this is a simplified example. For certain classifications we have more-detailed endpoints that give
        # a greater granularity of information, such as the credential-exposure endpoint which contains the actual
        # credential we have found exposed in a specific field on the model
        alerts = self.get_alerts(alert_triage_items=alert_triage_items)

        incident_ids = {ti[SOURCE][INCIDENT_ID] for ti in triage_items if
                        INCIDENT_ID in ti[SOURCE] and ti[SOURCE][INCIDENT_ID]}
        incidents = get_incidents(self.request_handler, incident_ids=incident_ids)

        asset_ids = {
            asset[ID] for alert_or_incident in [*alerts, *incidents] for asset in alert_or_incident[ASSETS]}
        assets = get_assets(self.request_handler, asset_ids=asset_ids)

        triage_data = self.merge_data(events, triage_items, triage_item_comments, alerts, incidents, assets, should_ingest_closed)
        return RQPollResult(max_event_num, triage_data)


''' FETCH INCIDENT '''


def fetch_incidents(fetchLimit, last_run, ingestClosed, riskLevel, riskTypes, search_light_request_handler, sinceDate):
    """
    fetch incidents will take config for fetching and ingesting incidents in xsoar
    Args:
        fetchLimit: no of incidents needs to fetch per iteration
        last_run: last run offset
        ingestClosed: closed incidents should be ingested or not
        riskLevel: risk levels needs to ingest
        riskTypes: risk types needs to ingest
        search_light_request_handler: request handler to fetch data
        sinceDate: since when we want to ingest data
    """
    last_event_num = last_run.get('incidents', {}).get('last_fetch', 0)
    demisto.info(f"fetch_incidents last run: {last_event_num}")
    search_list_triage_poller = SearchLightTriagePoller(search_light_request_handler)
    poll_result = search_list_triage_poller.poll_triage(event_created_after=sinceDate, event_num_start=last_event_num,
                                                        limit=fetchLimit, alert_risk_types=riskTypes, risk_level=riskLevel,
                                                        should_ingest_closed=ingestClosed)
    data = poll_result.triage_data
    last_polled_number = poll_result.max_event_number
    if last_polled_number == last_event_num:
        demisto.info(f"Polling done. last_event_num: {last_event_num}")
        return {'incidents': {'last_fetch': last_event_num}}, []

    if data:
        incidents = [
            {
                'name': item["triage_item"]['title'],
                'occurred': item["triage_item"]['raised'],
                'rawJSON': json.dumps(item)
            }
            for item in data
        ]
        demisto.info(f"data found for iteration last_polled_number:{last_polled_number}")
    else:
        incidents = []
        demisto.info(f"No data found for iteration last_polled_number:{last_polled_number}")

    return {'incidents': {'last_fetch': last_polled_number}}, incidents


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
    riskTypes = demisto.params()['riskTypes']
    riskLevel = demisto.params()['riskLevel']
    ingestClosed = demisto.params().get('ingestClosedIncidents')

    if RISK_TYPE_ALL in riskTypes:
        riskTypes = [RISK_TYPE_ALL]
    if RISK_LEVEL_ALL in riskLevel:
        riskLevel = [RISK_LEVEL_ALL]
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
            next_run, incidents = fetch_incidents(fetchLimit, demisto.getLastRun(), ingestClosed, riskLevel, riskTypes, rq_client,
                                                  first_fetch_datetime)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif demisto.command() == 'ds-search':
            return_results(search_find(rq_client, demisto.args()))
        else:
            raise NotImplementedError(f'{demisto.command()} command is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
