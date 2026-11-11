import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import copy
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode, urljoin

import requests

VENDOR = 'Sprinklr'
PRODUCT = 'Sprinklr'
DEFAULT_TOKEN_BUFFER_SECONDS = 60
MAX_SPRINKLR_PAGE_SIZE = 1000
DEFAULT_XSIAM_FETCH_LIMIT = 200
FETCH_STATE_VERSION = 2


class Client:
    def __init__(
        self,
        server_url: str,
        environment: str,
        client_id: str,
        client_secret: str,
        reporting_path: str,
        scim_delete_path: str,
        verify: bool = True,
        timeout: int = 60,
    ):
        self.server_url = server_url.rstrip('/') + '/'
        self.environment = environment.strip().strip('/')
        self.client_id = client_id.strip()
        self.client_secret = client_secret.strip()
        self.reporting_path = reporting_path
        self.scim_delete_path = scim_delete_path
        self.verify = verify
        self.timeout = timeout

    def _format_path(self, path_template: str) -> str:
        return path_template.replace('{env}', self.environment).lstrip('/')

    @property
    def token_url(self) -> str:
        return urljoin(self.server_url, f'{self.environment}/oauth/token')

    @property
    def reporting_url(self) -> str:
        return urljoin(self.server_url, self._format_path(self.reporting_path))

    def _get_cached_token(self) -> Optional[str]:
        context = demisto.getIntegrationContext() or {}
        token = context.get('sprinklr_access_token')
        expires_at = context.get('sprinklr_access_token_expires_at')
        try:
            expires_at = float(expires_at or 0)
        except (TypeError, ValueError):
            expires_at = 0
        if token and time.time() < expires_at:
            return str(token)
        return None

    def _cache_token(self, access_token: str, expires_in: Any) -> None:
        try:
            expires_seconds = int(expires_in)
        except (TypeError, ValueError):
            expires_seconds = 0

        buffer_seconds = min(DEFAULT_TOKEN_BUFFER_SECONDS, max(0, expires_seconds // 10))
        effective_ttl = max(0, expires_seconds - buffer_seconds)
        context = demisto.getIntegrationContext() or {}
        context['sprinklr_access_token'] = access_token
        context['sprinklr_access_token_expires_at'] = time.time() + effective_ttl
        context['sprinklr_access_token_expires_in'] = expires_seconds
        demisto.setIntegrationContext(context)

    def _clear_cached_token(self) -> None:
        context = demisto.getIntegrationContext() or {}
        context.pop('sprinklr_access_token', None)
        context.pop('sprinklr_access_token_expires_at', None)
        context.pop('sprinklr_access_token_expires_in', None)
        demisto.setIntegrationContext(context)

    def _request_new_token(self) -> str:
        # Match the documented form-encoded OAuth client-credentials request:
        # Content-Type: application/x-www-form-urlencoded
        # --data-urlencode client_id=...
        # --data-urlencode client_secret=...
        # --data-urlencode grant_type=client_credentials
        form_body = urlencode([
            ('client_id', self.client_id),
            ('client_secret', self.client_secret),
            ('grant_type', 'client_credentials'),
        ])
        response = requests.post(
            self.token_url,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=form_body,
            verify=self.verify,
            timeout=self.timeout,
        )
        if not response.ok:
            body = response.text[:2000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr OAuth token request failed. HTTP {response.status_code}. Response: {body}'
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise DemistoException('Sprinklr OAuth token response was not valid JSON.') from exc

        access_token = payload.get('access_token')
        if not access_token:
            raise DemistoException('Sprinklr OAuth token response did not contain access_token.')

        self._cache_token(str(access_token), payload.get('expires_in', 0))
        return str(access_token)

    def get_access_token(self, force_new: bool = False) -> str:
        if not force_new:
            cached = self._get_cached_token()
            if cached:
                return cached
        return self._request_new_token()

    def _authorized_headers(self, content_type: str = 'application/json', force_new_token: bool = False) -> dict:
        return {
            'Authorization': f'Bearer {self.get_access_token(force_new=force_new_token)}',
            'Key': self.client_id,
            'Content-Type': content_type,
            'Accept': 'application/json',
        }

    def _authorized_request(
        self,
        method: str,
        url: str,
        *,
        content_type: str = 'application/json',
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> requests.Response:
        response = requests.request(
            method,
            url,
            headers=self._authorized_headers(content_type=content_type),
            json=json_body,
            params=params,
            verify=self.verify,
            timeout=self.timeout,
        )

        # A token can expire or be revoked between fetch cycles. Re-authenticate once on 401.
        if response.status_code == 401:
            self._clear_cached_token()
            response = requests.request(
                method,
                url,
                headers=self._authorized_headers(content_type=content_type, force_new_token=True),
                json=json_body,
                params=params,
                verify=self.verify,
                timeout=self.timeout,
            )
        return response

    def report_query(self, payload: dict) -> dict:
        response = self._authorized_request('POST', self.reporting_url, json_body=payload)
        if not response.ok:
            body = response.text[:4000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr Reporting API request failed. HTTP {response.status_code}. Response: {body}'
            )
        try:
            result = response.json()
        except ValueError as exc:
            raise DemistoException('Sprinklr Reporting API response was not valid JSON.') from exc

        errors = result.get('errors') if isinstance(result, dict) else None
        if errors:
            raise DemistoException(f'Sprinklr Reporting API returned errors: {json.dumps(errors)}')
        return result

    def deprovision_user(self, user_id: str) -> int:
        if '{userId}' not in self.scim_delete_path:
            raise DemistoException('SCIM delete path must contain the literal placeholder {userId}.')
        path = self._format_path(self.scim_delete_path).replace('{userId}', quote(str(user_id), safe=''))
        url = urljoin(self.server_url, path)
        response = self._authorized_request('DELETE', url, content_type='application/scim+json')
        if response.status_code != 204:
            body = response.text[:2000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr deprovision request failed. HTTP {response.status_code}. Response: {body}'
            )
        return response.status_code

    def set_user_active(self, user_id: str, active: bool) -> dict:
        """Activate/deactivate a Sprinklr user using the SCIM 2.0 PATCH API."""
        if '{userId}' not in self.scim_delete_path:
            raise DemistoException('SCIM user path must contain the literal placeholder {userId}.')
        path = self._format_path(self.scim_delete_path).replace('{userId}', quote(str(user_id), safe=''))
        url = urljoin(self.server_url, path)
        payload = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {
                    'op': 'Replace',
                    'path': 'active',
                    'value': active,
                }
            ],
        }
        response = self._authorized_request(
            'PATCH', url, content_type='application/scim+json', json_body=payload
        )
        if not response.ok:
            body = response.text[:3000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr SCIM user status update failed. HTTP {response.status_code}. Response: {body}'
            )
        if response.status_code == 204 or not response.text.strip():
            return {'status_code': response.status_code, 'user_id': user_id, 'active': active}
        try:
            body = response.json()
        except ValueError:
            body = {'response': response.text[:3000]}
        return {'status_code': response.status_code, 'user_id': user_id, 'active': active, 'response': body}

    def governance_get_user(self, email: str) -> dict:
        path = self._format_path('/{env}/api/v2/paid/governance/get/user')
        url = urljoin(self.server_url, path)
        response = self._authorized_request('GET', url, params={'userMail': email})
        if not response.ok:
            body = response.text[:3000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr get user request failed. HTTP {response.status_code}. Response: {body}'
            )
        try:
            return response.json()
        except ValueError as exc:
            raise DemistoException('Sprinklr get user response was not valid JSON.') from exc

    def governance_delete_user(self, email: str) -> dict:
        path = self._format_path('/{env}/api/v2/paid/governance/delete/user')
        url = urljoin(self.server_url, path)
        response = self._authorized_request('POST', url, params={'userMail': email})
        if not response.ok:
            body = response.text[:3000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr delete user by email failed. HTTP {response.status_code}. Response: {body}'
            )
        if not response.text.strip():
            return {'status_code': response.status_code, 'email': email}
        try:
            body = response.json()
        except ValueError:
            body = {'response': response.text[:3000]}
        return {'status_code': response.status_code, 'email': email, 'response': body}

    def governance_remove_user_from_team(self, email: str, team_id: str) -> dict:
        path = self._format_path('/{env}/api/v2/paid/governance/remove/user')
        url = urljoin(self.server_url, path)
        response = self._authorized_request(
            'POST', url, params={'userEmail': email, 'teamId': team_id}
        )
        if not response.ok:
            body = response.text[:3000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr remove user from team failed. HTTP {response.status_code}. Response: {body}'
            )
        try:
            body = response.json() if response.text.strip() else {}
        except ValueError:
            body = {'response': response.text[:3000]}
        errors = body.get('errors') if isinstance(body, dict) else None
        if errors:
            raise DemistoException(f'Sprinklr remove user from team returned errors: {json.dumps(errors)}')
        return {'status_code': response.status_code, 'email': email, 'team_id': team_id, 'response': body}


    def governance_get_social_logins(self, email: str) -> dict:
        """Get social login profiles linked to a Sprinklr user email."""
        path = self._format_path('/{env}/api/v2/paid/governance/get/socialProfiles/')
        url = urljoin(self.server_url, path)
        response = self._authorized_request('GET', url, params={'userEmail': email})
        if not response.ok:
            body = response.text[:3000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr get social logins request failed. HTTP {response.status_code}. Response: {body}'
            )
        try:
            return response.json()
        except ValueError as exc:
            raise DemistoException('Sprinklr get social logins response was not valid JSON.') from exc

    def governance_create_user(
        self,
        email: str,
        name: str,
        profile_picture: Optional[str] = None,
        teams: Optional[List[dict]] = None,
    ) -> dict:
        """Create a Sprinklr user using the Governance User API."""
        path = self._format_path('/{env}/api/v2/paid/governance/create/user')
        url = urljoin(self.server_url, path)
        payload: Dict[str, Any] = {'email': email, 'name': name}
        if profile_picture:
            payload['profilePicture'] = profile_picture
        if teams:
            payload['teams'] = teams
        response = self._authorized_request('POST', url, json_body=payload)
        if not response.ok:
            body = response.text[:3000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr create user request failed. HTTP {response.status_code}. Response: {body}'
            )
        if not response.text.strip():
            return {'status_code': response.status_code, 'email': email, 'name': name}
        try:
            body = response.json()
        except ValueError:
            body = {'response': response.text[:3000]}
        errors = body.get('errors') if isinstance(body, dict) else None
        if errors:
            raise DemistoException(f'Sprinklr create user returned errors: {json.dumps(errors)}')
        return {'status_code': response.status_code, 'email': email, 'name': name, 'response': body}

    def governance_account_team_action(
        self,
        action: str,
        account_kind: str,
        team_id: str,
        account_id: str,
    ) -> dict:
        """Attach/remove a page or ad account to/from a Sprinklr team."""
        if action not in ('attach', 'remove'):
            raise DemistoException('Unsupported Sprinklr account team action.')
        endpoint_name = {'ad': 'adAccount', 'page': 'pageAccount'}.get(account_kind)
        if not endpoint_name:
            raise DemistoException('account_kind must be ad or page.')
        path = self._format_path(f'/{{env}}/api/v2/paid/governance/{action}/{endpoint_name}')
        url = urljoin(self.server_url, path)
        response = self._authorized_request(
            'POST', url, params={'teamId': team_id, 'accountId': account_id}
        )
        if not response.ok:
            body = response.text[:3000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr {action} {account_kind} account request failed. '
                f'HTTP {response.status_code}. Response: {body}'
            )
        text = response.text.strip()
        parsed: Any = text
        if text:
            try:
                parsed = response.json()
            except ValueError:
                if text.lower() in ('true', 'false'):
                    parsed = text.lower() == 'true'
        else:
            parsed = None
        if parsed is False:
            raise DemistoException(
                f'Sprinklr {action} {account_kind} account returned false.'
            )
        return {
            'status_code': response.status_code,
            'action': action,
            'account_kind': account_kind,
            'team_id': team_id,
            'account_id': account_id,
            'result': parsed,
        }


    def get_account_details(self, account_id: str) -> dict:
        """Fetch a Sprinklr account using the documented Account API."""
        account_id = str(account_id).strip()
        if not account_id:
            raise DemistoException('account_id is required.')
        path = self._format_path('/{env}/api/v2/account/{accountId}').replace(
            '{accountId}', quote(account_id, safe='')
        )
        url = urljoin(self.server_url, path)
        response = self._authorized_request('GET', url)
        if not response.ok:
            body = response.text[:3000] if response.text else '<empty response>'
            raise DemistoException(
                f'Sprinklr fetch account request failed. HTTP {response.status_code}. Response: {body}'
            )
        try:
            return response.json()
        except ValueError as exc:
            raise DemistoException('Sprinklr fetch account response was not valid JSON.') from exc



def _load_json_object(value: Any, field_name: str) -> dict:
    if isinstance(value, dict):
        return copy.deepcopy(value)
    if not value:
        raise DemistoException(f'{field_name} is required.')
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError as exc:
        raise DemistoException(f'{field_name} must be valid JSON. Error: {str(exc)}') from exc
    if not isinstance(parsed, dict):
        raise DemistoException(f'{field_name} must contain a JSON object.')
    return parsed


def _to_epoch_ms(value: Any, default: Optional[int] = None) -> int:
    if value is None or value == '':
        if default is None:
            raise DemistoException('A timestamp value is required.')
        return default

    text = str(value).strip()
    if text.isdigit():
        numeric = int(text)
        return numeric if numeric > 10_000_000_000 else numeric * 1000

    parsed = arg_to_datetime(text)
    if not parsed:
        raise DemistoException(f'Unable to parse timestamp: {text}')
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def _iso_utc_from_ms(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _parse_first_fetch(value: str) -> int:
    # Handle relative intervals first so "1 minute" means now minus one minute.
    parts = str(value).strip().lower().split()
    if len(parts) == 2 and parts[0].isdigit():
        amount = int(parts[0])
        unit = parts[1].rstrip('s')
        delta_map = {
            'second': timedelta(seconds=amount),
            'minute': timedelta(minutes=amount),
            'hour': timedelta(hours=amount),
            'day': timedelta(days=amount),
        }
        if unit in delta_map:
            return int((datetime.now(timezone.utc) - delta_map[unit]).timestamp() * 1000)

    parsed = arg_to_datetime(value)
    if parsed:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    raise DemistoException(f'Unable to parse First fetch time interval: {value}')


def _build_reporting_payload(
    base_payload: dict,
    start_ms: int,
    end_ms: int,
    page_size: int,
    page: int,
) -> dict:
    payload = copy.deepcopy(base_payload)
    payload['startTime'] = str(start_ms)
    payload['endTime'] = str(end_ms)
    payload['pageSize'] = str(page_size)
    payload['page'] = str(page)
    return payload


def _extract_records(response: dict) -> List[dict]:
    data = response.get('data', {}) if isinstance(response, dict) else {}
    rows = data.get('rows', []) if isinstance(data, dict) else []
    records: List[dict] = []
    if not isinstance(rows, list):
        return records

    for row in rows:
        if isinstance(row, dict):
            records.append(row)
        elif isinstance(row, list):
            for item in row:
                if isinstance(item, dict):
                    records.append(item)
    return records


def _event_time_ms(record: dict, fallback_ms: int) -> int:
    # Prefer the Sprinklr publication timestamp, then creation and scheduling timestamps.
    for key in ('publishedDate', 'createdDate', 'scheduleDate'):
        value = record.get(key)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return fallback_ms


def _shape_events(records: List[dict], reporting_engine: str, fallback_ms: int) -> List[dict]:
    shaped: List[dict] = []
    for record in records:
        event = copy.deepcopy(record)
        event['_time'] = _iso_utc_from_ms(_event_time_ms(record, fallback_ms))
        event['source_log_type'] = reporting_engine
        shaped.append(event)
    return shaped


def _validate_required_params(params: dict) -> None:
    required = ['server_url', 'environment', 'client_id', 'client_secret', 'reporting_payload']
    missing = [name for name in required if not params.get(name)]
    if missing:
        raise DemistoException(f"Missing required configuration: {', '.join(missing)}")


def test_module(client: Client, params: dict) -> str:
    _validate_required_params(params)
    base_payload = _load_json_object(params.get('reporting_payload'), 'Reporting API payload')
    now_ms = int(time.time() * 1000)
    payload = _build_reporting_payload(base_payload, now_ms - 60_000, now_ms, 1, 0)
    # This validates both OAuth client-credentials authentication and the Reporting API headers.
    client.report_query(payload)
    return 'ok'


def report_query_command(client: Client, args: dict, params: dict) -> CommandResults:
    raw_payload = args.get('payload') or params.get('reporting_payload')
    payload = _load_json_object(raw_payload, 'payload')
    # The configured collector payload intentionally omits fixed timestamps. For a manual
    # report query, supply a one-minute window only when the payload does not already provide one.
    now_ms = int(time.time() * 1000)
    payload.setdefault('startTime', str(now_ms - 60_000))
    payload.setdefault('endTime', str(now_ms))
    payload.setdefault('pageSize', '20')
    payload.setdefault('page', '0')
    response = client.report_query(payload)
    return CommandResults(
        readable_output='Sprinklr Reporting API query completed successfully.',
        outputs_prefix='Sprinklr.Reporting',
        outputs=response,
        raw_response=response,
    )


def get_events_command(client: Client, args: dict, params: dict) -> CommandResults:
    base_payload = _load_json_object(args.get('payload') or params.get('reporting_payload'), 'Reporting API payload')
    now_ms = int(time.time() * 1000)
    start_ms = _to_epoch_ms(args.get('from_time'), default=now_ms - 60_000)
    end_ms = _to_epoch_ms(args.get('to_time'), default=now_ms)
    if end_ms < start_ms:
        raise DemistoException('to_time must be equal to or later than from_time.')

    limit = int(args.get('limit') or 20)
    if limit < 1 or limit > MAX_SPRINKLR_PAGE_SIZE:
        raise DemistoException(f'limit must be between 1 and {MAX_SPRINKLR_PAGE_SIZE}.')
    page = int(args.get('page') or 0)
    if page < 0:
        raise DemistoException('page must be 0 or greater.')

    payload = _build_reporting_payload(base_payload, start_ms, end_ms, limit, page)
    response = client.report_query(payload)
    records = _extract_records(response)
    reporting_engine = str(base_payload.get('reportingEngine') or base_payload.get('report') or 'REPORTING_API')
    events = _shape_events(records, reporting_engine, end_ms)

    should_push = argToBoolean(args.get('should_push_events', False))
    if should_push:
        send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

    summary = {
        'Count': len(events),
        'From': _iso_utc_from_ms(start_ms),
        'To': _iso_utc_from_ms(end_ms),
        'Page': page,
        'PushedToXSIAM': should_push,
    }
    return CommandResults(
        readable_output=tableToMarkdown('Sprinklr events', summary),
        outputs_prefix='Sprinklr.Events',
        outputs=events,
        raw_response=response,
    )


def _response_has_more(response: dict, records_count: int, page_size: int) -> bool:
    """Return Sprinklr's explicit data.hasMore value, with a safe legacy fallback."""
    data = response.get('data', {}) if isinstance(response, dict) else {}
    if isinstance(data, dict) and 'hasMore' in data:
        value = data.get('hasMore')
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() == 'true'
        return bool(value)
    return records_count >= page_size


def fetch_events_command(client: Client, params: dict) -> Tuple[List[dict], dict]:
    base_payload = _load_json_object(params.get('reporting_payload'), 'Reporting API payload')
    max_fetch = int(params.get('max_fetch') or DEFAULT_XSIAM_FETCH_LIMIT)
    if max_fetch < 1:
        raise DemistoException('Maximum number of events per fetch must be greater than 0.')
    page_size = min(max_fetch, MAX_SPRINKLR_PAGE_SIZE)

    last_run = demisto.getLastRun() or {}
    now_ms = int(time.time() * 1000)

    # Ignore incompatible legacy state once so the configured first-fetch interval is honored.
    if int(last_run.get('state_version') or 0) != FETCH_STATE_VERSION:
        first_fetch = params.get('first_fetch')
        demisto.debug(
            f'Sprinklr fetch state migration: resetting legacy state and honoring first_fetch={first_fetch!r}.'
        )
        last_run = {}

    if last_run.get('pending_end_ms') is not None:
        start_ms = int(last_run['pending_start_ms'])
        end_ms = int(last_run['pending_end_ms'])
        page = int(last_run.get('pending_page', 0))
        previous_completed_ms = int(last_run.get('last_fetch_ms', start_ms - 1))
    else:
        previous_completed_ms = int(last_run.get('last_fetch_ms') or 0)
        if previous_completed_ms:
            start_ms = previous_completed_ms + 1
        else:
            start_ms = _parse_first_fetch(str(params.get('first_fetch') or '1 minute'))
        end_ms = now_ms
        page = 0

    # Avoid querying an inverted window in case the local clock or saved state moves ahead.
    start_ms = min(start_ms, end_ms)

    payload = _build_reporting_payload(base_payload, start_ms, end_ms, page_size, page)
    demisto.debug(
        f'Sprinklr scheduled fetch: start={start_ms}, end={end_ms}, page={page}, page_size={page_size}'
    )
    response = client.report_query(payload)
    records = _extract_records(response)
    has_more = _response_has_more(response, len(records), page_size)
    reporting_engine = str(base_payload.get('reportingEngine') or base_payload.get('report') or 'REPORTING_API')
    events = _shape_events(records, reporting_engine, end_ms)

    # Keep the exact same time window while Sprinklr reports more pages. Advance the completed
    # checkpoint only after data.hasMore is false. This prevents both gaps and duplicate windows.
    if has_more:
        next_run = {
            'state_version': FETCH_STATE_VERSION,
            'last_fetch_ms': previous_completed_ms,
            'pending_start_ms': start_ms,
            'pending_end_ms': end_ms,
            'pending_page': page + 1,
        }
    else:
        next_run = {
            'state_version': FETCH_STATE_VERSION,
            'last_fetch_ms': end_ms,
        }

    demisto.debug(
        f'Sprinklr scheduled fetch result: records={len(records)}, has_more={has_more}, next_run={next_run}'
    )
    return events, next_run



def _collect_report_records(
    client: Client,
    base_payload: dict,
    start_ms: int,
    end_ms: int,
    page_size: int = 200,
    max_pages: int = 10,
) -> List[dict]:
    if page_size < 1 or page_size > MAX_SPRINKLR_PAGE_SIZE:
        raise DemistoException(f'page_size must be between 1 and {MAX_SPRINKLR_PAGE_SIZE}.')
    if max_pages < 1 or max_pages > 100:
        raise DemistoException('max_pages must be between 1 and 100.')

    records: List[dict] = []
    for page in range(max_pages):
        payload = _build_reporting_payload(base_payload, start_ms, end_ms, page_size, page)
        response = client.report_query(payload)
        page_records = _extract_records(response)
        records.extend(page_records)
        if not _response_has_more(response, len(page_records), page_size):
            break
    return records


def _arg_time_range(args: dict, default_from: str = '24 hours ago') -> Tuple[int, int]:
    now_ms = int(time.time() * 1000)
    start_ms = _to_epoch_ms(args.get('from_time') or default_from, default=now_ms - 86_400_000)
    end_ms = _to_epoch_ms(args.get('to_time'), default=now_ms)
    if end_ms < start_ms:
        raise DemistoException('to_time must be equal to or later than from_time.')
    return start_ms, end_ms


def _record_matches(record: dict, args: dict) -> bool:
    mapping = {
        'author_id': 'authorId',
        'account_id': 'accountId',
        'post_id': 'postId',
        'message_id': 'messageId',
        'channel': 'channelType',
        'status': 'status',
    }
    for arg_name, field_name in mapping.items():
        wanted = args.get(arg_name)
        if wanted not in (None, '') and str(record.get(field_name)) != str(wanted):
            return False

    if args.get('deleted') not in (None, ''):
        wanted_deleted = argToBoolean(args.get('deleted'))
        actual = record.get('deleted')
        if isinstance(actual, str):
            actual = actual.strip().lower() == 'true'
        else:
            actual = bool(actual)
        if actual != wanted_deleted:
            return False
    return True


def search_events_command(client: Client, args: dict, params: dict) -> CommandResults:
    base_payload = _load_json_object(params.get('reporting_payload'), 'Reporting API payload')
    start_ms, end_ms = _arg_time_range(args, '24 hours ago')
    page_size = int(args.get('page_size') or 200)
    max_pages = int(args.get('max_pages') or 10)
    limit = int(args.get('limit') or 200)
    if limit < 1 or limit > 10000:
        raise DemistoException('limit must be between 1 and 10000.')

    records = _collect_report_records(client, base_payload, start_ms, end_ms, page_size, max_pages)
    matches = [r for r in records if _record_matches(r, args)][:limit]
    summary = {
        'Scanned': len(records),
        'Matched': len(matches),
        'From': _iso_utc_from_ms(start_ms),
        'To': _iso_utc_from_ms(end_ms),
    }
    return CommandResults(
        readable_output=tableToMarkdown('Sprinklr investigation search', summary),
        outputs_prefix='Sprinklr.Search.Events',
        outputs=matches,
        raw_response=matches,
    )


def user_activity_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['author_id'] = str(args.get('author_id', '')).strip()
    if not scoped['author_id']:
        raise DemistoException('author_id is required.')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.UserActivity'
    return result


def account_activity_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['account_id'] = str(args.get('account_id', '')).strip()
    if not scoped['account_id']:
        raise DemistoException('account_id is required.')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.AccountActivity'
    return result


def get_post_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['post_id'] = str(args.get('post_id', '')).strip()
    if not scoped['post_id']:
        raise DemistoException('post_id is required.')
    scoped.setdefault('limit', '50')
    scoped.setdefault('page_size', '200')
    scoped.setdefault('from_time', '7 days ago')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.Post'
    return result


def deleted_events_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['deleted'] = 'true'
    scoped.setdefault('page_size', '200')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.DeletedEvents'
    return result


def security_summary_command(client: Client, args: dict, params: dict) -> CommandResults:
    base_payload = _load_json_object(params.get('reporting_payload'), 'Reporting API payload')
    start_ms, end_ms = _arg_time_range(args, '24 hours ago')
    page_size = int(args.get('page_size') or 200)
    max_pages = int(args.get('max_pages') or 10)
    records = _collect_report_records(client, base_payload, start_ms, end_ms, page_size, max_pages)

    def counts(field: str) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for record in records:
            value = record.get(field)
            key = '<null>' if value is None else str(value)
            out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items(), key=lambda item: (-item[1], item[0])))

    deleted_count = sum(1 for r in records if str(r.get('deleted')).lower() == 'true' or r.get('deleted') is True)
    summary = {
        'From': _iso_utc_from_ms(start_ms),
        'To': _iso_utc_from_ms(end_ms),
        'TotalEvents': len(records),
        'DeletedEvents': deleted_count,
        'ByStatus': counts('status'),
        'ByChannel': counts('channelType'),
        'ByAuthor': counts('authorId'),
        'ByAccount': counts('accountId'),
    }
    readable_rows = [
        {'Metric': 'Total events', 'Value': len(records)},
        {'Metric': 'Deleted events', 'Value': deleted_count},
        {'Metric': 'Distinct statuses', 'Value': len(summary['ByStatus'])},
        {'Metric': 'Distinct channels', 'Value': len(summary['ByChannel'])},
        {'Metric': 'Distinct authors', 'Value': len(summary['ByAuthor'])},
        {'Metric': 'Distinct accounts', 'Value': len(summary['ByAccount'])},
    ]
    return CommandResults(
        readable_output=tableToMarkdown('Sprinklr security summary', readable_rows),
        outputs_prefix='Sprinklr.SecuritySummary',
        outputs=summary,
        raw_response=summary,
    )


def get_account_details_command(client: Client, args: dict) -> CommandResults:
    account_id = str(args.get('account_id', '')).strip()
    if not account_id:
        raise DemistoException('account_id is required.')
    response = client.get_account_details(account_id)
    return CommandResults(
        readable_output=tableToMarkdown(
            'Sprinklr account details',
            response if isinstance(response, (dict, list)) else {'Result': response},
        ),
        outputs_prefix='Sprinklr.Investigation.AccountDetails',
        outputs=response,
        raw_response=response,
    )


def get_message_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['message_id'] = str(args.get('message_id', '')).strip()
    if not scoped['message_id']:
        raise DemistoException('message_id is required.')
    scoped.setdefault('from_time', '7 days ago')
    scoped.setdefault('limit', '100')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.Message'
    return result


def get_channel_activity_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['channel'] = str(args.get('channel', '')).strip()
    if not scoped['channel']:
        raise DemistoException('channel is required.')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.ChannelActivity'
    return result


def get_status_events_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['status'] = str(args.get('status', '')).strip()
    if not scoped['status']:
        raise DemistoException('status is required.')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.StatusEvents'
    return result


def get_fixed_status_events_command(
    client: Client, args: dict, params: dict, status: str, output_prefix: str
) -> CommandResults:
    scoped = dict(args)
    scoped['status'] = status
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = output_prefix
    return result


def get_author_account_activity_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['author_id'] = str(args.get('author_id', '')).strip()
    scoped['account_id'] = str(args.get('account_id', '')).strip()
    if not scoped['author_id']:
        raise DemistoException('author_id is required.')
    if not scoped['account_id']:
        raise DemistoException('account_id is required.')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.AuthorAccountActivity'
    return result


def get_account_channel_activity_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['account_id'] = str(args.get('account_id', '')).strip()
    scoped['channel'] = str(args.get('channel', '')).strip()
    if not scoped['account_id']:
        raise DemistoException('account_id is required.')
    if not scoped['channel']:
        raise DemistoException('channel is required.')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.AccountChannelActivity'
    return result


def get_author_channel_activity_command(client: Client, args: dict, params: dict) -> CommandResults:
    scoped = dict(args)
    scoped['author_id'] = str(args.get('author_id', '')).strip()
    scoped['channel'] = str(args.get('channel', '')).strip()
    if not scoped['author_id']:
        raise DemistoException('author_id is required.')
    if not scoped['channel']:
        raise DemistoException('channel is required.')
    result = search_events_command(client, scoped, params)
    result.outputs_prefix = 'Sprinklr.Investigation.AuthorChannelActivity'
    return result


def _require_confirmation(args: dict, action: str) -> None:
    confirm = str(args.get('confirm', '')).strip().lower()
    if confirm != 'yes':
        raise DemistoException(f'{action} blocked. Run with confirm=yes only after analyst approval.')


def get_user_command(client: Client, args: dict) -> CommandResults:
    email = str(args.get('email', '')).strip()
    if not email:
        raise DemistoException('email is required.')
    response = client.governance_get_user(email)
    return CommandResults(
        readable_output=tableToMarkdown(
            'Sprinklr user', response if isinstance(response, dict) else {'Result': response}
        ),
        outputs_prefix='Sprinklr.Response.User',
        outputs=response,
        raw_response=response,
    )


def set_user_active_command(client: Client, args: dict, active: bool) -> CommandResults:
    user_id = str(args.get('user_id', '')).strip()
    if not user_id:
        raise DemistoException('user_id is required.')
    action = 'activate user' if active else 'deactivate user'
    _require_confirmation(args, action.capitalize())
    response = client.set_user_active(user_id, active)
    output = {
        'UserID': user_id,
        'Action': 'activate' if active else 'deactivate',
        'Active': active,
        'StatusCode': response.get('status_code'),
    }
    return CommandResults(
        readable_output=tableToMarkdown(f'Sprinklr {action}', output),
        outputs_prefix='Sprinklr.Response',
        outputs=output,
        raw_response=response,
    )


def delete_user_by_email_command(client: Client, args: dict) -> CommandResults:
    email = str(args.get('email', '')).strip()
    if not email:
        raise DemistoException('email is required.')
    _require_confirmation(args, 'Delete user by email')
    response = client.governance_delete_user(email)
    output = {
        'Email': email,
        'Action': 'delete-user-by-email',
        'StatusCode': response.get('status_code'),
    }
    return CommandResults(
        readable_output=tableToMarkdown('Sprinklr delete user by email', output),
        outputs_prefix='Sprinklr.Response',
        outputs=output,
        raw_response=response,
    )


def remove_user_from_team_command(client: Client, args: dict) -> CommandResults:
    email = str(args.get('email', '')).strip()
    team_id = str(args.get('team_id', '')).strip()
    if not email:
        raise DemistoException('email is required.')
    if not team_id:
        raise DemistoException('team_id is required.')
    _require_confirmation(args, 'Remove user from team')
    response = client.governance_remove_user_from_team(email, team_id)
    output = {
        'Email': email,
        'TeamID': team_id,
        'Action': 'remove-user-from-team',
        'StatusCode': response.get('status_code'),
    }
    return CommandResults(
        readable_output=tableToMarkdown('Sprinklr remove user from team', output),
        outputs_prefix='Sprinklr.Response',
        outputs=output,
        raw_response=response,
    )



def _parse_optional_json_list(value: Any, field_name: str) -> Optional[List[dict]]:
    if value in (None, ''):
        return None
    if isinstance(value, list):
        parsed = value
    else:
        try:
            parsed = json.loads(str(value))
        except json.JSONDecodeError as exc:
            raise DemistoException(f'{field_name} must be a valid JSON array. Error: {str(exc)}') from exc
    if not isinstance(parsed, list):
        raise DemistoException(f'{field_name} must contain a JSON array.')
    if not all(isinstance(item, dict) for item in parsed):
        raise DemistoException(f'Every {field_name} item must be a JSON object.')
    return parsed


def get_social_logins_command(client: Client, args: dict) -> CommandResults:
    email = str(args.get('email', '')).strip()
    if not email:
        raise DemistoException('email is required.')
    response = client.governance_get_social_logins(email)
    return CommandResults(
        readable_output=tableToMarkdown(
            'Sprinklr social logins',
            response if isinstance(response, (dict, list)) else {'Result': response},
        ),
        outputs_prefix='Sprinklr.Investigation.SocialLogins',
        outputs=response,
        raw_response=response,
    )


def create_user_command(client: Client, args: dict) -> CommandResults:
    email = str(args.get('email', '')).strip()
    name = str(args.get('name', '')).strip()
    if not email:
        raise DemistoException('email is required.')
    if not name:
        raise DemistoException('name is required.')
    _require_confirmation(args, 'Create user')
    teams = _parse_optional_json_list(args.get('teams'), 'teams')
    response = client.governance_create_user(
        email=email,
        name=name,
        profile_picture=str(args.get('profile_picture', '')).strip() or None,
        teams=teams,
    )
    output = {
        'Email': email,
        'Name': name,
        'Action': 'create-user',
        'StatusCode': response.get('status_code'),
    }
    return CommandResults(
        readable_output=tableToMarkdown('Sprinklr create user', output),
        outputs_prefix='Sprinklr.Response',
        outputs=output,
        raw_response=response,
    )


def account_team_action_command(
    client: Client,
    args: dict,
    action: str,
    account_kind: str,
) -> CommandResults:
    team_id = str(args.get('team_id', '')).strip()
    account_id = str(args.get('account_id', '')).strip()
    if not team_id:
        raise DemistoException('team_id is required.')
    if not account_id:
        raise DemistoException('account_id is required.')
    _require_confirmation(args, f'{action.capitalize()} {account_kind} account')
    response = client.governance_account_team_action(action, account_kind, team_id, account_id)
    output = {
        'TeamID': team_id,
        'AccountID': account_id,
        'AccountKind': account_kind,
        'Action': f'{action}-{account_kind}-account',
        'StatusCode': response.get('status_code'),
        'Result': response.get('result'),
    }
    return CommandResults(
        readable_output=tableToMarkdown(f'Sprinklr {action} {account_kind} account', output),
        outputs_prefix='Sprinklr.Response',
        outputs=output,
        raw_response=response,
    )


def deprovision_user_command(client: Client, args: dict) -> CommandResults:
    user_id = str(args.get('user_id', '')).strip()
    if not user_id:
        raise DemistoException('user_id is required.')
    _require_confirmation(args, 'Deprovision user')

    status_code = client.deprovision_user(user_id)
    output = {'UserID': user_id, 'Action': 'deprovision', 'StatusCode': status_code}
    return CommandResults(
        readable_output=f'Sprinklr user **{user_id}** was deprovisioned successfully (HTTP 204).',
        outputs_prefix='Sprinklr.Response',
        outputs_key_field='UserID',
        outputs=output,
        raw_response={'status_code': status_code, 'user_id': user_id},
    )


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        _validate_required_params(params)
        handle_proxy()
        client = Client(
            server_url=str(params.get('server_url', '')).strip(),
            environment=str(params.get('environment', '')).strip(),
            client_id=str(params.get('client_id', '')).strip(),
            client_secret=str(params.get('client_secret', '')),
            reporting_path=str(params.get('reporting_path') or '/{env}/api/v2/reports/query'),
            scim_delete_path=str(params.get('scim_delete_path') or '/{env}/api/v1/scim/v2/Users/{userId}'),
            verify=not argToBoolean(params.get('insecure', False)),
            timeout=int(params.get('timeout') or 60),
        )

        if command == 'test-module':
            return_results(test_module(client, params))
        elif command == 'sprinklr-report-query':
            return_results(report_query_command(client, args, params))
        elif command == 'sprinklr-get-events':
            return_results(get_events_command(client, args, params))
        elif command == 'sprinklr-search-events':
            return_results(search_events_command(client, args, params))
        elif command == 'sprinklr-get-user-activity':
            return_results(user_activity_command(client, args, params))
        elif command == 'sprinklr-get-account-activity':
            return_results(account_activity_command(client, args, params))
        elif command == 'sprinklr-get-post':
            return_results(get_post_command(client, args, params))
        elif command == 'sprinklr-get-deleted-events':
            return_results(deleted_events_command(client, args, params))
        elif command == 'sprinklr-security-summary':
            return_results(security_summary_command(client, args, params))
        elif command == 'sprinklr-get-account-details':
            return_results(get_account_details_command(client, args))
        elif command == 'sprinklr-get-message':
            return_results(get_message_command(client, args, params))
        elif command == 'sprinklr-get-channel-activity':
            return_results(get_channel_activity_command(client, args, params))
        elif command == 'sprinklr-get-status-events':
            return_results(get_status_events_command(client, args, params))
        elif command == 'sprinklr-get-failed-events':
            return_results(get_fixed_status_events_command(
                client, args, params, 'FAILED', 'Sprinklr.Investigation.FailedEvents'
            ))
        elif command == 'sprinklr-get-sent-events':
            return_results(get_fixed_status_events_command(
                client, args, params, 'SENT', 'Sprinklr.Investigation.SentEvents'
            ))
        elif command == 'sprinklr-get-author-account-activity':
            return_results(get_author_account_activity_command(client, args, params))
        elif command == 'sprinklr-get-account-channel-activity':
            return_results(get_account_channel_activity_command(client, args, params))
        elif command == 'sprinklr-get-author-channel-activity':
            return_results(get_author_channel_activity_command(client, args, params))
        elif command == 'fetch-events':
            events, next_run = fetch_events_command(client, params)
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
        elif command == 'sprinklr-get-user':
            return_results(get_user_command(client, args))
        elif command == 'sprinklr-deactivate-user':
            return_results(set_user_active_command(client, args, active=False))
        elif command == 'sprinklr-activate-user':
            return_results(set_user_active_command(client, args, active=True))
        elif command == 'sprinklr-remove-user-from-team':
            return_results(remove_user_from_team_command(client, args))
        elif command == 'sprinklr-delete-user-by-email':
            return_results(delete_user_by_email_command(client, args))
        elif command == 'sprinklr-get-social-logins':
            return_results(get_social_logins_command(client, args))
        elif command == 'sprinklr-create-user':
            return_results(create_user_command(client, args))
        elif command == 'sprinklr-attach-ad-account-to-team':
            return_results(account_team_action_command(client, args, action='attach', account_kind='ad'))
        elif command == 'sprinklr-remove-ad-account-from-team':
            return_results(account_team_action_command(client, args, action='remove', account_kind='ad'))
        elif command == 'sprinklr-attach-page-account-to-team':
            return_results(account_team_action_command(client, args, action='attach', account_kind='page'))
        elif command == 'sprinklr-remove-page-account-from-team':
            return_results(account_team_action_command(client, args, action='remove', account_kind='page'))
        elif command == 'sprinklr-deprovision-user':
            return_results(deprovision_user_command(client, args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')
    except Exception as exc:
        return_error(f'Failed to execute {command}. Error: {str(exc)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
