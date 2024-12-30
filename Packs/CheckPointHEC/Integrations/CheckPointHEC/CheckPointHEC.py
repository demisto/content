import hashlib
import uuid
from urllib.parse import urlencode

import urllib3

from CommonServerPython import *

urllib3.disable_warnings()

ANTI_MALWARE_SAAS_NAME = 'checkpoint2'
AVANAN_URL_SAAS_NAME = 'avanan_url'
AVANAN_DLP_SAAS_NAME = 'avanan_dlp'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
FETCH_INTERVAL_DEFAULT = 1
MAX_FETCH_DEFAULT = 10
SAAS_NAMES = [
    'office365_emails',
    'google_mail'
]
SAAS_APPS_TO_SAAS_NAMES = {
    'Microsoft Exchange': 'office365_emails',
    'Gmail': 'google_mail'
}
SEVERITY_VALUES = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'very low': 1
}
CP_DETECTION_VALUES = {
    'Phishing': 'cp_phishing',
    'Suspected Phishing': 'cp_ap_suspicious',
    'Malware': 'cp_malicious',
    'Suspected Malware': 'cp_av_suspicious',
    'Spam': 'cp_spam',
    'Clean': 'cp_clean',
    'DLP': 'cp_leak',
    'Malicious URL Click': 'cp_malicious_url_click',
    'Malicious URL': 'cp_malicious_url'
}
MS_DETECTION_VALUES = {
    'Malware': 'ms_malware',
    'High Confidence Phishing': 'ms_high_confidence_phishing',
    'Phishing': 'ms_phishing',
    'High Confidence Spam': 'ms_high_confidence_spam',
    'Spam': 'ms_spam',
    'Bulk': 'ms_bulk',
    'Clean': 'ms_clean'
}
CP_QUARANTINED_VALUES = {
    'Quarantined (Any source)': 'all',
    'Not Quarantined': 'cp_not_quarantined',
    'Quarantined by Check Point': 'cp_quarantined_by_cp',
    'Quarantined by CP Analyst': 'cp_quarantined_by_analyst',
    'Quarantined by Admin': 'cp_quarantined_by_admin'
}
MS_QUARANTINED_VALUES = {
    'Quarantined': 'ms_quarantined',
    'Not Quarantined': 'ms_not_quarantined',
    'Not Quarantined Delivered to Inbox': 'ms_delivered_inbox',
    'Not Quarantined Delivered to Junk': 'ms_delivered_junk'
}
MIS_CLASSIFICATION_CONFIDENCE = {
    'Not so sure': 'not_so_sure',
    'Medium Confidence': 'medium',
    'High Confidence': 'very',
}
MIS_CLASSIFICATION_OPTIONS = {
    'Clean Email': 'clean',
    'Spam': 'spam',
    'Phishing': 'phishing',
    'Legit Marketing Email': 'marketing_email',
}


def arg_to_bool(arg: Optional[str]) -> bool:
    try:
        return argToBoolean(arg)
    except ValueError:
        return False


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.api_version = 'v1.0'
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_expiry = float('-inf')
        self.is_infinity = 'cloudinfra' in base_url

    def _should_refresh_token(self) -> bool:
        return not self.token or time.time() >= self.token_expiry

    def _generate_infinity_token(self):
        if self._should_refresh_token():
            payload = {
                "clientId": self.client_id,
                "accessKey": self.client_secret
            }
            timestamp = time.time()

            res = self._http_request(
                method='POST',
                url_suffix='auth/external',
                json_data=payload
            )
            data = res['data']
            self.token = data.get('token')
            self.token_expiry = timestamp + float(data.get('expiresIn'))

        return self.token

    def _generate_signature(self, request_id: str, timestamp: str, request_string: str = None) -> str:
        if request_string:
            signature_string = f'{request_id}{self.client_id}{timestamp}{request_string}{self.client_secret}'
        else:
            signature_string = f'{request_id}{self.client_id}{timestamp}{self.client_secret}'
        signature_bytes = signature_string.encode('utf-8')
        signature_base64_bytes = base64.b64encode(signature_bytes)
        signature_hash = hashlib.sha256(signature_base64_bytes).hexdigest()
        return signature_hash

    def _get_headers(self, request_string: str = None, auth: bool = False) -> dict[str, str]:
        request_id = str(uuid.uuid4())
        if self.is_infinity:
            token = self._generate_infinity_token()
            headers = {
                'Authorization': f'Bearer {token}',
                'x-av-req-id': request_id,
            }
        else:
            timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
            headers = {
                'x-av-req-id': request_id,
                'x-av-app-id': self.client_id,
                'x-av-date': timestamp,
                'x-av-sig': self._generate_signature(request_id, timestamp, request_string),
            }
            if not auth:
                headers['x-av-token'] = self._get_token()
        return headers

    def _get_token(self) -> str:
        if self.token:
            return self.token

        self.token = self._http_request(
            'GET',
            url_suffix=f'{self.api_version}/auth',
            headers=self._get_headers(auth=True),
            resp_type='text',
        )
        return self.token or ''

    def _call_api(self, method: str, url_suffix: str, params: dict = None, json_data: dict = None) -> dict[str, Any]:
        if self.is_infinity:
            path = '/'.join(['app', 'hec-api', self.api_version, url_suffix])
            request_string = None
        else:
            path = '/'.join([self.api_version, url_suffix])
            request_string = f'/{path}'
            if params:
                request_string += f'?{urlencode(params)}'

        return self._http_request(
            method,
            url_suffix=path,
            headers=self._get_headers(request_string),
            params=params,
            json_data=json_data
        )

    def test_api(self) -> dict[str, Any]:
        return self._call_api(
            'GET',
            url_suffix='scopes'
        )

    def restore_requests(self, start_date: str, saas: str, include_denied: bool, include_accepted: bool) -> dict[str, Any]:
        denied_attr_op = 'is' if include_denied else 'isNot'
        accepted_attr_op = 'is' if include_accepted else 'isNot'
        fifteen_days_ago = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=15)).isoformat()
        entity_filter = {
            'saas': saas,
            'startDate': fifteen_days_ago,
        }

        request_data: dict[str, Any] = {
            'entityFilter': entity_filter,
            'entityExtendedFilter': [
                {
                    'saasAttrName': 'entityPayload.isRestoreRequested',
                    'saasAttrOp': 'is',
                    'saasAttrValue': 'true'
                },
                {
                    'saasAttrName': 'entityPayload.restoreRequestTime',
                    'saasAttrOp': 'greaterThan',
                    'saasAttrValue': start_date
                },
                {
                    'saasAttrName': 'entityPayload.isRestoreDeclined',
                    'saasAttrOp': denied_attr_op,
                    'saasAttrValue': 'true'
                },
                {
                    'saasAttrName': 'entityPayload.isRestored',
                    'saasAttrOp': accepted_attr_op,
                    'saasAttrValue': 'true'
                }
            ]
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            url_suffix='search/query',
            json_data=payload
        )

    def query_events(self, start_date: str, end_date: str = None, saas_apps: List[str] = None, states: List[str] = None,
                     severities: List[int] = None, threat_types: List[str] = None) -> dict[str, Any]:
        request_data: dict[str, Any] = {
            'startDate': start_date,
            'endDate': end_date,
            'saas': saas_apps or SAAS_NAMES,
        }
        if states:
            request_data['eventStates'] = states
        if severities:
            request_data['severities'] = severities
        if threat_types:
            request_data['eventTypes'] = threat_types

        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            url_suffix='event/query',
            json_data=payload
        )

    def get_entity(self, entity: str) -> dict[str, Any]:
        return self._call_api(
            'GET',
            url_suffix=f'search/entity/{entity}'
        )

    def get_email(self, entity: str) -> dict[str, Any]:
        return self._call_api(
            'GET',
            url_suffix=f'soar/entity/{entity}'
        )

    def search_emails(self, start_date: str, end_date: str = None, saas: str = None, direction: str = None,
                      subject_contains: str = None, subject_match: str = None, sender_contains: str = None,
                      sender_match: str = None, domain: str = None, cp_detection: List[str] = None,
                      ms_detection: List[str] = None, detection_op: str = None, server_ip: str = None,
                      recipients_contains: str = None, recipients_match: str = None, links: str = None, message_id: str = None,
                      cp_quarantined_state: str = None, ms_quarantined_state: str = None, quarantined_state_op: str = None,
                      name_contains: str = None, name_match: str = None, client_ip: str = None, attachment_md5: str = None):
        entity_filter = {
            'saas': saas,
            'startDate': start_date,
        }
        if end_date:
            entity_filter['endDate'] = end_date
        extended_filter = []
        detection_resolution_filter: dict[str, Any] = {}
        if direction:
            extended_filter.append({
                'saasAttrName': f'entityPayload.is{direction}',
                'saasAttrOp': 'is',
                'saasAttrValue': 'true',
            })
        if subject_contains:
            extended_filter.append({
                'saasAttrName': 'entityPayload.subject',
                'saasAttrOp': 'contains',
                'saasAttrValue': subject_contains
            })
        elif subject_match:
            extended_filter.append({
                'saasAttrName': 'entityPayload.subject',
                'saasAttrOp': 'is',
                'saasAttrValue': subject_match
            })
        if sender_contains:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromEmail',
                'saasAttrOp': 'contains',
                'saasAttrValue': sender_contains
            })
        elif sender_match:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromEmail',
                'saasAttrOp': 'is',
                'saasAttrValue': sender_match
            })
        if domain:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromDomain',
                'saasAttrOp': 'is',
                'saasAttrValue': domain
            })
        if cp_detection:
            detection_resolution_filter['cpDetection'] = cp_detection
        if ms_detection:
            detection_resolution_filter['msDetection'] = ms_detection
        if cp_detection and ms_detection:
            detection_resolution_filter['detectionOp'] = detection_op
        if server_ip:
            extended_filter.append({
                'saasAttrName': 'entityPayload.senderServerIp',
                'saasAttrOp': 'is',
                'saasAttrValue': server_ip
            })
        if recipients_contains:
            extended_filter.append({
                'saasAttrName': 'entityPayload.recipients',
                'saasAttrOp': 'contains',
                'saasAttrValue': recipients_contains
            })
        elif recipients_match:
            extended_filter.append({
                'saasAttrName': 'entityPayload.recipients',
                'saasAttrOp': 'is',
                'saasAttrValue': recipients_match
            })
        if links:
            extended_filter.append({
                'saasAttrName': 'entityPayload.emailLinks',
                'saasAttrOp': 'is',
                'saasAttrValue': links
            })
        if message_id:
            extended_filter.append({
                'saasAttrName': 'entityPayload.internetMessageId',
                'saasAttrOp': 'is',
                'saasAttrValue': message_id
            })
        if cp_quarantined_state:
            detection_resolution_filter['cpQuarantinedState'] = cp_quarantined_state
        if ms_quarantined_state:
            detection_resolution_filter['msQuarantinedState'] = ms_quarantined_state
        if cp_quarantined_state and ms_quarantined_state:
            detection_resolution_filter['quarantinedStateOp'] = quarantined_state_op
        if name_contains:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromName',
                'saasAttrOp': 'contains',
                'saasAttrValue': name_contains
            })
        elif name_match:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromName',
                'saasAttrOp': 'is',
                'saasAttrValue': name_match
            })
        if client_ip:
            extended_filter.append({
                'saasAttrName': 'entityPayload.senderClientIp',
                'saasAttrOp': 'is',
                'saasAttrValue': client_ip
            })
        if attachment_md5:
            extended_filter.append({
                'saasAttrName': 'entityPayload.attachments.MD5',
                'saasAttrOp': 'is',
                'saasAttrValue': attachment_md5
            })
        request_data: dict[str, Any] = {
            'entityFilter': entity_filter,
        }
        if extended_filter:
            request_data['entityExtendedFilter'] = extended_filter
        if detection_resolution_filter:
            request_data['entityDetectionResolutionFilter'] = detection_resolution_filter
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            url_suffix='search/query',
            json_data=payload
        )

    def send_action(self, entities: list, entity_type: str, action: str, restore_decline_reason: str = None):
        request_data = assign_params(**{
            'entityIds': entities,
            'entityType': entity_type,
            'entityActionName': action,
            'restoreDeclineReason': restore_decline_reason
        })
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            'action/entity',
            json_data=payload,
        )

    def get_task(self, task: str):
        return self._call_api(
            'GET',
            f'task/{task}',
        )

    def send_notification(self, entity: str, emails: List[str]):
        payload = {
            'requestData': {
                'entityId': entity,
                'emails': emails
            }
        }
        return self._call_api(
            'POST',
            'soar/notify',
            json_data=payload
        )

    def report_mis_classification(self, entities: List[str], classification: str, confident: str):
        request_data = {
            'entityIds': entities,
            'classification': classification,
            'confident': confident
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            'report/mis-classification',
            json_data=payload
        )

    def get_ap_exceptions(self, exc_type: str, exc_id: str = None):
        path = f'exceptions/{exc_type}/{exc_id}' if exc_id else f'exceptions/{exc_type}'
        return self._call_api('GET', path)

    def create_ap_exception(self, exc_type: str, entity_id: str = None, attachment_md5: str = None, from_email: str = None,
                            nickname: str = None, recipient: str = None, sender_client_ip: str = None,
                            from_domain_ends_with: str = None, sender_ip: str = None, email_link: List[str] = None,
                            subject: str = None, comment: str = None, action_needed: str = None, ignoring_spf_check: bool = None,
                            subject_matching: str = None, email_link_matching: str = None, from_name_matching: str = None,
                            from_domain_matching: str = None, from_email_matching: str = None, recipient_matching: str = None):
        request_data = assign_params(**{
            'entityId': entity_id,
            'attachmentMd5': attachment_md5,
            'senderEmail': from_email,
            'senderName': nickname,
            'recipient': recipient,
            'senderClientIp': sender_client_ip,
            'senderDomain': from_domain_ends_with,
            'senderIp': sender_ip,
            'linkDomains': email_link,
            'subject': subject,
            'comment': comment,
            'actionNeeded': action_needed,
            'ignoringSpfCheck': ignoring_spf_check,
            'subjectMatching': subject_matching,
            'linkDomainMatching': email_link_matching,
            'senderNameMatching': from_name_matching,
            'senderDomainMatching': from_domain_matching,
            'senderEmailMatching': from_email_matching,
            'recipientMatching': recipient_matching
        })
        payload = {
            'requestData': request_data
        }
        return self._call_api('POST', f'exceptions/{exc_type}', json_data=payload)

    def update_ap_exception(self, exc_type: str, exc_id: str, entity_id: str = None, attachment_md5: str = None,
                            from_email: str = None, nickname: str = None, recipient: str = None, sender_client_ip: str = None,
                            from_domain_ends_with: str = None, sender_ip: str = None, email_link: List[str] = None,
                            subject: str = None, comment: str = None, action_needed: str = None, ignoring_spf_check: bool = None,
                            subject_matching: str = None, email_link_matching: str = None, from_name_matching: str = None,
                            from_domain_matching: str = None, from_email_matching: str = None, recipient_matching: str = None):
        request_data = assign_params(**{
            'entityId': entity_id,
            'attachmentMd5': attachment_md5,
            'senderEmail': from_email,
            'senderName': nickname,
            'recipient': recipient,
            'senderClientIp': sender_client_ip,
            'senderDomain': from_domain_ends_with,
            'senderIp': sender_ip,
            'linkDomains': email_link,
            'subject': subject,
            'comment': comment,
            'actionNeeded': action_needed,
            'ignoringSpfCheck': ignoring_spf_check,
            'subjectMatching': subject_matching,
            'linkDomainMatching': email_link_matching,
            'senderNameMatching': from_name_matching,
            'senderDomainMatching': from_domain_matching,
            'senderEmailMatching': from_email_matching,
            'recipientMatching': recipient_matching
        })
        payload = {
            'requestData': request_data
        }
        return self._call_api('PUT', f'exceptions/{exc_type}/{exc_id}', json_data=payload)

    def delete_ap_exception(self, exc_type: str, exc_id: str):
        return self._call_api('POST', f'exceptions/{exc_type}/delete/{exc_id}')

    def get_sectool_exception(self, sectool: str, exc_type: str, exc_str: str):
        path = f'sectool-exceptions/{sectool}/exceptions/{exc_type}/{exc_str}'
        return self._call_api('GET', path)

    def create_sectool_exception(self, sectool: str, exc_type: str, exc_str: str, entity_type: str = None, entity_id: str = None,
                                 comment: str = None, exc_payload_condition: str = None, file_name: str = None,
                                 created_by_email: str = None, is_exclusive: bool = None):
        request_data = assign_params(**{
            'exceptionType': exc_type,
            'exceptionStr': exc_str,
            'entityType': entity_type,
            'entityId': entity_id,
            'fileName': file_name,
            'createdByEmail': created_by_email,
            'isExclusive': is_exclusive,
            'comment': comment,
        })
        if exc_payload_condition:
            request_data['exceptionPayload'] = {
                'condition': exc_payload_condition
            }
        payload = {
            'requestData': request_data
        }
        return self._call_api('POST', f'sectool-exceptions/{sectool}', json_data=payload)

    def update_sectool_exception(self, sectool: str, exc_type: str, exc_str: str, comment: str = None,
                                 exc_payload_condition: str = None):
        request_data = assign_params(**{
            'exceptionType': exc_type,
            'exceptionStr': exc_str,
            'comment': comment,
        })
        if exc_payload_condition:
            request_data['exceptionPayload'] = {
                'condition': exc_payload_condition
            }
        payload = {
            'requestData': request_data
        }
        return self._call_api('PUT', f'sectool-exceptions/{sectool}', json_data=payload)

    def delete_sectool_exception(self, sectool: str, exc_type: str, exc_str: str, entity_type: str = None, entity_id: str = None):
        request_data = assign_params(**{
            'exceptionType': exc_type,
            'exceptionStr': exc_str,
            'entityType': entity_type,
            'entityId': entity_id
        })
        payload = {
            'requestData': request_data
        }
        return self._call_api('DELETE', f'sectool-exceptions/{sectool}', json_data=payload)

    def get_sectool_exceptions(self, sectool: str, exc_type: str, filter_str: str = None, filter_index: str = None,
                               sort_dir: str = None, last_evaluated_key: str = None, insert_time_gte: bool = None,
                               limit: int = None):
        request_data = assign_params(**{
            'filterStr': filter_str,
            'filterIndex': filter_index,
            'sortDir': sort_dir,
            'lastEvaluatedKey': last_evaluated_key,
            'insertTimeGte': insert_time_gte,
            'limit': limit
        })
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'GET',
            f'sectool-exceptions/{sectool}/exceptions/{exc_type}',
            json_data=payload
        )

    def delete_sectool_exceptions(self, sectool: str, exc_type: str, exc_str_list: List[str], entity_type: str = None,
                                  entity_id: str = None):
        request_data = assign_params(**{
            'exceptionType': exc_type,
            'exceptionStrList': exc_str_list,
            'entityType': entity_type,
            'entityId': entity_id
        })
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'DELETE',
            f'sectool-exceptions/{sectool}/exceptions',
            json_data=payload
        )

    def get_anomaly_exceptions(self):
        return self._call_api('GET', 'sectools/anomaly/exceptions')

    def create_anomaly_exceptions(self, request_json: dict, added_by: str = None):
        request_data = assign_params(**{
            'requestJson': request_json,
            'addedBy': added_by
        })
        payload = {
            'requestData': request_data
        }
        return self._call_api('POST', 'sectools/anomaly/exceptions', json_data=payload)

    def delete_anomaly_exceptions(self, rule_ids: List[str]):
        request_data = {
            'ruleId': rule_ids
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api('DELETE', 'sectools/anomaly/exceptions', json_data=payload)

    def get_ctp_lists(self):
        return self._call_api('GET', 'sectools/click_time_protection/exceptions')

    def get_ctp_list(self, list_id: str):
        return self._call_api('GET', f'sectools/click_time_protection/exceptions/{list_id}')

    def get_ctp_list_items(self):
        return self._call_api('GET', 'sectools/click_time_protection/exceptions/items')

    def get_ctp_list_item(self, item_id: str):
        return self._call_api('GET', f'sectools/click_time_protection/exceptions/items/{item_id}')

    def create_ctp_list_item(self, list_id: str, list_item_name: str, created_by: str):
        request_data = {
            'listId': list_id,
            'listItemName': list_item_name,
            'createdBy': created_by
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api('POST', 'sectools/click_time_protection/exceptions/items', json_data=payload)

    def update_ctp_list_item(self, item_id: str, list_id: str, list_item_name: str, created_by: str):
        request_data = {
            'listId': list_id,
            'listItemName': list_item_name,
            'createdBy': created_by
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api('PUT', f'sectools/click_time_protection/exceptions/items/{item_id}', json_data=payload)

    def delete_ctp_list_item(self, item_id: str):
        return self._call_api('DELETE', f'sectools/click_time_protection/exceptions/items/{item_id}')

    def delete_ctp_list_items(self, list_item_ids: List[str]):
        request_data = {
            'listItemIds': list_item_ids
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api('DELETE', 'sectools/click_time_protection/exceptions/items', json_data=payload)

    def delete_ctp_lists(self):
        return self._call_api('DELETE', 'sectools/click_time_protection/exceptions')


def test_module(client: Client):
    result = client.test_api()
    scopes = result.get('responseData')

    if not isinstance(scopes, list):
        return 'scope format wrong'

    if len(scopes) != 1:
        return 'multi customer supported'

    if len(scopes[0].split(':')) != 2:
        return 'customer format wrong'

    return 'ok'


def fetch_incidents(client: Client, params: dict):
    first_fetch: str = params.get('first_fetch', '1 hour')
    saas_apps: List[str] = [SAAS_APPS_TO_SAAS_NAMES[x] for x in argToList(params.get('saas_apps'))] or SAAS_NAMES
    states: List[str] = [x.lower() for x in argToList(params.get('event_state'))]
    severities: List[int] = [SEVERITY_VALUES[x.lower()] for x in argToList(params.get('event_severity'))]
    threat_types: List[str] = [x.lower().replace(' ', '_') for x in argToList(params.get('threat_type'))]
    max_fetch: int = arg_to_number(params.get('max_fetch')) or MAX_FETCH_DEFAULT
    fetch_interval: int = arg_to_number(params.get('incidentFetchInterval')) or FETCH_INTERVAL_DEFAULT

    now = datetime.now(timezone.utc).replace(tzinfo=None)  # We get current time before processing
    last_run = demisto.getLastRun()
    if not (last_fetch := last_run.get('last_fetch')):
        if last_fetch := dateparser.parse(first_fetch, date_formats=[DATE_FORMAT]):
            last_fetch = last_fetch.isoformat()
        else:
            raise DemistoException('Could not get last fetch')

    counter = 0
    incidents: List[dict[str, Any]] = []

    result = client.query_events(
        start_date=last_fetch, states=states, saas_apps=saas_apps, severities=severities, threat_types=threat_types
    )
    events = result['responseData']

    for event in events:
        if (occurred := event.get('eventCreated')) <= last_fetch:
            continue

        threat_type = event.get('type')

        count_field = f'count_{threat_type}'
        count = last_run.get(count_field, 0) + 1
        last_run[count_field] = count

        incidents.append({
            'dbotMirrorId': event.get('eventId'),
            'details': event.get('description'),
            'name': f'Threat: {threat_type.replace("_", " ").title()} {count}',
            'occurred': occurred,
            'rawJSON': json.dumps(event),
        })

        if max_fetch == (counter := counter + 1):
            break

    if incidents:
        last_run['last_fetch'] = incidents[-1]['occurred']
    else:
        last_run['last_fetch'] = (now - timedelta(minutes=fetch_interval)).isoformat()

    demisto.setLastRun(last_run)
    demisto.incidents(incidents)


def fetch_restore_requests(client: Client, params: dict):
    first_fetch: str = params.get('first_fetch', '1 hour')
    saas_apps: List[str] = [SAAS_APPS_TO_SAAS_NAMES[x] for x in argToList(params.get('saas_apps'))] or SAAS_NAMES
    max_fetch: int = arg_to_number(params.get('max_fetch')) or MAX_FETCH_DEFAULT
    fetch_interval: int = arg_to_number(params.get('incidentFetchInterval')) or FETCH_INTERVAL_DEFAULT

    now = datetime.now(timezone.utc).replace(tzinfo=None)  # We get current time before processing
    last_run = demisto.getLastRun()
    if not (last_fetch := last_run.get('last_rr_fetch')):
        if last_fetch := dateparser.parse(first_fetch, date_formats=[DATE_FORMAT]):
            last_fetch = last_fetch.isoformat()
        else:
            raise DemistoException('Could not get last restore request fetch')

    counter = 0
    incidents: List[dict[str, Any]] = []

    include_denied_rr = arg_to_bool(params.get('include_denied_requests'))
    include_accepted_rr = arg_to_bool(params.get('include_accepted_requests'))
    for saas in saas_apps:
        result = client.restore_requests(last_fetch, saas, include_denied_rr, include_accepted_rr)
        for restore_request in result['responseData']:
            entity_info = restore_request.get('entityInfo')
            entity_payload = restore_request.get('entityPayload')
            if (occurred := entity_payload.get('restoreRequestTime')) <= last_fetch:
                continue

            count_field = 'count_restore_request'
            count = last_run.get(count_field, 0) + 1
            last_run[count_field] = count

            incidents.append({
                'dbotMirrorId': entity_info.get('entityId'),
                'details': entity_payload.get('restoreCommentary'),
                'name': f'Threat: Restore Request {count}',
                'occurred': occurred,
                'rawJSON': json.dumps(entity_payload),
            })

            if max_fetch == (counter := counter + 1):
                break

    if incidents:
        last_run['last_rr_fetch'] = incidents[-1]['occurred']
    else:
        last_run['last_rr_fetch'] = (now - timedelta(minutes=fetch_interval)).isoformat()

    demisto.setLastRun(last_run)
    demisto.incidents(incidents)


def checkpointhec_get_entity(client: Client, args: dict) -> CommandResults:
    entity: str = args['entity']

    result = client.get_entity(entity)
    if entities := result.get('responseData'):
        _entity = entities[0]['entityPayload']
        human_readable = tableToMarkdown('entity', _entity, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.Entity',
            outputs_key_field='internetMessageId',
            readable_output=human_readable,
            outputs=_entity,
        )
    else:
        return CommandResults(
            readable_output=f'Entity with id {entity} not found'
        )


def checkpointhec_get_events(client: Client, args: dict) -> CommandResults:
    start_date: str = args['start_date']
    end_date: Optional[str] = args.get('end_date')
    saas_apps: Optional[List[str]] = [SAAS_APPS_TO_SAAS_NAMES[x] for x in argToList(args.get('saas_apps'))]
    states: Optional[List[str]] = [x.lower() for x in argToList(args.get('states'))]
    severities: Optional[List[int]] = [SEVERITY_VALUES[x.lower()] for x in argToList(args.get('severities'))]
    threat_types: Optional[List[str]] = [x.lower().replace(' ', '_') for x in argToList(args.get('threat_type'))]
    limit: int = arg_to_number(args.get('limit')) or 1000

    result = client.query_events(
        start_date=start_date, end_date=end_date, saas_apps=saas_apps, states=states, severities=severities,
        threat_types=threat_types
    )
    if events := result.get('responseData'):
        _events = events[:min(limit, len(events))]
        human_readable = tableToMarkdown('events', _events, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.Event',
            outputs_key_field='eventId',
            readable_output=human_readable,
            outputs=_events,
        )
    else:
        return CommandResults(
            readable_output='Events not found with the given criteria'
        )


def checkpointhec_get_scan_info(client: Client, args: dict) -> CommandResults:
    entity: str = args['entity']

    result = client.get_entity(entity)
    outputs = {}
    if entities := result.get('responseData'):
        sec_result = entities[0]['entitySecurityResult']
        for tool, verdict in sec_result['combinedVerdict'].items():
            if verdict not in (None, 'clean'):
                outputs[tool] = json.dumps(sec_result[tool])
        return CommandResults(
            outputs_prefix='CheckPointHEC.ScanResult',
            outputs=outputs
        )
    else:
        return CommandResults(
            readable_output=f'Entity with id {entity} not found'
        )


def checkpointhec_search_emails(client: Client, args: dict, params: dict) -> CommandResults:
    date_last: Optional[str] = args.get('date_last')
    date_from: Optional[str] = args.get('date_from')
    date_to: Optional[str] = args.get('date_to')
    if saas := args.get('saas'):
        saas = SAAS_APPS_TO_SAAS_NAMES.get(saas)
    else:  # If no saas, we default to the first one from params
        if saas := argToList(params.get('saas_apps')):
            saas = SAAS_APPS_TO_SAAS_NAMES.get(saas[0])
        else:  # If no params, we default to the first one from SAAS_NAMES
            saas = SAAS_NAMES[0]
    direction: Optional[str] = args.get('direction')
    subject_contains: Optional[str] = args.get('subject_contains')
    subject_match: Optional[str] = args.get('subject_match')
    sender_contains: Optional[str] = args.get('sender_contains')
    sender_match: Optional[str] = args.get('sender_match')
    domain: Optional[str] = args.get('domain')
    cp_detection: List[str] = [CP_DETECTION_VALUES[x] for x in argToList(args.get('cp_detection'))]
    ms_detection: List[str] = [MS_DETECTION_VALUES[x] for x in argToList(args.get('ms_detection'))]
    detection_op: str = args.get('detection_op', 'OR')
    server_ip: Optional[str] = args.get('server_ip')
    recipients_contains: Optional[str] = args.get('recipients_contains')
    recipients_match: Optional[str] = args.get('recipients_match')
    links: Optional[str] = args.get('links')
    message_id: Optional[str] = args.get('message_id')
    cp_quarantined_state: Optional[str]
    if _key := args.get('cp_quarantined_state'):
        cp_quarantined_state = CP_QUARANTINED_VALUES.get(_key)
    else:
        cp_quarantined_state = None
    ms_quarantined_state: Optional[str]
    if _key := args.get('ms_quarantined_state'):
        ms_quarantined_state = MS_QUARANTINED_VALUES.get(_key)
    else:
        ms_quarantined_state = None
    quarantined_state_op: str = args.get('quarantined_state_op', 'OR')
    name_contains: Optional[str] = args.get('name_contains')
    name_match: Optional[str] = args.get('name_match')
    client_ip: Optional[str] = args.get('client_ip')
    attachment_md5: Optional[str] = args.get('attachment_md5')

    end_date: Optional[str] = None

    if date_last:
        if date_from or date_to:
            return CommandResults(
                readable_output=f'Argument {date_last=} cannot be used with {date_from=} or {date_to=}'
            )
        else:
            if _start_date := dateparser.parse(date_last, date_formats=[DATE_FORMAT]):
                start_date = _start_date.isoformat()
            else:
                return CommandResults(
                    readable_output=f'Could not establish start date with {date_last=}'
                )
    elif date_from:
        start_date = date_from
        if date_to:
            end_date = date_to
    else:
        return CommandResults(
            readable_output='Argument date_last and date_from cannot be both empty'
        )

    if subject_contains and subject_match:
        return CommandResults(
            readable_output=f'Argument {subject_contains=} and {subject_match=} cannot be both set'
        )

    if sender_contains and sender_match:
        return CommandResults(
            readable_output=f'Argument {sender_contains=} and {sender_match=} cannot be both set'
        )

    if recipients_contains and recipients_match:
        return CommandResults(
            readable_output=f'Argument {recipients_contains=} and {recipients_match=} cannot be both set'
        )

    if name_contains and name_match:
        return CommandResults(
            readable_output=f'Argument {name_contains=} and {name_match=} cannot be both set'
        )

    result = client.search_emails(start_date, end_date, saas, direction, subject_contains, subject_match, sender_contains,
                                  sender_match, domain, cp_detection, ms_detection, detection_op, server_ip, recipients_contains,
                                  recipients_match, links, message_id, cp_quarantined_state, ms_quarantined_state,
                                  quarantined_state_op, name_contains, name_match, client_ip, attachment_md5)
    if entities := result.get('responseData'):
        emails = []
        for entity in entities:
            email = entity['entityPayload']
            email['entityId'] = entity['entityInfo']['entityId']
            emails.append(email)
        human_readable = tableToMarkdown('emails', emails, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.Entity',
            readable_output=human_readable,
            outputs=emails
        )
    else:
        return CommandResults(
            readable_output='Emails with the specified parameters were not found'
        )


def checkpointhec_send_action(client: Client, args: dict) -> CommandResults:
    entities: list = argToList(args['entity'])
    entity_type: str = SAAS_APPS_TO_SAAS_NAMES[args['saas']] + '_email'
    action: str = args['action']
    restore_decline_reason: Optional[str] = args.get('restore_decline_reason')

    result = client.send_action(entities, entity_type, action, restore_decline_reason)
    if resp := result.get('responseData'):
        return CommandResults(
            outputs_prefix='CheckPointHEC.Task',
            outputs={'task': resp[0]['taskId']}
        )
    else:
        raise DemistoException('Task not queued successfully')


def checkpointhec_get_action_result(client: Client, args: dict) -> CommandResults:
    task: str = args['task']

    result = client.get_task(task)
    if resp := result.get('responseData'):
        return CommandResults(
            outputs_prefix='CheckPointHEC.ActionResult',
            outputs=resp
        )
    else:
        return CommandResults(
            readable_output=f'Cannot get results about task with id {task}'
        )


def checkpointhec_send_notification(client: Client, args: dict) -> CommandResults:
    entity: str = args['entity']
    emails: List[str] = argToList(args['emails'])

    result = client.send_notification(entity, emails)
    if result.get('ok'):
        return CommandResults(
            outputs_prefix='CheckPointHEC.Notification',
            outputs=result
        )
    else:
        raise DemistoException('Error sending notification email')


def checkpointhec_report_mis_classification(client: Client, args: dict) -> CommandResults:
    entities: List[str] = argToList(args['entities'])
    classification: str = MIS_CLASSIFICATION_OPTIONS[args['classification']]
    confident: str = MIS_CLASSIFICATION_CONFIDENCE[args['confident']]

    result = client.report_mis_classification(entities, classification, confident)
    if result.get('responseEnvelope', {}).get('responseCode') == 200:
        return CommandResults(
            readable_output='Mis-classification reported successfully'
        )
    else:
        raise DemistoException('Error reporting mis-classification')


def checkpointhec_get_ap_exceptions(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_id: Optional[str] = args.get('exc_id')

    result = client.get_ap_exceptions(exc_type, exc_id)
    if exceptions := result.get('responseData'):
        human_readable = tableToMarkdown('exceptions', exceptions, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.AntiPhishingException',
            outputs_key_field='id',
            readable_output=human_readable,
            outputs=exceptions,
        )
    else:
        return CommandResults(
            readable_output='No Anti-Phishing exceptions found'
        )


def checkpointhec_create_ap_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    entity_id: Optional[str] = args.get('entity_id')
    attachment_md5: Optional[str] = args.get('attachment_md5')
    from_email: Optional[str] = args.get('from_email')
    nickname: Optional[str] = args.get('nickname')
    recipient: Optional[str] = args.get('recipient')
    sender_client_ip: Optional[str] = args.get('sender_client_ip')
    from_domain_ends_with: Optional[str] = args.get('from_domain_ends_with')
    sender_ip: Optional[str] = args.get('sender_ip')
    email_link: Optional[List[str]] = argToList(args.get('email_link'))
    subject: Optional[str] = args.get('subject')
    comment: Optional[str] = args.get('comment')
    action_needed: Optional[str] = args.get('action_needed')
    ignoring_spf_check: Optional[bool] = arg_to_bool(args.get('ignoring_spf_check'))
    subject_matching: Optional[str] = args.get('subject_matching')
    email_link_matching: Optional[str] = args.get('email_link_matching')
    from_name_matching: Optional[str] = args.get('from_name_matching')
    from_domain_matching: Optional[str] = args.get('from_domain_matching')
    from_email_matching: Optional[str] = args.get('from_email_matching')
    recipient_matching: Optional[str] = args.get('recipient_matching')

    result = client.create_ap_exception(exc_type, entity_id, attachment_md5, from_email, nickname, recipient, sender_client_ip,
                                        from_domain_ends_with, sender_ip, email_link, subject, comment, action_needed,
                                        ignoring_spf_check, subject_matching, email_link_matching, from_name_matching,
                                        from_domain_matching, from_email_matching, recipient_matching)
    if result.get('responseEnvelope', {}).get('responseCode') == 200:
        return CommandResults(
            readable_output='Anti-Phishing exception created successfully'
        )
    else:
        raise DemistoException('Error creating Anti-Phishing exception')


def checkpointhec_update_ap_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_id: str = args['exc_id']
    entity_id: Optional[str] = args.get('entity_id')
    attachment_md5: Optional[str] = args.get('attachment_md5')
    from_email: Optional[str] = args.get('from_email')
    nickname: Optional[str] = args.get('nickname')
    recipient: Optional[str] = args.get('recipient')
    sender_client_ip: Optional[str] = args.get('sender_client_ip')
    from_domain_ends_with: Optional[str] = args.get('from_domain_ends_with')
    sender_ip: Optional[str] = args.get('sender_ip')
    email_link: Optional[List[str]] = argToList(args.get('email_link'))
    subject: Optional[str] = args.get('subject')
    comment: Optional[str] = args.get('comment')
    action_needed: Optional[str] = args.get('action_needed')
    ignoring_spf_check: Optional[bool] = arg_to_bool(args.get('ignoring_spf_check'))
    subject_matching: Optional[str] = args.get('subject_matching')
    email_link_matching: Optional[str] = args.get('email_link_matching')
    from_name_matching: Optional[str] = args.get('from_name_matching')
    from_domain_matching: Optional[str] = args.get('from_domain_matching')
    from_email_matching: Optional[str] = args.get('from_email_matching')
    recipient_matching: Optional[str] = args.get('recipient_matching')

    result = client.update_ap_exception(exc_type, exc_id, entity_id, attachment_md5, from_email, nickname, recipient,
                                        sender_client_ip, from_domain_ends_with, sender_ip, email_link, subject, comment,
                                        action_needed, ignoring_spf_check, subject_matching, email_link_matching,
                                        from_name_matching, from_domain_matching, from_email_matching, recipient_matching)
    if result.get('responseEnvelope', {}).get('responseCode') == 200:
        return CommandResults(
            readable_output='Anti-Phishing exception updated successfully'
        )
    else:
        raise DemistoException('Error updating Anti-Phishing exception')


def checkpointhec_delete_ap_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_id: str = args['exc_id']

    result = client.delete_ap_exception(exc_type, exc_id)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='Anti-Phishing exception deleted successfully'
        )
    else:
        raise DemistoException('Error deleting Anti-Phishing exception')


def checkpointhec_get_cp2_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']

    result = client.get_sectool_exception(ANTI_MALWARE_SAAS_NAME, exc_type, exc_str)
    if exception := result.get('responseData'):
        human_readable = tableToMarkdown('exception', exception, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.AntiMalwareException',
            outputs_key_field='exception_str',
            readable_output=human_readable,
            outputs=exception,
        )
    else:
        return CommandResults(
            readable_output='No Anti-Malware exception found'
        )


def checkpointhec_create_cp2_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')
    comment: Optional[str] = args.get('comment')
    exc_payload_condition: Optional[str] = args.get('exc_payload_condition')
    file_name: Optional[str] = args.get('file_name')
    created_by_email: Optional[str] = args.get('created_by_email')
    is_exclusive: Optional[bool] = arg_to_bool(args.get('is_exclusive'))

    result = client.create_sectool_exception(ANTI_MALWARE_SAAS_NAME, exc_type, exc_str, entity_type, entity_id, comment,
                                             exc_payload_condition, file_name, created_by_email, is_exclusive)
    if result.get('responseEnvelope', {}).get('responseCode') == 201:
        return CommandResults(
            readable_output='Anti-Malware exception created successfully'
        )
    else:
        raise DemistoException('Error creating Anti-Malware exception')


def checkpointhec_update_cp2_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    comment: Optional[str] = args.get('comment')
    exc_payload_condition: Optional[str] = args.get('exc_payload_condition')

    result = client.update_sectool_exception(ANTI_MALWARE_SAAS_NAME, exc_type, exc_str, comment, exc_payload_condition)
    if result.get('responseEnvelope', {}).get('responseCode') == 200:
        return CommandResults(
            readable_output='Anti-Malware exception updated successfully'
        )
    else:
        raise DemistoException('Error updating Anti-Malware exception')


def checkpointhec_delete_cp2_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')

    result = client.delete_sectool_exception(ANTI_MALWARE_SAAS_NAME, exc_type, exc_str, entity_type, entity_id)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='Anti-Malware exception deleted successfully'
        )
    else:
        raise DemistoException('Error deleting Anti-Malware exception')


def checkpointhec_get_cp2_exceptions(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    filter_str: Optional[str] = args.get('filter_str')
    filter_index: Optional[str] = args.get('filter_index')
    sort_dir: Optional[str] = args.get('sort_dir')
    last_evaluated_key: Optional[str] = args.get('last_evaluated_key')
    insert_time_gte: Optional[bool] = arg_to_bool(args.get('insert_time_gte'))
    limit: Optional[int] = arg_to_number(args.get('limit'))

    result = client.get_sectool_exceptions(ANTI_MALWARE_SAAS_NAME, exc_type, filter_str, filter_index, sort_dir,
                                           last_evaluated_key, insert_time_gte, limit)
    if exceptions := result.get('responseData'):
        human_readable = tableToMarkdown('exceptions', exceptions, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.AntiMalwareException',
            outputs_key_field='exception_str',
            readable_output=human_readable,
            outputs=exceptions,
        )
    else:
        return CommandResults(
            readable_output='No Anti-Malware exceptions found'
        )


def checkpointhec_delete_cp2_exceptions(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str_list: List[str] = argToList(args['exc_str_list'])
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')

    result = client.delete_sectool_exceptions(ANTI_MALWARE_SAAS_NAME, exc_type, exc_str_list, entity_type, entity_id)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='Anti-Malware exceptions deleted successfully'
        )
    else:
        raise DemistoException('Error deleting Anti-Malware exceptions')


def checkpointhec_get_anomaly_exceptions(client: Client) -> CommandResults:
    result = client.get_anomaly_exceptions()
    if exceptions := result.get('responseData'):
        human_readable = tableToMarkdown('exceptions', exceptions, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.AnomalyException',
            outputs_key_field='id',
            readable_output=human_readable,
            outputs=exceptions,
        )
    else:
        return CommandResults(
            readable_output='No Anomaly exceptions found'
        )


def checkpointhec_create_anomaly_exception(client: Client, args: dict) -> CommandResults:
    request_json: dict = args['request_json']
    added_by: Optional[str] = args.get('added_by')

    result = client.create_anomaly_exceptions(request_json, added_by)
    if result.get('responseEnvelope', {}).get('responseCode') == 201:
        return CommandResults(
            readable_output='Anomaly exception created successfully'
        )
    else:
        raise DemistoException('Error creating Anomaly exception')


def checkpointhec_delete_anomaly_exceptions(client: Client, args: dict) -> CommandResults:
    rule_ids: List[str] = argToList(args['rule_ids'])

    result = client.delete_anomaly_exceptions(rule_ids)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='Anomaly exceptions deleted successfully'
        )
    else:
        raise DemistoException('Error deleting Anomaly exceptions')


def checkpointhec_get_ctp_lists(client: Client) -> CommandResults:
    result = client.get_ctp_lists()
    if lists := result.get('responseData'):
        human_readable = tableToMarkdown('lists', lists, removeNull=False)
        return CommandResults(
            outputs_prefix='CheckPointHEC.CTPList',
            outputs_key_field='listid',
            readable_output=human_readable,
            outputs=lists,
        )
    else:
        return CommandResults(
            readable_output='No CTP lists found'
        )


def checkpointhec_get_ctp_list(client: Client, args: dict) -> CommandResults:
    list_id: str = args['list_id']

    result = client.get_ctp_list(list_id)
    if lists := result.get('responseData'):
        human_readable = tableToMarkdown('lists', lists, removeNull=False)
        return CommandResults(
            outputs_prefix='CheckPointHEC.CTPList',
            outputs_key_field='listid',
            readable_output=human_readable,
            outputs=lists,
        )
    else:
        return CommandResults(
            readable_output='No CTP list found'
        )


def checkpointhec_get_ctp_list_items(client: Client) -> CommandResults:
    result = client.get_ctp_list_items()
    if items := result.get('responseData'):
        human_readable = tableToMarkdown('items', items, removeNull=False)
        return CommandResults(
            outputs_prefix='CheckPointHEC.CTPListItem',
            outputs_key_field='listitemid',
            readable_output=human_readable,
            outputs=items,
        )
    else:
        return CommandResults(
            readable_output='No CTP list items found'
        )


def checkpointhec_get_ctp_list_item(client: Client, args: dict) -> CommandResults:
    item_id: str = args['item_id']

    result = client.get_ctp_list_item(item_id)
    if item := result.get('responseData'):
        human_readable = tableToMarkdown('item', item, removeNull=False)
        return CommandResults(
            outputs_prefix='CheckPointHEC.CTPListItem',
            outputs_key_field='listitemid',
            readable_output=human_readable,
            outputs=item,
        )
    else:
        return CommandResults(
            readable_output='No CTP list items found'
        )


def checkpointhec_create_ctp_list_item(client: Client, args: dict) -> CommandResults:
    list_id: str = args['list_id']
    list_item_name: str = args['list_item_name']
    created_by: str = args['created_by']

    result = client.create_ctp_list_item(list_id, list_item_name, created_by)
    if result.get('responseEnvelope', {}).get('responseCode') == 201:
        return CommandResults(
            readable_output='CTP list item created successfully'
        )
    else:
        raise DemistoException('Error creating CTP list item')


def checkpointhec_update_ctp_list_item(client: Client, args: dict) -> CommandResults:
    item_id: str = args['item_id']
    list_id: str = args['list_id']
    list_item_name: str = args['list_item_name']
    created_by: str = args['created_by']

    result = client.update_ctp_list_item(item_id, list_id, list_item_name, created_by)
    if result.get('responseEnvelope', {}).get('responseCode') == 200:
        return CommandResults(
            readable_output='CTP list item updated successfully'
        )
    else:
        raise DemistoException('Error updating CTP list item')


def checkpointhec_delete_ctp_list_item(client: Client, args: dict) -> CommandResults:
    item_id: str = args['item_id']

    result = client.delete_ctp_list_item(item_id)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='CTP list item deleted successfully'
        )
    else:
        raise DemistoException('Error deleting CTP list item')


def checkpointhec_delete_ctp_list_items(client: Client, args: dict) -> CommandResults:
    list_item_ids: List[str] = argToList(args['list_item_ids'])

    result = client.delete_ctp_list_items(list_item_ids)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='CTP list items deleted successfully'
        )
    else:
        raise DemistoException('Error deleting CTP list items')


def checkpointhec_delete_ctp_lists(client: Client) -> CommandResults:
    result = client.delete_ctp_lists()
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='CTP lists deleted successfully'
        )
    else:
        raise DemistoException('Error deleting CTP lists')


def checkpointhec_get_avurl_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']

    result = client.get_sectool_exception(AVANAN_URL_SAAS_NAME, exc_type, exc_str)
    if exception := result.get('responseData'):
        human_readable = tableToMarkdown('exception', exception, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.AvananURLException',
            outputs_key_field='exception_str',
            readable_output=human_readable,
            outputs=exception,
        )
    else:
        return CommandResults(
            readable_output='No Avanan URL exception found'
        )


def checkpointhec_create_avurl_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')
    comment: Optional[str] = args.get('comment')
    exc_payload_condition: Optional[str] = args.get('exc_payload_condition')
    file_name: Optional[str] = args.get('file_name')
    created_by_email: Optional[str] = args.get('created_by_email')
    is_exclusive: Optional[bool] = arg_to_bool(args.get('is_exclusive'))

    result = client.create_sectool_exception(AVANAN_URL_SAAS_NAME, exc_type, exc_str, entity_type, entity_id, comment,
                                             exc_payload_condition, file_name, created_by_email, is_exclusive)
    if result.get('responseEnvelope', {}).get('responseCode') == 201:
        return CommandResults(
            readable_output='Avanan URL exception created successfully'
        )
    else:
        raise DemistoException('Error creating Avanan URL exception')


def checkpointhec_update_avurl_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    comment: Optional[str] = args.get('comment')
    exc_payload_condition: Optional[str] = args.get('exc_payload_condition')

    result = client.update_sectool_exception(AVANAN_URL_SAAS_NAME, exc_type, exc_str, comment, exc_payload_condition)
    if result.get('responseEnvelope', {}).get('responseCode') == 200:
        return CommandResults(
            readable_output='Avanan URL exception updated successfully'
        )
    else:
        raise DemistoException('Error updating Avanan URL exception')


def checkpointhec_delete_avurl_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')

    result = client.delete_sectool_exception(AVANAN_URL_SAAS_NAME, exc_type, exc_str, entity_type, entity_id)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='Avanan URL exception deleted successfully'
        )
    else:
        raise DemistoException('Error deleting Avanan URL exception')


def checkpointhec_get_avurl_exceptions(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    filter_str: Optional[str] = args.get('filter_str')
    filter_index: Optional[str] = args.get('filter_index')
    sort_dir: Optional[str] = args.get('sort_dir')
    last_evaluated_key: Optional[str] = args.get('last_evaluated_key')
    insert_time_gte: Optional[bool] = arg_to_bool(args.get('insert_time_gte'))
    limit: Optional[int] = arg_to_number(args.get('limit'))

    result = client.get_sectool_exceptions(AVANAN_URL_SAAS_NAME, exc_type, filter_str, filter_index, sort_dir,
                                           last_evaluated_key, insert_time_gte, limit)
    if exceptions := result.get('responseData'):
        human_readable = tableToMarkdown('exceptions', exceptions, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.AvananURLException',
            outputs_key_field='exception_str',
            readable_output=human_readable,
            outputs=exceptions,
        )
    else:
        return CommandResults(
            readable_output='No Avanan URL exceptions found'
        )


def checkpointhec_delete_avurl_exceptions(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str_list: List[str] = argToList(args['exc_str_list'])
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')

    result = client.delete_sectool_exceptions(AVANAN_URL_SAAS_NAME, exc_type, exc_str_list, entity_type, entity_id)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='Avanan URL exceptions deleted successfully'
        )
    else:
        raise DemistoException('Error deleting Avanan URL exceptions')


def checkpointhec_get_avdlp_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']

    result = client.get_sectool_exception(AVANAN_DLP_SAAS_NAME, exc_type, exc_str)
    if exception := result.get('responseData'):
        human_readable = tableToMarkdown('exception', exception, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.AvananDLPException',
            outputs_key_field='exception_str',
            readable_output=human_readable,
            outputs=exception,
        )
    else:
        return CommandResults(
            readable_output='No Avanan DLP exception found'
        )


def checkpointhec_create_avdlp_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')
    comment: Optional[str] = args.get('comment')
    exc_payload_condition: Optional[str] = args.get('exc_payload_condition')
    file_name: Optional[str] = args.get('file_name')
    created_by_email: Optional[str] = args.get('created_by_email')
    is_exclusive: Optional[bool] = arg_to_bool(args.get('is_exclusive'))

    result = client.create_sectool_exception(AVANAN_DLP_SAAS_NAME, exc_type, exc_str, entity_type, entity_id, comment,
                                             exc_payload_condition, file_name, created_by_email, is_exclusive)
    if result.get('responseEnvelope', {}).get('responseCode') == 201:
        return CommandResults(
            readable_output='Avanan DLP exception created successfully'
        )
    else:
        raise DemistoException('Error creating Avanan DLP exception')


def checkpointhec_update_avdlp_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    comment: Optional[str] = args.get('comment')
    exc_payload_condition: Optional[str] = args.get('exc_payload_condition')

    result = client.update_sectool_exception(AVANAN_DLP_SAAS_NAME, exc_type, exc_str, comment, exc_payload_condition)
    if result.get('responseEnvelope', {}).get('responseCode') == 200:
        return CommandResults(
            readable_output='Avanan DLP exception updated successfully'
        )
    else:
        raise DemistoException('Error updating Avanan DLP exception')


def checkpointhec_delete_avdlp_exception(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str: str = args['exc_str']
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')

    result = client.delete_sectool_exception(AVANAN_DLP_SAAS_NAME, exc_type, exc_str, entity_type, entity_id)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='Avanan DLP exception deleted successfully'
        )
    else:
        raise DemistoException('Error deleting Avanan DLP exception')


def checkpointhec_get_avdlp_exceptions(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    filter_str: Optional[str] = args.get('filter_str')
    filter_index: Optional[str] = args.get('filter_index')
    sort_dir: Optional[str] = args.get('sort_dir')
    last_evaluated_key: Optional[str] = args.get('last_evaluated_key')
    insert_time_gte: Optional[bool] = arg_to_bool(args.get('insert_time_gte'))
    limit: Optional[int] = arg_to_number(args.get('limit'))

    result = client.get_sectool_exceptions(AVANAN_DLP_SAAS_NAME, exc_type, filter_str, filter_index, sort_dir,
                                           last_evaluated_key, insert_time_gte, limit)
    if exceptions := result.get('responseData'):
        human_readable = tableToMarkdown('exceptions', exceptions, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.AvananDLPException',
            outputs_key_field='exception_str',
            readable_output=human_readable,
            outputs=exceptions,
        )
    else:
        return CommandResults(
            readable_output='No Avanan DLP exceptions found'
        )


def checkpointhec_delete_avdlp_exceptions(client: Client, args: dict) -> CommandResults:
    exc_type: str = args['exc_type']
    exc_str_list: List[str] = argToList(args['exc_str_list'])
    entity_type: Optional[str] = args.get('entity_type')
    entity_id: Optional[str] = args.get('entity_id')

    result = client.delete_sectool_exceptions(AVANAN_DLP_SAAS_NAME, exc_type, exc_str_list, entity_type, entity_id)
    if result.get('responseEnvelope', {}).get('responseCode') == 204:
        return CommandResults(
            readable_output='Avanan DLP exceptions deleted successfully'
        )
    else:
        raise DemistoException('Error deleting Avanan DLP exceptions')


def main() -> None:  # pragma: no cover
    args = demisto.args()
    params = demisto.params()

    base_url = params.get('url')
    client_id = params.get('client_id', {}).get('password')
    client_secret = params.get('client_secret', {}).get('password')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    client = Client(
        base_url,
        client_id,
        client_secret,
        verify,
        proxy
    )

    try:
        command = demisto.command()
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            if arg_to_bool(params.get('collect_restore_requests')):
                fetch_restore_requests(client, params)
            else:
                fetch_incidents(client, params)
        elif command == 'checkpointhec-get-entity':
            return_results(checkpointhec_get_entity(client, args))
        elif command == 'checkpointhec-get-events':
            return_results(checkpointhec_get_events(client, args))
        elif command == 'checkpointhec-get-scan-info':
            return_results(checkpointhec_get_scan_info(client, args))
        elif command == 'checkpointhec-search-emails':
            return_results(checkpointhec_search_emails(client, args, params))
        elif command == 'checkpointhec-send-action':
            return_results(checkpointhec_send_action(client, args))
        elif command == 'checkpointhec-get-action-result':
            return_results(checkpointhec_get_action_result(client, args))
        elif command == 'checkpointhec-send-notification':
            return_results(checkpointhec_send_notification(client, args))
        elif command == 'checkpointhec-report-mis-classification':
            return_results(checkpointhec_report_mis_classification(client, args))
        elif command == 'checkpointhec-get-ap-exceptions':
            return_results(checkpointhec_get_ap_exceptions(client, args))
        elif command == 'checkpointhec-create-ap-exception':
            return_results(checkpointhec_create_ap_exception(client, args))
        elif command == 'checkpointhec-update-ap-exception':
            return_results(checkpointhec_update_ap_exception(client, args))
        elif command == 'checkpointhec-delete-ap-exception':
            return_results(checkpointhec_delete_ap_exception(client, args))
        elif command == 'checkpointhec-get-cp2-exception':
            return_results(checkpointhec_get_cp2_exception(client, args))
        elif command == 'checkpointhec-create-cp2-exception':
            return_results(checkpointhec_create_cp2_exception(client, args))
        elif command == 'checkpointhec-update-cp2-exception':
            return_results(checkpointhec_update_cp2_exception(client, args))
        elif command == 'checkpointhec-delete-cp2-exception':
            return_results(checkpointhec_delete_cp2_exception(client, args))
        elif command == 'checkpointhec-get-cp2-exceptions':
            return_results(checkpointhec_get_cp2_exceptions(client, args))
        elif command == 'checkpointhec-delete-cp2-exceptions':
            return_results(checkpointhec_delete_cp2_exceptions(client, args))
        elif command == 'checkpointhec-get-anomaly-exceptions':
            return_results(checkpointhec_get_anomaly_exceptions(client))
        elif command == 'checkpointhec-create-anomaly-exception':
            return_results(checkpointhec_create_anomaly_exception(client, args))
        elif command == 'checkpointhec-delete-anomaly-exceptions':
            return_results(checkpointhec_delete_anomaly_exceptions(client, args))
        elif command == 'checkpointhec-get-ctp-lists':
            return_results(checkpointhec_get_ctp_lists(client))
        elif command == 'checkpointhec-get-ctp-list':
            return_results(checkpointhec_get_ctp_list(client, args))
        elif command == 'checkpointhec-get-ctp-list-items':
            return_results(checkpointhec_get_ctp_list_items(client))
        elif command == 'checkpointhec-get-ctp-list-item':
            return_results(checkpointhec_get_ctp_list_item(client, args))
        elif command == 'checkpointhec-create-ctp-list-item':
            return_results(checkpointhec_create_ctp_list_item(client, args))
        elif command == 'checkpointhec-update-ctp-list-item':
            return_results(checkpointhec_update_ctp_list_item(client, args))
        elif command == 'checkpointhec-delete-ctp-list-item':
            return_results(checkpointhec_delete_ctp_list_item(client, args))
        elif command == 'checkpointhec-delete-ctp-list-items':
            return_results(checkpointhec_delete_ctp_list_items(client, args))
        elif command == 'checkpointhec-delete-ctp-lists':
            return_results(checkpointhec_delete_ctp_lists(client))
        elif command == 'checkpointhec-get-avurl-exception':
            return_results(checkpointhec_get_avurl_exception(client, args))
        elif command == 'checkpointhec-create-avurl-exception':
            return_results(checkpointhec_create_avurl_exception(client, args))
        elif command == 'checkpointhec-update-avurl-exception':
            return_results(checkpointhec_update_avurl_exception(client, args))
        elif command == 'checkpointhec-delete-avurl-exception':
            return_results(checkpointhec_delete_avurl_exception(client, args))
        elif command == 'checkpointhec-get-avurl-exceptions':
            return_results(checkpointhec_get_avurl_exceptions(client, args))
        elif command == 'checkpointhec-delete-avurl-exceptions':
            return_results(checkpointhec_delete_avurl_exceptions(client, args))
        elif command == 'checkpointhec-get-avdlp-exception':
            return_results(checkpointhec_get_avdlp_exception(client, args))
        elif command == 'checkpointhec-create-avdlp-exception':
            return_results(checkpointhec_create_avdlp_exception(client, args))
        elif command == 'checkpointhec-update-avdlp-exception':
            return_results(checkpointhec_update_avdlp_exception(client, args))
        elif command == 'checkpointhec-delete-avdlp-exception':
            return_results(checkpointhec_delete_avdlp_exception(client, args))
        elif command == 'checkpointhec-get-avdlp-exceptions':
            return_results(checkpointhec_get_avdlp_exceptions(client, args))
        elif command == 'checkpointhec-delete-avdlp-exceptions':
            return_results(checkpointhec_delete_avdlp_exceptions(client, args))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
