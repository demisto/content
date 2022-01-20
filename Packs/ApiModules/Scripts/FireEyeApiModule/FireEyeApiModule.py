from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
FE_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
OK_CODES = (200, 206)


class FireEyeClient(BaseClient):
    def __init__(self, base_url: str,
                 username: str, password: str,
                 verify: bool, proxy: bool,
                 ok_codes: tuple = OK_CODES):

        super().__init__(base_url=base_url, auth=(username, password), verify=verify, proxy=proxy, ok_codes=ok_codes)
        self._headers = {
            'X-FeApi-Token': self._get_token(),
            'Accept': 'application/json',
        }

    @logger
    def http_request(self, method: str, url_suffix: str = '', json_data: dict = None, params: dict = None,
                     timeout: int = 10, resp_type: str = 'json', retries: int = 1):
        try:
            address = urljoin(self._base_url, url_suffix)
            res = self._session.request(
                method,
                address,
                headers=self._headers,
                verify=self._verify,
                params=params,
                json=json_data,
                timeout=timeout
            )
            # Handle error responses gracefully
            if not self._is_status_code_valid(res):
                err_msg = f'Error in API call {res.status_code} - {res.reason}'
                try:
                    # Try to parse json error response
                    error_entry = res.json()
                    err_msg += f'\n{json.dumps(error_entry)}'
                    if 'Server Error. code:AUTH004' in err_msg and retries:
                        # implement 1 retry to re create a token
                        self._headers['X-FeApi-Token'] = self._generate_token()
                        self.http_request(method, url_suffix, json_data, params, timeout, resp_type, retries - 1)
                    else:
                        raise DemistoException(err_msg, res=res)
                except ValueError:
                    err_msg += f'\n{res.text}'
                    raise DemistoException(err_msg, res=res)

            resp_type = resp_type.lower()
            try:
                if resp_type == 'json':
                    return res.json()
                if resp_type == 'text':
                    return res.text
                if resp_type == 'content':
                    return res.content
                return res
            except ValueError:
                raise DemistoException('Failed to parse json object from response.')
        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.SSLError as exception:
            # in case the "Trust any certificate" is already checked
            if not self._verify:
                raise
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.ProxyError as exception:
            err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                      ' selected, try clearing the checkbox.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.ConnectionError as exception:
            # Get originating Exception in Exception chain
            error_class = str(exception.__class__)
            err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
            err_msg = f'Verify that the server URL parameter' \
                      f' is correct and that you have access to the server from your host.' \
                      f'\nError Type: {err_type}\nError Number: [{exception.errno}]\nMessage: {exception.strerror}\n'
            raise DemistoException(err_msg, exception)

    @logger
    def _get_token(self) -> str:
        """
        Obtains token from integration context if available and still valid
        (15 minutes according to the API, we gave 10 minutes).
        After expiration, new token are generated and stored in the integration context.
        Returns:
            str: token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        token = integration_context.get('token', '')
        valid_until = integration_context.get('valid_until')

        now = datetime.now()
        now_timestamp = datetime.timestamp(now)
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until:
            if now_timestamp < valid_until:
                return token

        # else generate a token and update the integration context accordingly
        token = self._generate_token()

        return token

    @logger
    def _generate_token(self) -> str:
        resp = self._http_request(method='POST', url_suffix='auth/login', resp_type='response')
        if resp.status_code != 200:
            raise DemistoException(
                f'Token request failed with status code {resp.status_code}. message: {str(resp)}')
        if 'X-FeApi-Token' not in resp.headers:
            raise DemistoException(
                f'Token request failed. API token is missing. message: {str(resp)}')
        token = resp.headers['X-FeApi-Token']

        integration_context = get_integration_context()
        integration_context.update({'token': token})
        time_buffer = 10  # minutes by which to lengthen the validity period
        integration_context.update({'valid_until': datetime.timestamp(datetime.now() + timedelta(seconds=time_buffer))})
        set_integration_context(integration_context)

        return token

    @logger
    def get_alerts_request(self, request_params: Dict[str, Any]) -> Dict[str, str]:
        return self.http_request(method='GET', url_suffix='alerts', params=request_params, resp_type='json')

    @logger
    def get_alert_details_request(self, alert_id: str, timeout: int) -> Dict[str, str]:
        return self.http_request(method='GET', url_suffix=f'alerts/alert/{alert_id}', resp_type='json',
                                 timeout=timeout)

    @logger
    def alert_acknowledge_request(self, uuid: str) -> Dict[str, str]:
        # json_data here is redundant as we are not sending any meaningful data,
        # but without it the API call to FireEye fails and we are getting an error. hence sending it with a dummy value.
        # the error we get when not sending json_data is: "Bad Request" with Invalid input. code:ALRTCONF001
        return self.http_request(method='POST', url_suffix=f'alerts/alert/{uuid}',
                                 params={'schema_compatibility': True}, json_data={"annotation": "<test>"},
                                 resp_type='resp')

    @logger
    def get_artifacts_by_uuid_request(self, uuid: str, timeout: int) -> Dict[str, str]:
        self._headers.pop('Accept')  # returns a file, hence this header is disruptive
        return self.http_request(method='GET', url_suffix=f'artifacts/{uuid}', resp_type='content',
                                 timeout=timeout)

    @logger
    def get_artifacts_metadata_by_uuid_request(self, uuid: str) -> Dict[str, str]:
        return self.http_request(method='GET', url_suffix=f'artifacts/{uuid}/meta', resp_type='json')

    @logger
    def get_events_request(self, duration: str, end_time: str, mvx_correlated_only: bool) -> Dict[str, str]:
        return self.http_request(method='GET',
                                 url_suffix='events',
                                 params={
                                     'event_type': 'Ips Event',
                                     'duration': duration,
                                     'end_time': end_time,
                                     'mvx_correlated_only': mvx_correlated_only
                                 },
                                 resp_type='json')

    @logger
    def get_quarantined_emails_request(self, start_time: str, end_time: str, from_: str, subject: str,
                                       appliance_id: str, limit: int) -> Dict[str, str]:
        params = {
            'start_time': start_time,
            'end_time': end_time,
            'limit': limit
        }
        if from_:
            params['from'] = from_
        if subject:
            params['subject'] = subject
        if appliance_id:
            params['appliance_id'] = appliance_id

        return self.http_request(method='GET', url_suffix='emailmgmt/quarantine', params=params, resp_type='json')

    @logger
    def release_quarantined_emails_request(self, queue_ids: list, sensor_name: str):
        return self.http_request(method='POST',
                                 url_suffix='emailmgmt/quarantine/release',
                                 params={'sensorName': sensor_name},
                                 json_data={"queue_ids": queue_ids},
                                 resp_type='resp')

    @logger
    def delete_quarantined_emails_request(self, queue_ids: list, sensor_name: str = ''):
        return self.http_request(method='POST',
                                 url_suffix='emailmgmt/quarantine/delete',
                                 params={'sensorName': sensor_name},
                                 json_data={"queue_ids": queue_ids},
                                 resp_type='resp')

    @logger
    def download_quarantined_emails_request(self, queue_id: str, timeout: str, sensor_name: str = ''):
        self._headers.pop('Accept')  # returns a file, hence this header is disruptive
        return self.http_request(method='GET',
                                 url_suffix=f'emailmgmt/quarantine/{queue_id}',
                                 params={'sensorName': sensor_name},
                                 resp_type='content',
                                 timeout=timeout)

    @logger
    def get_reports_request(self, report_type: str, start_time: str, end_time: str, limit: str, interface: str,
                            alert_id: str, infection_type: str, infection_id: str, timeout: int):
        params = {
            'report_type': report_type,
            'start_time': start_time,
            'end_time': end_time
        }
        if limit:
            params['limit'] = limit
        if interface:
            params['interface'] = interface
        if alert_id:
            params['id'] = alert_id
        if infection_type:
            params['infection_type'] = infection_type
        if infection_id:
            params['infection_id'] = infection_id

        return self.http_request(method='GET',
                                 url_suffix='reports/report',
                                 params=params,
                                 resp_type='content',
                                 timeout=timeout)

    @logger
    def list_allowedlist_request(self, type_: str) -> Dict[str, str]:
        return self.http_request(method='GET', url_suffix=f'devicemgmt/emlconfig/policy/allowed_lists/{type_}',
                                 resp_type='json')

    @logger
    def create_allowedlist_request(self, type_: str, entry_value: str, matches: int) -> Dict[str, str]:
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/allowed_lists/{type_}',
                                 params={'operation': 'create'},
                                 json_data={"name": entry_value, "matches": matches},
                                 resp_type='resp')

    @logger
    def update_allowedlist_request(self, type_: str, entry_value: str, matches: int) -> Dict[str, str]:
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/allowed_lists/{type_}/{entry_value}',
                                 json_data={"matches": matches},
                                 resp_type='resp')

    @logger
    def delete_allowedlist_request(self, type_: str, entry_value: str) -> Dict[str, str]:
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/allowed_lists/{type_}/{entry_value}',
                                 params={'operation': 'delete'},
                                 resp_type='resp')

    @logger
    def list_blockedlist_request(self, type_: str) -> Dict[str, str]:
        return self.http_request(method='GET', url_suffix=f'devicemgmt/emlconfig/policy/blocked_lists/{type_}',
                                 resp_type='json')

    @logger
    def create_blockedlist_request(self, type_: str, entry_value: str, matches: int) -> Dict[str, str]:
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/blocked_lists/{type_}',
                                 params={'operation': 'create'},
                                 json_data={'name': entry_value, 'matches': matches},
                                 resp_type='resp')

    @logger
    def update_blockedlist_request(self, type_: str, entry_value: str, matches: int) -> Dict[str, str]:
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/blocked_lists/{type_}/{entry_value}',
                                 json_data={"matches": matches},
                                 resp_type='resp')

    @logger
    def delete_blockedlist_request(self, type_: str, entry_value: str) -> Dict[str, str]:
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/blocked_lists/{type_}/{entry_value}',
                                 params={'operation': 'delete'},
                                 resp_type='resp')


def to_fe_datetime_converter(time_given: str = 'now') -> str:
    """Generates a string in the FireEye format, e.g: 2015-01-24T16:30:00.000-07:00

    Examples:
        >>> to_fe_datetime_converter('2021-05-14T01:08:04.000-02:00')
        2021-05-14T01:08:04.000-02:00
        >>> to_fe_datetime_converter('now')
        2021-05-23T06:45:16.688+00:00

    Args:
        time_given: the time given, if none given, the default is now.

    Returns:
        The time given in FireEye format.
    """
    date_obj = dateparser.parse(time_given)
    fe_time = date_obj.strftime(FE_DATE_FORMAT)
    fe_time += f'.{date_obj.strftime("%f")[:3]}'
    if not date_obj.tzinfo:
        given_timezone = '+00:00'
    else:
        given_timezone = f'{date_obj.strftime("%z")[:3]}:{date_obj.strftime("%z")[3:]}'  # converting the timezone
    fe_time += given_timezone
    return fe_time


def alert_severity_to_dbot_score(severity_str: str):
    severity = severity_str.lower()
    if severity == 'minr':
        return 1
    if severity == 'majr':
        return 2
    if severity == 'crit':
        return 3
    demisto.info(f'FireEye Incident severity: {severity} is not known. Setting as unknown(DBotScore of 0).')
    return 0
