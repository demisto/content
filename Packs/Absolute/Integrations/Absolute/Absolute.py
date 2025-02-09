import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
import hashlib

from CommonServerUserPython import *  # noqa
import urllib.parse
import requests
import urllib3
from typing import Any
import hmac

from datetime import timedelta
import jwt

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

ABSOLUTE_URL_TO_API_URL = {
    'https://cc.absolute.com': 'https://api.absolute.com',
    'https://cc.us.absolute.com': 'https://api.us.absolute.com',
    'https://cc.eu2.absolute.com': 'https://api.eu2.absolute.com',
}
ABSOLUTE_URL_REGION = {
    'https://api.absolute.com': 'cadc',
    'https://api.us.absolute.com': 'usdc',
    'https://api.eu2.absolute.com': 'eudc',
}
ABSOLUTE_AGET_STATUS = {
    'Active': 'A',
    'Disabled': 'D',
    'Inactive': 'I',
}
INTEGRATION = "Absolute"
STRING_TO_SIGN_ALGORITHM = "ABS1-HMAC-SHA-256"
STRING_TO_SIGN_SIGNATURE_VERSION = "abs1"
DATE_FORMAT = '%Y%m%dT%H%M%SZ'
DATE_FORMAT_CREDENTIAL_SCOPE = '%Y%m%d'

DEVICE_LIST_RETURN_FIELDS = [
    "id",
    "esn",
    "lastConnectedUtc",
    "systemName",
    "systemModel",
    "fullSystemName",
    "agentStatus",
    "os.name",
    "systemManufacturer",
    "serial",
    "systemType",
    "localIp",
    "publicIp",
    "espInfo.encryptionStatus",
]

DEVICE_GET_COMMAND_RETURN_FIELDS = [
    "id",
    "esn",
    "domain",
    "lastConnectedUtc",
    "systemName",
    "systemModel",
    "systemType",
    "fullSystemName",
    "agentStatus",
    "os.name",
    "os.version",
    "os.currentBuild",
    "os.architecture",
    "os.installDate",
    "os.productKey",
    "os.serialNumber",
    "os.lastBootTime",
    "systemManufacturer",
    "serial",
    "localIp",
    "publicIp",
    "username",
    "espInfo.encryptionStatus",
    "bios.id",
    "bios.serialNumber",
    "bios.version",
    "bios.versionDate",
    "bios.smBiosVersion",
    "policyGroupUid",
    "policyGroupName",
    "isStolen",
    "deviceStatus.type",
    "deviceStatus.reported",
    "networkAdapters.networkSSID"
]

DEVICE_GET_LOCATION_COMMAND_RETURN_FIELDS = [
    "geoData.location.point.coordinates",
    "geoData.location.geoAddress.city",
    "geoData.location.geoAddress.state",
    "geoData.location.geoAddress.countryCode",
    "geoData.location.geoAddress.country",
    "geoData.location.locationTechnology",
    "geoData.location.accuracy",
    "geoData.location.lastUpdateDateTimeUtc",
]

SEIM_EVENTS_PAGE_SIZE = 1000
CLIENT_V3_JWS_VALIDATION_URL = "https://api.absolute.com/jws/validate"
VENDOR = 'Absolute'
PRODUCT = 'Secure Endpoint'
HEADERS_V3: dict = {"content-type": "text/plain"}


class Client(BaseClient):
    def __init__(self, base_url: str, token_id: str, secret_key: str, verify: bool, headers: dict, proxy: bool,
                 x_abs_date: str):
        """
        Client to use in the Absolute integration. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request.
            token_id (str): The Absolute token id
            secret_key (str): User's Absolute secret key
            verify (bool): Whether to check for SSL certificate validity.
            proxy (bool): Whether the client should use proxies.
            headers (dict): Headers to set when doing a http request.
            x_abs_date (str): The automatically generated header that indicates the time (in UTC) the request was made.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._payload = None
        self._base_url = base_url
        self._token_id = token_id
        self._secret_key = secret_key
        self._headers = headers
        self._x_abs_date = x_abs_date

    def prepare_request_for_api(self, method: str, canonical_uri: str, query_string: str, payload: str):
        """
        The Absolute v2 API requires following 5 steps in order to properly authorize the API request.
        We must follow the steps:
        1. Create a canonical request
        2. Create a signing string
        3. Create a signing key
        4. Create a signature
        5. Add the authorization header

        For more info https://www.absolute.com/media/2221/abt-api-working-with-absolute.pdf
        """
        canonical_req = self.create_canonical_request(method, canonical_uri, query_string, payload)
        signing_string = self.create_signing_string(canonical_req)
        signing_key = self.create_signing_key()
        signing_signature = self.create_signature(signing_string, signing_key)
        self._headers['Authorization'] = self.add_authorization_header(signing_signature)

    def create_canonical_request(self, method: str, canonical_uri: str, query_string: str, payload: str) -> str:
        """
        The canonical request should look like (for example):

        GET
        /v2/reporting/devices
        %24filter=substringof%28%2760001%27%2C%20esn%29%20eq%20true
        host:api.absolute.com
        content-type:application/json
        x-abs-date:20170926T172213Z
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        canonical_request = [method, canonical_uri, self.prepare_query_string_for_canonical_request(query_string),
                             self.prepare_canonical_headers(), self.prepare_canonical_hash_payload(payload)]
        return "\n".join(canonical_request).rstrip()

    def prepare_query_string_for_canonical_request(self, query_string: str) -> str:
        """
        Query is given as a string represents the filter query. For example,
        query_string = "$top=10 $skip=20"
        1. Splitting into a list (by space as a separator).
        2. Sorting arguments in ascending order; for example, 'A' is before 'a'.
        3. URI encode the parameter name and value using URI generic syntax.
        4. Reassembling the list into a string.
        """
        if not query_string:
            return ""
        return urllib.parse.quote(query_string, safe='=&')

    def prepare_canonical_headers(self) -> str:
        """
        Create the canonical headers and signed headers. Header names must be trimmed and lowercase,
        and sorted in code point order from low to high. Note that there is a trailing \n.
        """
        canonical_headers = ""
        for header, value in self._headers.items():
            canonical_headers += f'{header.lower()}:{value.strip()}\n'
        return canonical_headers.rstrip()

    def prepare_canonical_hash_payload(self, payload: str) -> str:
        """
        According to the API we should do:
        Hash the entire body using SHA-256 algorithm, HexEncode.
        Create payload hash (hash of the request body content).
        For GET requests, the payload is an empty string ("").
        """
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def create_signing_string(self, canonical_req: str) -> str:
        """
        The signing string should look like (for example):

        ABS1-HMAC-SHA-256
        20170926T172032Z
        20170926/cadc/abs1
        63f83d2c7139b6119d4954e6766ce90871e41334c3f29b6d64201639d273fa19

        Algorithm: The string used to identify the algorithm. For example, ABS1-HMAC-SHA-256

        RequestedDateTime: The date and time (in UTC) from XAbs-Date. Format: <YYYY><MM><DD>T<HH><MM><SS>Z

        CredentialScope: The CredentialScope is defined in three parts:
                        1. The date (in UTC) of the request. Format: YYYYMMDD
                        2. Region or data center (must be in lowercase) Possible values: cadc, usdc, eudc
                        3. Version or type of signature. Always abs1

        HashedCanonicalRequest: The hashed, hex-converted, and lowercase value of the canonical request.
        """
        credential_scope = self.create_credential_scope()
        canonical_req_hashed = hashlib.sha256(canonical_req.encode('utf-8')).hexdigest()
        return "\n".join([STRING_TO_SIGN_ALGORITHM, self._x_abs_date, credential_scope, canonical_req_hashed])

    def create_credential_scope(self) -> str:
        """
        CredentialScope: The CredentialScope is defined in three parts:
                1. The date (in UTC) of the request. Format: YYYYMMDD
                2. Region or data center (must be in lowercase) Possible values: cadc, usdc, eudc
                3. Version or type of signature. Always abs1
        """
        credential_scope_date = datetime.utcnow().date().strftime(DATE_FORMAT_CREDENTIAL_SCOPE)
        region = ABSOLUTE_URL_REGION[self._base_url]
        return f'{credential_scope_date}/{region}/{STRING_TO_SIGN_SIGNATURE_VERSION}'

    def create_signing_key(self):
        """
        HMAC-SHA256 is used for authentication.
        The signing key should be created by:

        kSecret: The kSecret value is calculated by concatenating the static string “ABS1” with the value of the
                secret key from your API token and then encoding the resulting string using UTF8.
                The secret is the secret key value from the token that you created in the Absolute console.

        kDate: The date (in UTC) of the request. Format: <YYYY><MM><DD>. The result is a byte array.

        kSigning: Use the binary hash to get a pure binary kSigning key. The result is a byte array.
                    Note:Do not use a hex digest method.

        """
        credential_scope_date = datetime.now().date().strftime(DATE_FORMAT_CREDENTIAL_SCOPE)
        k_date = sign((STRING_TO_SIGN_SIGNATURE_VERSION.upper() + self._secret_key).encode('utf-8'),
                      credential_scope_date)
        return sign(k_date, 'abs1_request')

    def create_signature(self, signing_string, signing_key):
        """
        As a result of creating a signing key, kSigning is used as the key for hashing.
        The StringToSign is the string  data to be hashed.

        The signature should look like this:

        signature = lowercase(hexencode(HMAC(kSigning, StringToSign)))
        """
        return hmac.new(signing_key, signing_string.encode('utf-8'), hashlib.sha256).hexdigest()

    def add_authorization_header(self, signing_signature: str) -> str:
        """
        Use the standard HTTP Authorization header. Should look like this:
        Authorization: <algorithm> Credential=<token id>/<CredentialScope>,
        SignedHeaders=<SignedHeaders>, Signature=<signature>

        Authorization: The string used to identify the algorithm

        Credential: The token ID

        CredentialScope: the same as described in the create_credential_scope func.

        SignedHeaders: Semi-colon ; delimited list of lowercase headers used in CanonicalHeaders

        Signature: The fully calculated resulting signature from the signing key and the signature
        """
        credential_scope = self.create_credential_scope()
        canonical_headers = ";".join([header.lower() for header in self._headers])
        # There is a space after each comma in the authorization header
        return f'{STRING_TO_SIGN_ALGORITHM} Credential={self._token_id}/{credential_scope}, ' \
               f'SignedHeaders={canonical_headers}, Signature={signing_signature}'

    def api_request_absolute(self, method: str, url_suffix: str, body: str = "", success_status_code=None,
                             query_string: str = ''):
        """
        Makes an HTTP request to the Absolute API.
        Args:
            method (str): HTTP request method (GET/PUT/POST/DELETE).
            url_suffix (str): The API endpoint.
            body (str): The body to set.
            success_status_code (int): an HTTP status code of success.
            query_string (str): The query to filter results by.

        Note: As on the put and post requests we should pass a body from type str, we couldn't use the _http_request
              function in CSP (as it does not receive body from type str).
        """
        demisto.debug(f'current request is: method={method}, url suffix={url_suffix}, body={body}')
        full_url = urljoin(self._base_url, url_suffix)

        if success_status_code is None:
            success_status_code = [200]

        self.prepare_request_for_api(method=method, canonical_uri=url_suffix, query_string=query_string, payload=body)

        if method == 'GET':
            if query_string:
                url_suffix = f'{url_suffix}?{self.prepare_query_string_for_canonical_request(query_string)}'
            return self._http_request(method=method, url_suffix=url_suffix, headers=self._headers,
                                      return_empty_response=True)

        elif method == 'DELETE':
            return self._http_request(method=method, url_suffix=url_suffix, headers=self._headers,
                                      ok_codes=tuple(success_status_code), resp_type='response')

        elif method == 'PUT':
            res = requests.put(full_url, data=body, headers=self._headers, verify=self._verify)
            if res.status_code not in success_status_code:
                raise DemistoException(f'{INTEGRATION} error: the operation was failed due to: {res.json()}')
            return None

        elif method == 'POST':
            res = requests.post(full_url, data=body, headers=self._headers, verify=self._verify)
            if res.status_code not in success_status_code:
                raise DemistoException(f'{INTEGRATION} error: the operation was failed due to: {res.json()}')
            return res.json()
        return None


class ClientV3(BaseClient):
    def __init__(self, base_url: str, token_id: str, secret_key: str, verify: bool, proxy: bool, headers: dict = HEADERS_V3):
        """
        Client to use in the Absolute integration for API v3. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request.
            token_id (str): The Absolute token id
            secret_key (str): User's Absolute secret key
            verify (bool): Whether to check for SSL certificate validity.
            proxy (bool): Whether the client should use proxies.
            headers (dict): Dictionary of HTTP headers to send with the Request.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._token_id = token_id
        self._headers = headers
        self._secret_key = secret_key

    def prepare_request(self, method: str, url_suffix: str, query_string: str) -> str:
        """
        Prepares the signed HTTP request data for making an API call.

        Args:
            method (str): The HTTP method to be used for the request.
            url_suffix (str): The endpoint URL suffix for the API call.
            query_string (str): The query string parameters for the API call.

        Returns:
            str: The prepared signed HTTP request data.
        """
        headers = {
            "alg": "HS256",
            "kid": self._token_id,
            "method": method,
            "content-type": "application/json",
            "uri": url_suffix,
            "query-string": query_string,
            "issuedAt": round(time.time() * 1000)
        }

        return jwt.encode({"data": {}}, self._secret_key, algorithm='HS256', headers=headers)

    def fetch_events_request(self, query_string: str) -> dict[str, Any]:
        """
        Performs the HTTP request using the signed request data.

        Args:
            query_string (str): The query string parameters for the events to be fetched.

        Returns:
            dict: A dictionary containing the response object from the HTTP request.
        """
        signed = self.prepare_request(method='GET', url_suffix='/v3/reporting/siem-events', query_string=query_string)
        return self._http_request(method='POST', data=signed, full_url=CLIENT_V3_JWS_VALIDATION_URL)

    def fetch_events_between_dates(self, fetch_limit: int, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """
        Helper function to fetch events with time window from the API based on the provided parameters.

        Args:
            fetch_limit (int): The maximum number of events to fetch.
            start_date (datetime): The start date for the events to be fetched.
            end_date (datetime): The end date for the events to be fetched.
        Returns:
            list: A list of fetched events.
        """
        all_events: List[Dict[str, Any]] = []
        next_page_token = ''
        while len(all_events) < fetch_limit:
            page_size = min(SEIM_EVENTS_PAGE_SIZE, fetch_limit - len(all_events))
            query_string = self.prepare_query_string_for_fetch_events(page_size=page_size, start_date=start_date,
                                                                      end_date=end_date, next_page=next_page_token)
            response = self.fetch_events_request(query_string=query_string)
            all_events.extend(response.get('data', []))
            next_page_token = response.get('metadata', {}).get('pagination', {}).get('nextPage', '')
            if not next_page_token:
                break

        demisto.debug(f'fetch_events_between_dates: Fetched {len(all_events)} events')
        return all_events

    def prepare_query_string_for_fetch_events(self, start_date: datetime, end_date: datetime, page_size: int = None,
                                              next_page: str = None) -> str:
        """
        Prepares the query string for fetching events based on the provided parameters.

        Args:
            start_date (datetime): The start date of the events to fetch.
            end_date (datetime): The end date of the events to fetch.
            page_size (int, optional): The size of each page to fetch. Defaults to None.
            next_page (str, optional): The next page token. Defaults to None.

        Returns:
            str: The prepared query string for fetching events.

        """
        from_date_time_utc = f'fromDateTimeUtc={start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]}Z'
        to_date_time_utc = f'toDateTimeUtc={end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]}Z'
        query = f'{from_date_time_utc}&{to_date_time_utc}'
        if page_size:
            query += f'&pageSize={page_size}'
        if next_page:
            query += f'&nextPage={next_page}'
        demisto.debug(f'Query string for fetching events: {query}')
        return query


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def validate_absolute_api_url(base_url):
    if base_url not in ABSOLUTE_URL_TO_API_URL.keys():
        raise_demisto_exception(
            f"The Absolute server url {base_url} in not a valid url. "
            f"Possible options: {list(ABSOLUTE_URL_TO_API_URL.keys())}")
    return ABSOLUTE_URL_TO_API_URL[base_url]


def test_module(client: Client) -> str:
    """Tests API connectivity to Absolute """
    try:
        client.api_request_absolute('GET', '/v2/device-freeze/messages', success_status_code=(200, 204))
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def parse_device_field_list_response(response: dict) -> dict[str, Any]:
    parsed_data = {'DeviceUID': response.get('deviceUid'), 'ESN': response.get('esn'), 'CDFValues': []}  # type: ignore
    for cdf_item in response.get('cdfValues', []):
        parsed_data['CDFValues'].append({  # type: ignore
            'CDFUID': cdf_item.get('cdfUid'),
            'FieldKey': cdf_item.get('fieldKey'),
            'FieldName': cdf_item.get('fieldName'),
            'CategoryCode': cdf_item.get('categoryCode'),
            'FieldValue': cdf_item.get('fieldValue'),
            'Type': cdf_item.get('type'),
        })
    return parsed_data


def parse_device_field_list_response_human_readable(outputs):
    human_readable = []
    for cdf_values in outputs.get('CDFValues', []):
        human_readable.append({
            'Filed Name': cdf_values.get('FieldName'),
            'CDF ID': cdf_values.get('CDFUID'),
            'Field Value': cdf_values.get('FieldName'),
        })
    return human_readable


def get_custom_device_field_list_command(args, client) -> CommandResults:
    device_id = args.get('device_id')
    res = client.api_request_absolute('GET', f'/v2/devices/{device_id}/cdf')
    outputs = parse_device_field_list_response(res)
    human_readable = tableToMarkdown(f'{INTEGRATION} Custom device field list',
                                     parse_device_field_list_response_human_readable(outputs),
                                     removeNull=True)
    return CommandResults(outputs=outputs,
                          outputs_prefix="Absolute.CustomDeviceField",
                          outputs_key_field='DeviceUID',
                          readable_output=human_readable, raw_response=res)


def update_custom_device_field_command(args, client) -> CommandResults:
    device_id = args.get('device_id')
    cdf_uid = args.get('cdf_uid')
    field_value = args.get('value')

    payload = json.dumps({"cdfValues": [{'cdfUid': cdf_uid, 'fieldValue': field_value}]})
    client.api_request_absolute('PUT', f'/v2/devices/{device_id}/cdf', body=payload)
    return CommandResults(readable_output=f"Device {device_id} with value {field_value} was updated successfully.")


def validate_device_freeze_type_offline(offline_time_seconds):
    if not offline_time_seconds:
        # the default is 30 days
        offline_time_seconds = 22592000
    else:
        # must be between 1200 seconds (20 minutes) and 172800000 seconds (2000 days)
        offline_time_seconds_valid = 1200 <= offline_time_seconds <= 172800000
        if not offline_time_seconds_valid:
            raise_demisto_exception("the offline_time_seconds arg is not valid. Must be between 1200 seconds"
                                    " (20 minutes) and 172800000 seconds (2000 days).")
    return offline_time_seconds


def raise_demisto_exception(msg):
    raise DemistoException(f'{INTEGRATION} error: {msg}')


def validate_device_freeze_type_scheduled(scheduled_freeze_date):
    if not scheduled_freeze_date:
        raise_demisto_exception('When setting device_freeze_type to be Scheduled, you must specify the scheduled_'
                                'freeze_date arg.')
    return scheduled_freeze_date


def validate_passcode_type_args(passcode_type, passcode, passcode_length, payload):
    if passcode_type == "UserDefined":
        if not passcode:
            raise_demisto_exception(
                'when setting passcode_type to be UserDefined, you must specify the passcode arg.')
        payload["passcodeDefinition"].update({"passcode": passcode})

    elif passcode_type == "RandomForEach" or passcode_type == "RandomForAll":
        not_valid_passcode_length = not passcode_length or passcode_length > 8 or passcode_length < 4
        if not_valid_passcode_length:
            raise_demisto_exception('when setting passcode_type to be RandomForEach or RandomForAll, '
                                    'you must specify the passcode_length arg to be between 4 to 8.')
        payload["passcodeDefinition"].update({"length": passcode_length})

    return payload


def parse_freeze_device_response(response: dict):
    outputs = {'RequestUID': response.get('requestUid'), 'SucceededDeviceUIDs': response.get('deviceUids')}
    errors = response.get('errors', [])
    human_readable_errors = []
    if errors:
        for error in errors:
            human_readable_errors.append({'Failed UID': ','.join(error.get('detail', []).get('deviceUids')),
                                          'Error Message': error.get('message', '')})
        outputs['Errors'] = errors
        outputs['FailedDeviceUIDs'] = human_readable_errors
    return outputs


def device_freeze_request_command(args, client) -> CommandResults:
    payload = prepare_payload_to_freeze_request(args)
    res = client.api_request_absolute('POST', '/v2/device-freeze/requests', body=json.dumps(payload),
                                      success_status_code=[201])
    outputs = parse_freeze_device_response(res)
    human_readable = tableToMarkdown(f'{INTEGRATION} device freeze requests results', outputs,
                                     headers=['FailedDeviceUIDs', 'RequestUID', 'SucceededDeviceUIDs'], removeNull=True,
                                     json_transform_mapping={'FailedDeviceUIDs': JsonTransformer()}, )

    outputs.pop('FailedDeviceUIDs', '')
    return CommandResults(readable_output=human_readable, outputs=outputs, outputs_prefix="Absolute.FreezeRequest",
                          outputs_key_field="RequestUID", raw_response=res)


def prepare_payload_to_freeze_request(args):
    request_name = args.get('request_name')
    html_message = args.get('html_message')
    message_name = args.get('message_name')
    device_ids = argToList(args.get('device_ids'))
    notification_emails = argToList(args.get('notification_emails'))
    device_freeze_type = args.get('device_freeze_type')
    passcode_type = args.get('passcode_type')

    payload = {
        "name": request_name,
        "message": html_message,
        "messageName": message_name,
        "freezeDefinition":
            {
                "deviceFreezeType": device_freeze_type
            },
        "deviceUids": device_ids,
        "notificationEmails": notification_emails,
        "passcodeDefinition":
            {
                "option": passcode_type
            }
    }

    scheduled_freeze_date = args.get('scheduled_freeze_date')
    offline_time_seconds = arg_to_number(args.get('offline_time_seconds'), required=False)
    if device_freeze_type == "Scheduled":
        scheduled_freeze_date = validate_device_freeze_type_scheduled(scheduled_freeze_date)
        payload["freezeDefinition"].update({"scheduledFreezeDate": scheduled_freeze_date})

    elif device_freeze_type == "Offline":
        offline_time_seconds = validate_device_freeze_type_offline(offline_time_seconds)
        payload["freezeDefinition"].update({"offlineTimeSeconds": offline_time_seconds})
    passcode = args.get('passcode')
    passcode_length = arg_to_number(args.get('passcode_length'), required=False)
    payload = validate_passcode_type_args(passcode_type, passcode, passcode_length, payload)
    return payload


def remove_device_freeze_request_command(args, client) -> CommandResults:
    device_ids = argToList(args.get('device_ids'))
    remove_scheduled = args.get('remove_scheduled')
    remove_offline = args.get('remove_offline')

    # from the API docs: unfreeze - Make frozen devices usable immediately, Applies to all Freeze types.
    # Always set to true
    payload = {"deviceUids": device_ids, "unfreeze": "true", "removeScheduled": remove_scheduled,
               "removeOffline": remove_offline}

    client.api_request_absolute('PUT', '/v2/device-freeze/requests', body=json.dumps(payload),
                                success_status_code=[204])
    return CommandResults(
        readable_output=f"Successfully removed freeze request for devices ids: {args.get('device_ids')}.")


def parse_get_device_freeze_response(response: List):
    parsed_data = []
    for freeze_request in response:
        parsed_data.append({
            'ID': freeze_request.get('id'),
            'AccountUid': freeze_request.get('accountUid'),
            'ActionRequestUid': freeze_request.get('actionRequestUid'),
            'DeviceUid': freeze_request.get('deviceUid'),
            'Name': freeze_request.get('name'),
            'Statuses': freeze_request.get('statuses', []),
            'Configuration': freeze_request.get('configuration', {}),
            'Requester': freeze_request.get('requester'),
            'RequesterUid': freeze_request.get('requesterUid'),
            'CreatedUTC': freeze_request.get('createdUTC'),
            'ChangedUTC': freeze_request.get('changedUTC'),
            'NotificationEmails': freeze_request.get('notificationEmails'),
            'EventHistoryId': freeze_request.get('eventHistoryId'),
            'PolicyGroupUid': freeze_request.get('policyGroupUid'),
            'PolicyConfigurationVersion': freeze_request.get('policyConfigurationVersion'),
            'FreezePolicyUid': freeze_request.get('freezePolicyUid'),
            'Downloaded': freeze_request.get('downloaded'),
            'IsCurrent': freeze_request.get('isCurrent'),
            # for the freeze message command
            'Content': freeze_request.get('content'),
            'CreatedBy': freeze_request.get('createdBy'),
            'ChangedBy': freeze_request.get('changedBy'),
        })
    return parsed_data


def parse_device_freeze_message_response(response):
    if not isinstance(response, list):
        # in case we got here from the f'/v2/device-freeze/messages/{message_id}' url, the response is a json
        response = [response]
    parsed_data = []
    for freeze_request in response:
        parsed_data.append({
            'ID': freeze_request.get('id'),
            'Name': freeze_request.get('name'),
            'CreatedUTC': freeze_request.get('createdUTC'),
            'ChangedUTC': freeze_request.get('changedUTC'),
            'Content': freeze_request.get('content'),
            'CreatedBy': freeze_request.get('createdBy'),
            'ChangedBy': freeze_request.get('changedBy'),
        })
    return parsed_data


def get_device_freeze_request_command(args, client) -> CommandResults:
    request_uid = args.get('request_uid')
    res = client.api_request_absolute('GET', f'/v2/device-freeze/requests/{request_uid}')
    outputs = parse_get_device_freeze_response(res)

    human_readable = tableToMarkdown(f'{INTEGRATION} Freeze request details for: {request_uid}', outputs,
                                     headers=['ID', 'Name', 'AccountUid', 'ActionRequestUid', 'EventHistoryId',
                                              'FreezePolicyUid', 'CreatedUTC', 'ChangedUTC', 'Requester'],
                                     removeNull=True)
    return CommandResults(outputs=outputs, outputs_prefix="Absolute.FreezeRequestDetail", outputs_key_field='ID',
                          readable_output=human_readable, raw_response=res)


def list_device_freeze_message_command(args, client) -> CommandResults:
    message_id = args.get('message_id')
    if message_id:
        res = client.api_request_absolute('GET', f'/v2/device-freeze/messages/{message_id}')
    else:
        res = client.api_request_absolute('GET', '/v2/device-freeze/messages', success_status_code=(200, 204))

    if isinstance(res, list):
        outputs = parse_device_freeze_message_response(res)
        human_readable = tableToMarkdown(f'{INTEGRATION} Device freeze message details:', outputs,
                                         headers=['ID', 'Name', 'CreatedUTC', 'ChangedUTC', 'ChangedBy', 'CreatedBy'],
                                         removeNull=True)
        return CommandResults(outputs=outputs, outputs_prefix="Absolute.FreezeMessage", outputs_key_field='ID',
                              readable_output=human_readable, raw_response=res)
    else:
        # in this case the response is empty, no content in response, no messages found
        return CommandResults(readable_output=f'{INTEGRATION}: your account has no existing Freeze messages.')


def create_device_freeze_message_command(args, client) -> CommandResults:
    html_message = args.get('html_message')
    message_name = args.get('message_name')

    payload = {"name": message_name, "content": html_message}

    res = client.api_request_absolute('POST', '/v2/device-freeze/messages', body=json.dumps(payload),
                                      success_status_code=(200, 201))
    human_readable = f"{INTEGRATION} New freeze message was created with ID: {res.get('id')}"
    return CommandResults(outputs={'ID': res.get('id')}, outputs_prefix="Absolute.FreezeMessage",
                          outputs_key_field='ID',
                          readable_output=human_readable, raw_response=res)


def update_device_freeze_message_command(args, client) -> CommandResults:
    message_id = args.get('message_id')
    html_message = args.get('html_message')
    message_name = args.get('message_name')
    payload = {"name": message_name, "content": html_message}
    client.api_request_absolute('PUT', f'/v2/device-freeze/messages/{message_id}', body=json.dumps(payload))
    return CommandResults(readable_output=f'{INTEGRATION} Freeze message: {message_id} was updated successfully')


def delete_device_freeze_message_command(args, client) -> CommandResults:
    message_id = args.get('message_id')
    client.api_request_absolute('DELETE', f'/v2/device-freeze/messages/{message_id}', success_status_code=[204])
    return CommandResults(readable_output=f'{INTEGRATION} Freeze message: {message_id} was deleted successfully')


def parse_device_unenroll_response(response):
    parsed_data = []
    for device in response:
        parsed_data.append({
            'DeviceUid': device.get('deviceUid'),
            'SystemName': device.get('systemName'),
            'Username': device.get('username'),
            'EligibleStatus': device.get('eligibleStatus'),
            'Serial': device.get('serial'),
            'ESN': device.get('esn'),
        })
    return parsed_data


def device_unenroll_command(args, client) -> CommandResults:
    device_ids = argToList(args.get('device_ids'))
    payload = [{'deviceUid': device_id} for device_id in device_ids]
    res = client.api_request_absolute('POST', '/v2/device-unenrollment/unenroll', body=json.dumps(payload))
    outputs = parse_device_unenroll_response(res)
    human_readable = tableToMarkdown(f'{INTEGRATION} unenroll devices:', outputs, removeNull=True)
    return CommandResults(outputs_prefix='Absolute.DeviceUnenroll',
                          outputs=outputs,
                          readable_output=human_readable,
                          raw_response=res)


def add_list_to_filter_string(field_name, list_of_values, query):
    if not list_of_values:
        return query

    query_list = []
    list_of_values.sort()
    query_list.extend([f"substringof('{value}',{field_name})" for value in list_of_values])
    new_query = " or ".join(query_list)

    if query:
        return f'{query} or {new_query}'
    return new_query


def add_value_to_filter_string(field_name, value, query):
    if not value:
        return query
    if query:
        # if there is already a query, we should add 'or' before appending the new query
        return f"{query} or {field_name} eq '{value}'"

    return f"{field_name} eq '{value}'"


def create_filter_query_from_args_helper(args, arg_name, source_name, query):
    list_no_duplicates = remove_duplicates_from_list_arg(args, arg_name)
    query = add_list_to_filter_string(source_name, list_no_duplicates, query)
    return query


def create_filter_query_from_args(args: dict, change_device_name_to_system=False, change_device_id=False):
    """

    Args:
        args: args given from the user.
        change_device_name_to_system: True if to filter by "systemName" parameter and False to filter by "deviceName".
        change_device_id: True if to filter by "id" parameter and False to filter by "deviceUid".

    Returns: filter query to send to the API.

    """
    custom_filter = args.get('filter')
    if custom_filter:
        return f"$filter={custom_filter}"
    query = ""

    query = create_filter_query_from_args_helper(args, 'account_uids', "accountUid", query)
    query = create_filter_query_from_args_helper(args, 'app_names', "appName", query)
    query = create_filter_query_from_args_helper(args, 'app_publishers', "appPublisher", query)
    query = create_filter_query_from_args_helper(args, 'user_names', "userName", query)
    query = create_filter_query_from_args_helper(args, 'os', "osName", query)
    query = create_filter_query_from_args_helper(args, 'esn', "esn", query)
    query = create_filter_query_from_args_helper(args, 'local_ips', "localIp", query)
    query = create_filter_query_from_args_helper(args, 'public_ips', "publicIp", query)

    device_names = remove_duplicates_from_list_arg(args, 'device_names')
    if device_names and change_device_name_to_system:
        query = add_list_to_filter_string("systemName", device_names, query)
    else:
        query = add_list_to_filter_string("deviceName", device_names, query)

    device_ids = remove_duplicates_from_list_arg(args, 'device_ids')
    if device_ids and change_device_id:
        query = add_list_to_filter_string("id", device_ids, query)
    else:
        query = add_list_to_filter_string("deviceUid", device_ids, query)

    if args.get('agent_status'):
        agent_status = ABSOLUTE_AGET_STATUS[args.get('agent_status')]  # type: ignore
        query = add_value_to_filter_string("agentStatus", agent_status, query)

    os_name = args.get('os_name')
    query = add_value_to_filter_string("osName", os_name, query)

    os_version = args.get('os_version')
    query = add_value_to_filter_string("osVersion", os_version, query)

    manufacturer = args.get('manufacturer')
    query = add_value_to_filter_string("systemManufacturer", manufacturer, query)

    model = args.get('model')
    query = add_value_to_filter_string("systemModel", model, query)

    return f"$filter={query}"


def parse_return_fields(return_fields: str, query: str):
    """
    Returns values only for the fields that meet the specified criteria in the query.
    All other fields are returned with a null value.
    """
    if not return_fields:
        return query

    if query:
        return f"{query}&$select={return_fields}"
    return f"$select={return_fields}"


def parse_paging(page: int, limit: int, query: str) -> str:
    """
    Add pagination query format to the existing query
    """
    if query:
        return f'{query}&$skip={page}&$top={limit}'
    return f"$skip={page}&$top={limit}"


def parse_device_list_response(response, keep_os_in_list=True):
    parsed_response = []
    for device in response:
        parsed_device = {}
        for key, val in device.items():
            if val:
                if key == 'os' and not keep_os_in_list:
                    parsed_device['osName'] = val.get('name')
                elif key == 'espInfo':
                    parsed_device['encryptionStatus'] = val.get('encryptionStatus')
                else:
                    parsed_device[key[0].upper() + key[1:]] = val
        parsed_response.append(parsed_device)

    if len(parsed_response) == 1:
        return parsed_response[0]
    return parsed_response


def parse_geo_location_outputs(response):
    parsed_response = []
    for device in response:
        parsed_device = {}
        geo_data = device.get('geoData', {}).get('location', {})
        parsed_device['Coordinates'] = geo_data.get('point', {}).get('coordinates')
        parsed_device['LocationTechnology'] = geo_data.get('locationTechnology')
        parsed_device['Accuracy'] = geo_data.get('accuracy')
        parsed_device['LastUpdate'] = geo_data.get('lastUpdateDateTimeUtc')
        parsed_device['City'] = geo_data.get('geoAddress', {}).get('city')
        parsed_device['State'] = geo_data.get('geoAddress', {}).get('state')
        parsed_device['CountryCode'] = geo_data.get('geoAddress', {}).get('countryCode')
        parsed_device['Country'] = geo_data.get('geoAddress', {}).get('country')
        parsed_device['ID'] = device.get('id')

        parsed_response.append(parsed_device)

    if len(parsed_response) == 1:
        return parsed_response[0]
    return parsed_response


def get_device_application_list_command(args, client) -> CommandResults:
    page = arg_to_number(args.get('page', 0))
    limit = arg_to_number(args.get('limit', 50))

    query_string = create_filter_query_from_args(args)
    query_string = parse_return_fields(args.get('return_fields'), query_string)
    query_string = parse_paging(page, limit, query_string)  # type: ignore

    res = client.api_request_absolute('GET', '/v2/sw/deviceapplications', query_string=query_string)
    if res:
        outputs = parse_device_list_response(res)
        human_readable = tableToMarkdown(f'{INTEGRATION} device applications list:', outputs, removeNull=True)
        human_readable += f"Above results are with page number: {page} and with size: {limit}."
        return CommandResults(outputs_prefix='Absolute.DeviceApplication',
                              outputs=outputs,
                              outputs_key_field='Appid',
                              readable_output=human_readable,
                              raw_response=res)
    else:
        return CommandResults(readable_output=f"No applications found in {INTEGRATION} for the given filters: {args}")


def device_list_command(args, client) -> CommandResults:
    page = arg_to_number(args.get('page', 0))
    limit = arg_to_number(args.get('limit', 50))

    query_string = create_filter_query_from_args(args, change_device_name_to_system=True)
    query_string = parse_return_fields(",".join(DEVICE_LIST_RETURN_FIELDS), query_string)
    query_string = parse_paging(page, limit, query_string)  # type: ignore

    res = client.api_request_absolute('GET', '/v2/reporting/devices', query_string=query_string)
    if res:
        outputs = parse_device_list_response(copy.deepcopy(res), keep_os_in_list=False)
        human_readable = tableToMarkdown(f'{INTEGRATION} devices list:', outputs, removeNull=True)
        human_readable += f"Above results are with page number: {page} and with size: {limit}."
        return CommandResults(outputs_prefix='Absolute.Device',
                              outputs=outputs,
                              outputs_key_field="Id",
                              readable_output=human_readable,
                              raw_response=res)
    else:
        return CommandResults(readable_output=f"No devices found in {INTEGRATION} for the given filters: {args}")


def get_device_command(args, client) -> CommandResults:
    if not ('device_ids' in args or 'device_names' in args or 'local_ips' in args or 'public_ips' in args):
        raise_demisto_exception(
            "at least one of the commands args (device_ids, device_names, local_ips, public_ips must be provided.")

    query_string = create_filter_query_from_args(args, change_device_name_to_system=True, change_device_id=True)
    custom_fields_to_return = remove_duplicates_from_list_arg(args, 'fields')
    if custom_fields_to_return:
        custom_fields_to_return.extend(DEVICE_GET_COMMAND_RETURN_FIELDS)
        query_string = parse_return_fields(",".join(custom_fields_to_return), query_string)
    else:
        query_string = parse_return_fields(",".join(DEVICE_GET_COMMAND_RETURN_FIELDS), query_string)

    res = client.api_request_absolute('GET', '/v2/reporting/devices', query_string=query_string)
    if res:
        outputs = parse_device_list_response(copy.deepcopy(res))
        human_readable = tableToMarkdown(f'{INTEGRATION} devices list:', outputs, removeNull=True)
        return CommandResults(outputs_prefix='Absolute.Device',
                              outputs=outputs,
                              outputs_key_field="Id",
                              readable_output=human_readable,
                              raw_response=res)
    else:
        return CommandResults(readable_output=f"No devices found in {INTEGRATION} for the given filters: {args}")


def get_device_location_command(args, client) -> CommandResults:
    query_string = create_filter_query_from_args(args, change_device_id=True)
    query_string = parse_return_fields(",".join(DEVICE_GET_LOCATION_COMMAND_RETURN_FIELDS), query_string)

    res = client.api_request_absolute('GET', '/v2/reporting/devices', query_string=query_string)
    if res:
        outputs = parse_geo_location_outputs(copy.deepcopy(res))
        human_readable = tableToMarkdown(f'{INTEGRATION} devices location:', outputs, removeNull=True)
        return CommandResults(outputs_prefix='Absolute.LocationReport',
                              outputs=outputs,
                              readable_output=human_readable,
                              raw_response=res)
    else:
        return CommandResults(
            readable_output=f"No device locations found in {INTEGRATION} for the given filters: {args}")


''' EVENT COLLECTOR '''


def fetch_events(client: ClientV3, fetch_limit: int, last_run: Dict[str, Any]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
        Fetches events from the API client, with time window and duplication handling.
        The function using the client to fetch events, and then helper function to handle duplication,
        add time field and calculate the new latest events.

        Args:
            client (ClientV3): The client object used for fetching events.
            fetch_limit (int): The maximum number of events to fetch.
            last_run (Dict[str, Any]): A dictionary containing the last run information, including the latest events time and
                latest events ID.

        Returns:
            Tuple[List[Dict[str, Any]], Dict[str, Any]]: A tuple containing the fetched events and the updated last run
                information.
        """
    latest_events_time = last_run.get('latest_events_time')
    end_date = datetime.utcnow()
    start_date: datetime = datetime.strptime(latest_events_time, "%Y-%m-%dT%H:%M:%S.%fZ") if latest_events_time else (
        end_date - timedelta(minutes=1))

    # Adjust fetch_limit to ensure that the number of events fetched matches the user's desired amount.
    fetch_limit += len(last_run.get('latest_events_id', []))
    demisto.debug(f'Starting new fetch: {fetch_limit=}, {start_date=}, {end_date=}, {last_run=}')

    all_events = client.fetch_events_between_dates(fetch_limit, start_date, end_date)
    events, updated_last_run = process_events(all_events, last_run)
    demisto.debug(f'fetch_events: {updated_last_run.get("latest_events_id")=}, {updated_last_run.get("latest_events_time")=}')

    return events, updated_last_run


def process_events(events: List[Dict[str, Any]], last_run: Dict[str, Any], should_get_latest_events: bool = True) -> \
        tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Processes events by handling duplication, adding a time field, and optionally getting the latest events ID and time.

    Args:
        events (List[Dict[str, Any]]): The list of events to be processed.
        last_run (Dict[str, Any]): The updated last run information.
        should_get_latest_events (bool, optional): A flag indicating whether to get the latest events ID. Defaults to True.

    Returns:
        Tuple[List[Dict[str, Any]], [Dict[str, Any]]]: A tuple containing the processed events and the updated last run object.

    """
    demisto.debug(f"Handle duplicate events, adding _time field to events and optionally getting the latest events id and time."
                  f" {events=}, {last_run=}")
    last_run_latest_events_id = last_run.get('latest_events_id', [])
    earliest_event_time = last_run.get('latest_events_time', '')
    latest_event_time = events[-1].get('eventDateTimeUtc') if events else ''
    latest_events_id = []
    filtered_events = []
    for event in events:
        event_time = event.get('eventDateTimeUtc')
        # handle duplication
        if event_time == earliest_event_time and event.get('id') in last_run_latest_events_id:
            continue
        # adding time field
        event['_time'] = event_time
        # latest events batch
        if should_get_latest_events and event_time == latest_event_time:
            latest_events_id.append(event.get('id'))
        filtered_events.append(event)

    return filtered_events, {'latest_events_id': latest_events_id if latest_events_id else last_run_latest_events_id,
                             'latest_events_time': latest_event_time}


def get_events(client, args) -> tuple[List[Dict[str, Any]], CommandResults]:
    start_date = arg_to_datetime(args.get('start_date', "one minute ago"))
    end_date = arg_to_datetime(args.get('end_date', "now"))
    fetch_limit = int(args.get('limit', 50))
    if (start_date and end_date) and (start_date > end_date):
        raise ValueError("Start date is greater than the end date. Please provide valid dates.")

    events = client.fetch_events_between_dates(fetch_limit, start_date, end_date)
    demisto.debug(f'get_events: Found {len(events)} events.')
    if events:
        events, _ = process_events(events, {}, should_get_latest_events=False)
    return events, CommandResults(readable_output=tableToMarkdown('Events', t=events))


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    params = demisto.params()
    try:
        base_url = validate_absolute_api_url(params.get('url'))
        token_id = params.get('credentials').get('identifier')
        secret_key = params.get('credentials').get('password')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        demisto.debug(f'Command being called is {demisto.command()}')
        host = base_url.split('https://')[-1]
        x_abs_date = datetime.utcnow().strftime(DATE_FORMAT)
        headers: dict = {"host": host, "content-type": "application/json", "x-abs-date": x_abs_date}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            token_id=token_id,
            secret_key=secret_key,
            x_abs_date=x_abs_date,
        )

        client_v3 = ClientV3(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            token_id=token_id,
            secret_key=secret_key
        )

        args = demisto.args()
        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'absolute-custom-device-field-list':
            return_results(get_custom_device_field_list_command(args=args, client=client))

        elif demisto.command() == 'absolute-custom-device-field-update':
            return_results(update_custom_device_field_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-freeze-request':
            return_results(device_freeze_request_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-remove-freeze-request':
            return_results(remove_device_freeze_request_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-freeze-request-get':
            return_results(get_device_freeze_request_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-freeze-message-list':
            return_results(list_device_freeze_message_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-freeze-message-create':
            return_results(create_device_freeze_message_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-freeze-message-update':
            return_results(update_device_freeze_message_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-freeze-message-delete':
            return_results(delete_device_freeze_message_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-unenroll':
            return_results(device_unenroll_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-application-list':
            return_results(get_device_application_list_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-list':
            return_results(device_list_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-get':
            return_results(get_device_command(args=args, client=client))

        elif demisto.command() == 'absolute-device-location-get':
            return_results(get_device_location_command(args=args, client=client))

        elif demisto.command() == 'fetch-events':
            max_events_per_fetch = arg_to_number(params.get('max_events_per_fetch', 10000)) or 10000
            events, last_run_object = fetch_events(client_v3, max_events_per_fetch, demisto.getLastRun())
            if events:
                send_events_to_xsiam(events=events, vendor="Absolute", product="Secure Endpoint")
                demisto.setLastRun(last_run_object)

        elif demisto.command() == 'absolute-device-get-events':
            demisto.debug(f'Fetching Absolute Device events with the following parameters: {args}')
            should_push_events = argToBoolean(args.get('should_push_events', False))
            events, command_result = get_events(client=client_v3, args=args)
            if should_push_events and events:
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_result)

        else:
            raise NotImplementedError(f'{demisto.command()} is not an existing {INTEGRATION} command.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
