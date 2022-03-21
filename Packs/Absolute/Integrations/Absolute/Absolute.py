import hashlib

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from urllib.parse import urlparse
import requests
import traceback
from typing import Dict, Any
import hmac

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

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
INTEGRATION = "Absolute"
STRING_TO_SIGN_ALGORITHM = "ABS1-HMAC-SHA-256"
STRING_TO_SIGN_SIGNATURE_VERSION = "abs1"
DATE_FORMAT = '%Y%m%dT%H%M%SZ'  # ISO8601 format with UTC, default in XSOAR
DATE_FORMAT_CREDENTIAL_SCOPE = '%Y%m%d'
DATE_FORMAT_K_DATE = '<%Y><%m><%d>'


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
            x_abs_date (str):
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._payload = None
        self._base_url = base_url
        self._token_id = token_id
        self._secret_key = secret_key
        self._headers = headers
        self._x_abs_date = x_abs_date

    def validate_absolute_api_url(self):
        if self._base_url not in ABSOLUTE_URL_TO_API_URL.keys():
            DemistoException(f"{INTEGRATION} Error: The Absolute server url {self._base_url} in not a valid url.")

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
        query_list = query_string.split()
        query_list.sort()
        encoded_query_list = [urllib.parse.quote(query.encode('utf-8'), safe='=&') for query in query_list]
        return '&'.join(encoded_query_list)

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
        canonical_headers = ";".join([header.lower() for header in self._headers.keys()])
        # There is a space after each comma in the authorization header
        return f'{STRING_TO_SIGN_ALGORITHM} Credential={self._token_id}/{credential_scope}, ' \
               f'SignedHeaders={canonical_headers}, Signature={signing_signature}'

    def request_custom_device_fields(self, method: str, url_suffix: str, body: str = ""):
        """
        Makes an HTTP request to
        Args:
            method (str): HTTP request method (GET/POST/DELETE).
            url_suffix (str): The API endpoint.
            body (str): The body to set.
        """
        demisto.debug(f'current request is: method={method}, url suffix={url_suffix}, body={body}')
        self.prepare_request_for_api(method=method, canonical_uri=url_suffix, query_string='', payload=body)
        if method == 'GET':
            return self._http_request(method=method, url_suffix=url_suffix, headers=self._headers)
        else:
            full_url = urljoin(self._base_url, url_suffix)
            res = requests.put(full_url, data=body, headers=self._headers, verify=self._verify)
            if res.status_code != 200:
                raise DemistoException(f'{INTEGRATION} error: the operation was failed due to: {res.json()}')


''' COMMAND FUNCTIONS '''


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        client.validate_absolute_api_url()

        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def parse_device_field_list_response(response: dict) -> Dict[str, Any]:
    parsed_data = {'DeviceUID': response.get('deviceUid'), 'ESN': response.get('esn'), 'CDFValues': []}
    for cdf_item in response.get('cdfValues', []):
        parsed_data['CDFValues'].append({
            'CDFUID': cdf_item.get('cdfUid'),
            'FieldKey': cdf_item.get('fieldKey'),
            'FieldName': cdf_item.get('fieldName'),
            'CategoryCode': cdf_item.get('categoryCode'),
            'FieldValue': cdf_item.get('fieldValue'),
            'Type': cdf_item.get('type'),
        })
    return parsed_data


def get_custom_device_field_list_command(args, client) -> CommandResults:
    device_id = args.get('device_id')
    res = client.request_custom_device_fields('GET', f'/v2/devices/{device_id}/cdf')
    outputs = parse_device_field_list_response(res)
    human_readable = tableToMarkdown(f'{INTEGRATION}: Custom device field list', outputs,
                                     headers=['DeviceUID', 'ESN'], removeNull=True)
    return CommandResults(outputs=outputs, outputs_prefix="Absolute.CustomDeviceField", outputs_key_field='DeviceUID',
                          readable_output=human_readable, raw_response=res)


def update_custom_device_field_command(args, client) -> CommandResults:
    device_id = args.get('device_id')
    cdf_uid = args.get('cdf_uid')
    field_value = args.get('value')

    payload = json.dumps({"cdfValues": [{'cdfUid': cdf_uid, 'fieldValue': field_value}]})
    client.request_custom_device_fields('PUT', f'/v2/devices/{device_id}/cdf', body=payload)
    return CommandResults(readable_output=f"Device {device_id} with value {field_value} was updated successfully.")


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    base_url = ABSOLUTE_URL_TO_API_URL[params.get('url')]
    token_id = params.get('token')
    secret_key = params.get('secret_key', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        host = base_url.split('https://')[-1]
        x_abs_date = datetime.utcnow().strftime(DATE_FORMAT)
        headers: Dict = {"host": host, "content-type": "application/json", "x-abs-date": x_abs_date}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            token_id=token_id,
            secret_key=secret_key,
            x_abs_date=x_abs_date,
        )
        args = demisto.args()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'absolute-custom-device-field-list':
            return_results(get_custom_device_field_list_command(args=args, client=client))

        elif demisto.command() == 'absolute-custom-device-field-update':
            return_results(update_custom_device_field_command(args=args, client=client))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
