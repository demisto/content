# import demistomock as demisto
from CommonServerPython import *
# from CommonServerUserPython import *

from dateutil.parser import parse

import enum
import requests
import re
from typing import Dict, Any
from functools import wraps

CLOUD_TOKEN_URL = 'https://accounts.iboss.com/ibossauth/web/tokens'
CLOUD_ACCOUNT_SETTINGS_URL = 'https://cloud.iboss.com/ibcloud/web/users/mySettings'
CLOUD_CLUSTERS_URL = 'https://cloud.iboss.com/ibcloud/web/account/clusters'

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
URL_CATEGORIES_DICT = {
    0: 'Streaming Radio/TV',
    1: 'Ads',
    2: 'Porn/Nudity',
    3: 'Audio & Video',
    4: 'Dictionary',
    5: 'Dating & Personals',
    6: 'Drugs',
    7: 'Entertainment',
    8: 'Finance',
    9: 'Forums',
    10: 'Gambling',
    11: 'Games',
    12: 'Education',
    13: 'Jobs',
    14: 'Mobile Phones',
    15: 'News',
    16: 'Private Websites',
    17: 'Web Proxies',
    18: 'Shopping',
    19: 'Sports',
    20: 'Travel',
    21: 'Violence & Hate',
    22: 'Malware',
    23: 'Webmail',
    24: 'UNDEFINED',
    25: 'Guns & Weapons',
    26: 'Friendship',
    27: 'Religion',
    28: 'Toolbars',
    29: 'Search Engines',
    30: 'File Sharing',
    31: 'Government',
    32: 'Image / Video Search',
    33: 'Food',
    34: 'Trasportation',
    35: 'Business',
    36: 'Parked Domains',
    37: 'Health',
    38: 'Real Estate',
    39: 'Technology',
    40: 'Organizations',
    41: 'Auctions',
    42: 'Art',
    43: 'Political',
    44: 'Services',
    45: 'Swimsuit',
    46: 'Sex Ed',
    47: 'Adult Content',
    48: 'Alcohol',
    49: 'UNDEFINED',
    50: 'Terrorism',
    51: 'Abortion',
    52: 'Messaging',
    53: 'Infosec',
    54: 'CDN',
    55: 'Controlled Drugs',
    56: 'Dynamic DNS',
    57: 'Hacking',
    58: 'Humor',
    59: 'IoT',
    60: 'Internet Communication',
    61: 'Tech Infrastructure',
    62: 'Online Meetings',
    63: 'P2P',
    64: 'Piracy',
    65: 'Remote Access Tools',
    66: 'Illegal Activity',
    67: 'Scams',
    68: 'Translation Services',
    69: 'Phishing',
    70: 'Suspicious',
    71: 'Informational',
    72: 'Extreme',
    73: 'Marijuana',
    74: 'Nudity',
    75: 'Spam',
    76: 'Freeware / Shareware',
    77: 'Web Hosting',
    78: 'Kids',
    79: 'Suicide',
    80: 'Malicious Sources',
    81: 'Not Rated'
}

REPUTATION_MESSAGE_FIELDS = [
    'message',
    'googleSafeBrowsingDescription',
    'malwareEngineAnalysisDescription',
    'realtimeCloudLookupRiskDescription',
    'webRequestHeuristicDescription'
]

REPUTATION_MALICIOUS_FIELDS = ['googleSafeBrowsingISSafeUrl', 'malwareEngineIsSafeUrl', 'reputationDatabaseIsSafeUrl']
REPUTATION_SUSPICIOUS_FIELDS = ['webRequestHeuristicIsSafeUrl', 'realtimeCloudLookupIsSafeUrl']
REPUTATION_SAFE_FIELDS = ['isSafeUrl']

# Starting with init of metadata_collector
metadata_collector = YMLMetadataCollector(
    integration_name="iboss",
    description="Manage block lists, manage allow lists, and perform domain, IP, and/or URL reputation and categorization lookups.",
    display="iboss",
    category="Data Enrichment & Threat Intelligence",
    docker_image="demisto/python3:3.10.4.29342",
    is_fetch=False,
    long_running=False,
    long_running_port=False,
    is_runonce=False,
    integration_subtype="python3",
    integration_type="python",
    fromversion="5.0.0",
    # default_mapper_in="HelloWorld-mapper",
    # default_classifier="HelloWorld",
    conf=[ConfKey(name="auth",
                  display="Username",
                  # displaypassword="Password",
                  required=True,
                  key_type=ParameterTypes.AUTH),
          ConfKey(name="account_settings_id",
                  display="Account Settings ID",
                  required=True,
                  key_type=ParameterTypes.STRING),
          ConfKey(name="insecure",
                  display="Trust any certificate (not secure)",
                  required=False,
                  default_value="false",
                  key_type=ParameterTypes.BOOLEAN),
          ConfKey(name="proxy",
                  display="Use system proxy settings",
                  required=False,
                  default_value="false",
                  key_type=ParameterTypes.BOOLEAN)
          ])

''' CLIENT CLASS '''


def set_auth(method):
    @wraps(method)
    def _impl(self, *method_args, **method_kwargs):
        if not self.expiration or self.expiration < datetime.utcnow().timestamp():
            demisto.results(f"self.expiration = {self.expiration}. Re-authing")
            self.auth()
        try:
            return method(self, *method_args, **method_kwargs)
        except Exception as e:
            if "Unauthorized" in str(e):
                self.auth()
                return method(self, *method_args, **method_kwargs)
            raise (e)

    return _impl


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, username, password, account_settings_id, proxy: bool, verify: bool):
        super().__init__(base_url="cloud.iboss.com", proxy=proxy, verify=verify)
        self.username = username
        self.password = password
        self.account_settings_id = account_settings_id
        self._init_cache_params()

    def _init_cache_params(self):
        context = get_integration_context()

        # self.cloud_token = context.get("cloud_token")
        # self.xsrf_token = context.get("xsrf_token")
        self.primary_gateway = context.get("primary_gateway")
        self.gateway_xsrf_token = context.get("gateway_xsrf_token")
        self.expiration = int(context.get("expiration", -1))

        if self.primary_gateway:
            self._base_url = f"https://{self.primary_gateway}"
        if self.gateway_xsrf_token:
            self._headers = {"Cookie": self.gateway_xsrf_token}

    def auth(self):
        demisto.debug("Re-authenticating")

        token = self._get_cloud_token()
        xsrf_token, jsessionid, expiration = self._get_cloud_settings_tokens(token)
        primary_gateway = self._get_primary_gateway(token, jsessionid, xsrf_token)
        gateway_xsrf_token = self._get_swg_xsrf_token(primary_gateway, token)

        context = get_integration_context()
        context.update({
            'cloud_token': token,
            'xsrf_token': token,
            'jsessionid': jsessionid,
            'primary_gateway': primary_gateway,
            'gateway_xsrf_token': gateway_xsrf_token,
            'expiration': str(int(parse(expiration).timestamp()))
        })

        self.cloud_token = context.get("cloud_token")
        self.xsrf_token = context.get("xsrf_token")
        self.primary_gateway = context.get("primary_gateway")
        self.gateway_xsrf_token = context.get("gateway_xsrf_token")
        self.expiration = int(context.get("expiration"))

        self._base_url = f"https://{self.primary_gateway}"
        self._headers = {"Cookie": self.gateway_xsrf_token}

        set_integration_context(context)
        return "ok"

    def _get_cloud_token(self):
        auth = (self.username, self.password)
        params = {'ignoreAuthModule': 'true'}
        result = self._http_request(
            full_url='https://accounts.iboss.com/ibossauth/web/tokens',
            method="get",
            timeout=60,
            auth=auth,
            params=params
        )

        token = result.get("token")

        if not token:
            ValueError("System returned `None` for cloud token auth")

        return result["token"]

    def _get_cloud_settings_tokens(self, auth_token):
        headers = {"Authorization": f"Token {auth_token}"}
        cookie_values = self._http_request(
            full_url=CLOUD_ACCOUNT_SETTINGS_URL,
            method="get",
            headers=headers,
            resp_type="response"
        ).headers.get("Set-Cookie")

        # cv = requests.get(CLOUD_ACCOUNT_SETTINGS_URL, headers=headers).headers.get("Set-Cookie")

        demisto.info(f"Cookie vals: {cookie_values}")

        xsrf_token = re.findall(r"(?<=XSRF-TOKEN=).*?(?=;)", cookie_values)[0]
        jsessionid = re.findall(r"(?<=JSESSIONID=).*?(?=;)", cookie_values)[0]
        expiration = re.findall(r"(?<=expires=).*?(?=;)", cookie_values)[0]

        return xsrf_token, jsessionid, expiration

    def _get_primary_gateway(self, token, jsessionid, xsrf_token):
        headers = {
            "Authorization": f"Token {token}",
            "X-XSRF-TOKEN": "<cookie-list>",
            "Cookie": f"JSESSIONID={jsessionid}; XSRF-TOKEN={xsrf_token}"
        }

        result = self._http_request(
            full_url=CLOUD_CLUSTERS_URL + "?accountSettingsId=" + str(self.account_settings_id),
            method="get",
            timeout=60,
            headers=headers
        )

        swg_cluster = next(filter(lambda x: x['productFamily'] == 'swg', result))
        primary_swg = next(filter(lambda x: x['primary'] == 1, swg_cluster['members']))
        primary_swg_dns = primary_swg['cloudNode']['adminInterfaceDns']
        return primary_swg_dns

    def _get_swg_xsrf_token(self, primary_swg_dns, auth_token):
        url = f"https://{primary_swg_dns}/json/login"
        data = {"userName": auth_token, "x": "", "ldapServer": ""}
        result = self._http_request(
            method='post',
            full_url=url,
            json_data=data
        )
        xsrf_token = f"XSRF-TOKEN={result['uid']}&{result['sessionId']}"
        return xsrf_token

    def _list_error_handler(self, res):
        if res.status_code == 422:
            resp = res.json()
            if resp["errorCode"] == 0:
                return True
        raise DemistoException(f"Bad request. Origin response from server: {res.text}")

    def _remove_from_list_error_handler(self, res):
        if res.status_code == 422:
            resp = {'message': 'URL not found in list.'}
            if resp["errorCode"] == 0:
                return True
        raise DemistoException(f"Bad request. Origin response from server: {res.text}")

    @set_auth
    def get_block_list(self, current_policy_being_edited=0):
        result = self._http_request(
            method="get",
            url_suffix="/json/controls/blockList",
            params={"currentPolicyBeingEdited": current_policy_being_edited},
        )
        return result

    @set_auth
    def add_entity_to_block_list(self, url, current_policy_being_edited=1, allow_keyword=0,
                                 direction=2, end_port=0, apply_global=0, is_regex=0, is_timed_url=0, note="",
                                 priority=0, start_port=0, time_url_expires_in_minutes=0):
        params = {
            "url": url,
            "allow_keyword": allow_keyword,
            "direction": direction,
            "endPort": end_port,
            "global": apply_global,
            "isRegex": is_regex,
            "isTimedUrl": is_timed_url,
            "note": note,
            "priority": priority,
            "startPort": start_port,
            "timedUrlExpiresInMinutes": time_url_expires_in_minutes,
        }

        result = self._http_request(
            method="put",
            url_suffix="/json/controls/blockList",
            json_data=params,
            params={"currentPolicyBeingEdited": current_policy_being_edited},
            error_handler=self._list_error_handler,
            ok_codes=(200, 201, 202, 204, 422)
        )
        return result

    @set_auth
    def remove_entity_from_block_list(self, url, current_policy_being_edited=1, apply_global=0):
        params = {
            "url": url,
            "currentPolicyBeingEdited": current_policy_being_edited,
            "global": apply_global,
        }

        result = self._http_request(
            method="delete",
            url_suffix="/json/controls/blockList",
            params=params,
            ok_codes=(200, 201, 202, 204, 422),
            error_handler=self._remove_from_list_error_handler,
        )
        return result

    @set_auth
    def add_entity_to_allow_list(self, url, current_policy_being_edited=1, allow_keyword=0,
                                 direction=2, end_port=0, apply_global=0, is_regex=0, is_timed_url=0, note="",
                                 priority=0, start_port=0, time_url_expires_in_minutes=0):
        params = {
            "url": url,
            "allow_keyword": allow_keyword,
            "direction": direction,
            "endPort": end_port,
            "global": apply_global,
            "isRegex": is_regex,
            "isTimedUrl": is_timed_url,
            "note": note,
            "priority": priority,
            "startPort": start_port,
            "timedUrlExpiresInMinutes": time_url_expires_in_minutes,
        }

        result = self._http_request(
            method="put",
            url_suffix="/json/controls/allowList",
            json_data=params,
            params={"currentPolicyBeingEdited": current_policy_being_edited},
            error_handler=self._list_error_handler,
            ok_codes=(200, 201, 202, 204, 422)
        )
        return result

    @set_auth
    def remove_entity_from_allow_list(self, url, current_policy_being_edited=1, apply_global=0):
        params = {
            "url": url,
            "currentPolicyBeingEdited": current_policy_being_edited,
            "global": apply_global,
        }

        result = self._http_request(
            method="delete",
            url_suffix="/json/controls/allowList",
            params=params,
            ok_codes=(200, 201, 202, 204, 422),
            error_handler=self._remove_from_list_error_handler
        )
        return result

    @set_auth
    def get_url_reputation(self, url):
        data = {"url": url}
        result = self._http_request(
            method="post",
            url_suffix="/json/controls/urlLookup",
            json_data=data
        )
        return result


''' HELPER FUNCTIONS '''


def _iboss_entity_lookup_response_to_dbot_score(entity, lookup_response, dbot_score_type):
    if any(lookup_response.get(field, -1) == 0 for field in REPUTATION_MALICIOUS_FIELDS):
        dbot_score_value = Common.DBotScore.BAD
    elif any(lookup_response.get(field, -1) == 0 for field in REPUTATION_SUSPICIOUS_FIELDS):
        dbot_score_value = Common.DBotScore.SUSPICIOUS
    elif any(lookup_response.get(field, -1) == 0 for field in REPUTATION_SAFE_FIELDS):
        dbot_score_value = Common.DBotScore.GOOD
    else:
        dbot_score_value = Common.DBotScore.NONE

    dbot_score = Common.DBotScore(indicator=entity, indicator_type=dbot_score_type, score=dbot_score_value)

    if dbot_score_value == Common.DBotScore.BAD:
        dbot_score.malicious_description = _iboss_entity_lookup_response_to_message(lookup_response)

    return dbot_score


def _iboss_entity_lookup_response_to_indicator(entity, lookup_response, context_type, indicator_type):
    malicious_message = _iboss_entity_lookup_response_to_message(lookup_response)
    indicator = {
        context_type: {
            indicator_type: entity, 'Malicious': {'Vendor': 'iboss', 'Description': malicious_message}
        }
    }
    return indicator


def _iboss_ip_reputation(client, ip):
    response = client.get_url_reputation(ip)
    dbot_score = _iboss_entity_lookup_response_to_dbot_score(ip, response, DBotScoreType.IP)
    result = {"DBotScore": dbot_score, "iboss": response}

    if dbot_score.BAD:
        result.update(_iboss_entity_lookup_response_to_indicator(ip, response, 'IP', 'Address'))
    return result


def _iboss_url_reputation(client, url):
    response = client.get_url_reputation(url)
    dbot_score = _iboss_entity_lookup_response_to_dbot_score(url, response, DBotScoreType.URL)
    result = {"DBotScore": dbot_score, "iboss": response}

    if dbot_score.BAD:
        result.update(_iboss_entity_lookup_response_to_indicator(url, response, 'URL', 'Data'))
    return result


def _iboss_domain_reputation(client, domain):
    response = client.get_url_reputation(domain)
    dbot_score = _iboss_entity_lookup_response_to_dbot_score(domain, response, DBotScoreType.DOMAIN)
    result = {"DBotScore": dbot_score, "iboss": response}

    if dbot_score.BAD:
        result.update(_iboss_entity_lookup_response_to_indicator(domain, response, 'Domain', 'Name'))
    return result


def _iboss_entity_lookup_response_to_message(lookup_response):
    return '; '.join([lookup_response.get(x).strip(".") for x in REPUTATION_MESSAGE_FIELDS if lookup_response.get(x)])


def _get_validate_argument(name, args, default=None, validator=None, message="invalid argument", return_type=None):
    value = args.get(name, default)
    if return_type:
        value = return_type(value)

    if validator and not validator(value):
        raise ValueError(f"{name} ({value}) - {message}")

    return value


class ZeroOneEnum(enum.Enum):
    """YML configuration key types."""
    ZERO = "0"
    ONE = "1"


class ZeroOneTwoEnum(enum.Enum):
    """YML configuration key types."""
    ZERO = "0"
    ONE = "1"
    TWO = "2"


''' COMMAND FUNCTIONS '''


@metadata_collector.command(command_name="test-module")
def test_module(client: Client) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        return client.auth()
    except Exception as e:
        if any(x in str(e) for x in ["401", "Forbidden", "Authorization"]) or getattr(e.res, "status_code",
                                                                                      0) == 401:
            return 'Authorization Error: make sure username and password are correctly set'
        else:
            raise (e)


@metadata_collector.command(
    command_name='ip',
    description="Lookup reputation data for IP addresses.",
    multiple_output_prefixes=True,
    inputs_list=[
        InputArgument(name="ip", description="IP(s) to lookup.", required=True, is_array=True, default=True),
    ],
    outputs_list=[
        OutputArgument(name="Indicator", description="The indicator.", prefix="DBotScore"),
        OutputArgument(name="Type", description="The indicator type.", prefix="DBotScore"),
        OutputArgument(name="Vendor", description="The vendor.", prefix="DBotScore"),
        OutputArgument(name="Score", description="The DBot score.", prefix="DBotScore", output_type=int),

        OutputArgument(name="Description", description="The indicator context description",
                       prefix="IP.Malicious", output_type=str),
        OutputArgument(name="Vendor", description="The vendor that indicator context originated from.",
                       prefix="IP.Malicious", output_type=str),
        OutputArgument(name="Address", description="The IP address.", prefix="IP", output_type="str"),
        OutputArgument(
            name="isSafeUrl", description="Whether entity is deemed safe", prefix="iboss", output_type=int),
        OutputArgument(
            name="categories", description="The entity categories.", prefix="iboss", output_type=[str]),
        OutputArgument(
            name="activeMalwareSubscription", description="Whether active malware subscription is active",
            prefix="DBotScore", output_type=int),
        OutputArgument(
            name="categorized", description="Whether entity is categorized.", prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingDescription", description="Google safe browsing description",
            prefix="iboss", output_type=str),
        OutputArgument(name="message", description="Entity lookup message.", prefix="iboss", output_type=str),
        OutputArgument(name="url", description="The entity to perforum URL check on.", prefix="iboss",
                       output_type=str),
        OutputArgument(
            name="googleSafeBrowsingEnabled", description="Whether Google safe browsing is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingIsSafeUrl", description="Whether entity deemed safe by Google safe browsing.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingSuccess", description="Whether Google safe browsing check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingSupport", description="Whether Google safe browsing is supported", output_type=str),
        OutputArgument(
            name="malwareEngineAnalysisDescription", description="Malware engine analysis description",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="malwareEngineAnalysisEnabled", description="Whether the malware engine analysis is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineAnalysisSuccess",
            description="Whether the malware engine analysis check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineIsSafeUrl", description="Whether the entity was deemed safe by the malware engine.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineResultCode", description="The result code from the malware engine analysis",
            output_type=str),
        OutputArgument(
            name="realtimeCloudLookupDomainIsGrey", description="Whether realtime cloud lookup is grey.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupDomainEnabled", description="Whether realtime cloud lookup is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupIsSafeUrl", description="Whether realtime cloud lookup determined entity is safe.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupRiskDescription", description="Realtime cloud lookup risk description.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="realtimeCloudLookupSuccess", description="Whether realtime cloud lookup chec was successful.",
            output_type=int),
        OutputArgument(
            name="reputationDatabaseBotnetDetection", description="Whether reputation database detected a botnet.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseMalwareDetection", description="Whether reputation database detected malware.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseEnabled", description="Whether reputation database check is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseIsSafeUrl",
            description="Whether reputation database check determined entity is safe.", output_type=str),
        OutputArgument(
            name="reputationDatabaseLookupSuccess",
            description="Whether reputation database lookup was successful.", output_type=int),
        OutputArgument(
            name="webRequestHeuristicBlockUnreachableSites", description="Whether unreachable sites will be blocked.",
            output_type=int, prefix="iboss"),
        OutputArgument(
            name="webRequestHeuristicDescription", description="The web request heuristic description.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicIsSafeUrl", description="Whether web request heuristics determined URL is safe.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="webRequestHeuristicLevelHighScore", description="The web request heuristic score high threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelLowScore", description="The web request heuristic score low threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelMediumScore", description="The web request heuristic score low threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelNoneScore", description="The web request heuristic score none threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicProtectionActionHigh",
            description="The web request heuristic protection action high threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionActionLow",
            description="The web request heuristic protection action low threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionActionMedium",
            description="The web request heuristic protection action medium threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionLevel", description="The web request heuristic protection level.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicSuccess", description="Whether web request heuristic check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="webRequestHeuristicSupport", description="Whether web request heuristic support enabled.",
            prefix="iboss", output_type=int),
    ]
)
def ip_lookup(client: Client, args: Dict[str, Any]) -> [CommandResults]:
    """Looks up reputation data for IP addresses"""
    # TODO use get_ip
    ips = _get_validate_argument("ip", args, validator=lambda x: x and len(x) > 0, message="value is not specified")

    ips = argToList(ips)
    for ip in ips:
        if not is_ip_valid(ip):
            raise ValueError(f"ip ({ip}) - Is not valid IP")

    command_results = []
    for ip in ips:
        result = _iboss_ip_reputation(client, ip)
        command_result = CommandResults(
            readable_output=tableToMarkdown("Result", result, removeNull=True),
            outputs_key_field='message',
            outputs=result,
        )
        command_results.append(command_result)

    return command_results


@metadata_collector.command(
    command_name='domain',
    description="Lookup reputation for domain names.",
    multiple_output_prefixes=True,
    inputs_list=[
        InputArgument(name="domain", description="Domain(s) to lookup.", required=True, is_array=True),
    ],
    outputs_list=[
        OutputArgument(name="Indicator", description="The indicator.", prefix="DBotScore"),
        OutputArgument(name="Type", description="The indicator type.", prefix="DBotScore"),
        OutputArgument(name="Vendor", description="The vendor.", prefix="DBotScore"),
        OutputArgument(name="Score", description="The DBot score.", prefix="DBotScore", output_type=int),

        OutputArgument(name="Description", description="The indicator context description",
                       prefix="Domain.Malicious", output_type=str),
        OutputArgument(name="Vendor", description="The vendor that indicator context originated from.",
                       prefix="Domain.Malicious", output_type=str),
        OutputArgument(name="Name", description="The domain.", prefix="Domain", output_type="str"),
        OutputArgument(
            name="isSafeUrl", description="Whether entity is deemed safe", prefix="iboss", output_type=int),
        OutputArgument(
            name="categories", description="The entity categories.", prefix="iboss", output_type=[str]),
        OutputArgument(
            name="activeMalwareSubscription", description="Whether active malware subscription is active",
            prefix="DBotScore", output_type=int),
        OutputArgument(
            name="categorized", description="Whether entity is categorized.", prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingDescription", description="Google safe browsing description",
            prefix="iboss", output_type=str),
        OutputArgument(name="message", description="Entity lookup message.", prefix="iboss", output_type=str),
        OutputArgument(name="url", description="The entity to perforum URL check on.", prefix="iboss",
                       output_type=str),
        OutputArgument(
            name="googleSafeBrowsingEnabled", description="Whether Google safe browsing is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingIsSafeUrl", description="Whether entity deemed safe by Google safe browsing.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingSuccess", description="Whether Google safe browsing check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingSupport", description="Whether Google safe browsing is supported", output_type=str),
        OutputArgument(
            name="malwareEngineAnalysisDescription", description="Malware engine analysis description",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="malwareEngineAnalysisEnabled", description="Whether the malware engine analysis is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineAnalysisSuccess",
            description="Whether the malware engine analysis check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineIsSafeUrl", description="Whether the entity was deemed safe by the malware engine.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineResultCode", description="The result code from the malware engine analysis",
            output_type=str),
        OutputArgument(
            name="realtimeCloudLookupDomainIsGrey", description="Whether realtime cloud lookup is grey.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupDomainEnabled", description="Whether realtime cloud lookup is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupIsSafeUrl", description="Whether realtime cloud lookup determined entity is safe.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupRiskDescription", description="Realtime cloud lookup risk description.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="realtimeCloudLookupSuccess", description="Whether realtime cloud lookup chec was successful.",
            output_type=int),
        OutputArgument(
            name="reputationDatabaseBotnetDetection", description="Whether reputation database detected a botnet.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseMalwareDetection", description="Whether reputation database detected malware.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseEnabled", description="Whether reputation database check is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseIsSafeUrl",
            description="Whether reputation database check determined entity is safe.", output_type=str),
        OutputArgument(
            name="reputationDatabaseLookupSuccess",
            description="Whether reputation database lookup was successful.", output_type=int),
        OutputArgument(
            name="webRequestHeuristicBlockUnreachableSites", description="Whether unreachable sites will be blocked.",
            output_type=int, prefix="iboss"),
        OutputArgument(
            name="webRequestHeuristicDescription", description="The web request heuristic description.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicIsSafeUrl", description="Whether web request heuristics determined URL is safe.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="webRequestHeuristicLevelHighScore", description="The web request heuristic score high threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelLowScore", description="The web request heuristic score low threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelMediumScore", description="The web request heuristic score low threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelNoneScore", description="The web request heuristic score none threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicProtectionActionHigh",
            description="The web request heuristic protection action high threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionActionLow",
            description="The web request heuristic protection action low threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionActionMedium",
            description="The web request heuristic protection action medium threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionLevel", description="The web request heuristic protection level.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicSuccess", description="Whether web request heuristic check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="webRequestHeuristicSupport", description="Whether web request heuristic support enabled.",
            prefix="iboss", output_type=int),
    ]
)
def domain_lookup(client: Client, args: Dict[str, Any]) -> [CommandResults]:
    """Looks up reputation data for domain"""

    domains = _get_validate_argument(
        "domain", args, validator=lambda x: x and len(x) > 0, message="value is not specified")

    command_results = []
    for domain in argToList(domains):
        result = _iboss_domain_reputation(client, domain)
        command_result = CommandResults(
            readable_output=tableToMarkdown("Result", result, removeNull=True),
            outputs_key_field='message',
            outputs=result,
        )
        command_results.append(command_result)
    return command_results


@metadata_collector.command(
    command_name='url',
    description="Lookup reputation data for URLs.",
    multiple_output_prefixes=True,
    inputs_list=[
        InputArgument(name="url", description="URL(s) to lookup.", required=True, is_array=True),
    ],
    outputs_list=[
        OutputArgument(name="Indicator", description="The indicator.", prefix="DBotScore"),
        OutputArgument(name="Type", description="The indicator type.", prefix="DBotScore"),
        OutputArgument(name="Vendor", description="The vendor.", prefix="DBotScore"),
        OutputArgument(name="Score", description="The DBot score.", prefix="DBotScore", output_type=int),

        OutputArgument(name="Description", description="The indicator context description",
                       prefix="URL.Malicious", output_type=str),
        OutputArgument(name="Vendor", description="The vendor that indicator context originated from.",
                       prefix="URL.Malicious", output_type=str),
        OutputArgument(name="Data", description="The URL.", prefix="URL", output_type="str"),
        OutputArgument(
            name="isSafeUrl", description="Whether entity is deemed safe", prefix="iboss", output_type=int),
        OutputArgument(
            name="categories", description="The entity categories.", prefix="iboss", output_type=[str]),
        OutputArgument(
            name="activeMalwareSubscription", description="Whether active malware subscription is active",
            prefix="DBotScore", output_type=int),
        OutputArgument(
            name="categorized", description="Whether entity is categorized.", prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingDescription", description="Google safe browsing description",
            prefix="iboss", output_type=str),
        OutputArgument(name="message", description="Entity lookup message.", prefix="iboss", output_type=str),
        OutputArgument(name="url", description="The entity to perforum URL check on.", prefix="iboss",
                       output_type=str),
        OutputArgument(
            name="googleSafeBrowsingEnabled", description="Whether Google safe browsing is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingIsSafeUrl", description="Whether entity deemed safe by Google safe browsing.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingSuccess", description="Whether Google safe browsing check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="googleSafeBrowsingSupport", description="Whether Google safe browsing is supported", output_type=str),
        OutputArgument(
            name="malwareEngineAnalysisDescription", description="Malware engine analysis description",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="malwareEngineAnalysisEnabled", description="Whether the malware engine analysis is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineAnalysisSuccess",
            description="Whether the malware engine analysis check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineIsSafeUrl", description="Whether the entity was deemed safe by the malware engine.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="malwareEngineResultCode", description="The result code from the malware engine analysis",
            output_type=str),
        OutputArgument(
            name="realtimeCloudLookupDomainIsGrey", description="Whether realtime cloud lookup is grey.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupDomainEnabled", description="Whether realtime cloud lookup is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupIsSafeUrl", description="Whether realtime cloud lookup determined entity is safe.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="realtimeCloudLookupRiskDescription", description="Realtime cloud lookup risk description.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="realtimeCloudLookupSuccess", description="Whether realtime cloud lookup chec was successful.",
            output_type=int),
        OutputArgument(
            name="reputationDatabaseBotnetDetection", description="Whether reputation database detected a botnet.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseMalwareDetection", description="Whether reputation database detected malware.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseEnabled", description="Whether reputation database check is enabled.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="reputationDatabaseIsSafeUrl",
            description="Whether reputation database check determined entity is safe.", output_type=str),
        OutputArgument(
            name="reputationDatabaseLookupSuccess",
            description="Whether reputation database lookup was successful.", output_type=int),
        OutputArgument(
            name="webRequestHeuristicBlockUnreachableSites", description="Whether unreachable sites will be blocked.",
            output_type=int, prefix="iboss"),
        OutputArgument(
            name="webRequestHeuristicDescription", description="The web request heuristic description.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicIsSafeUrl", description="Whether web request heuristics determined URL is safe.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="webRequestHeuristicLevelHighScore", description="The web request heuristic score high threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelLowScore", description="The web request heuristic score low threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelMediumScore", description="The web request heuristic score low threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicLevelNoneScore", description="The web request heuristic score none threshold.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicProtectionActionHigh",
            description="The web request heuristic protection action high threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionActionLow",
            description="The web request heuristic protection action low threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionActionMedium",
            description="The web request heuristic protection action medium threshold.", prefix="iboss",
            output_type=int),
        OutputArgument(
            name="webRequestHeuristicProtectionLevel", description="The web request heuristic protection level.",
            prefix="iboss", output_type=str),
        OutputArgument(
            name="webRequestHeuristicSuccess", description="Whether web request heuristic check was successful.",
            prefix="iboss", output_type=int),
        OutputArgument(
            name="webRequestHeuristicSupport", description="Whether web request heuristic support enabled.",
            prefix="iboss", output_type=int),
    ]
)
def url_lookup(client: Client, args: Dict[str, Any]) -> [CommandResults]:
    urls = _get_validate_argument("url", args, validator=lambda x: x and len(x) > 0, message="value is not specified")

    command_results = []
    for url in argToList(urls):
        result = _iboss_url_reputation(client, url)
        command_result = CommandResults(
            readable_output=tableToMarkdown("Result", result, removeNull=True),
            outputs_key_field='message',
            outputs=result,
        )
        command_results.append(command_result)

    return command_results


@metadata_collector.command(
    command_name='iboss-add-entity-to-block-list', outputs_prefix='iboss.AddEntityToBlockList',
    description="Adds domains, IPs, and/or URLs to a block list.",
    inputs_list=[
        InputArgument(name="entity", description="Domains, IPs, and/or URLs to add to the block list.", required=True,
                      is_array=True),
        InputArgument(name="current_policy_being_edited", description="The group/policy number to update.",
                      default="1"),
        InputArgument(name="allow_keyword", description="Whether to enforce blocked keywords.",
                      options=["0", "1"], default="0"),
        InputArgument(name="direction", description="Which direction(s) to match.", options=["0", "1", "2"],
                      default="2"),
        InputArgument(name="start_port", description="Which start port(s) to match; 0 indicates all ports.",
                      default="0"),
        InputArgument(name="end_port", description="Which end port(s) to match; 0 indicates all ports.",
                      default="0"),
        InputArgument(name="global", description="Whether to apply to all groups.", options=["0", "1"], default="0"),
        InputArgument(name="is_regex", description="Whether entity consists of a regex pattern.", options=["0", "1"],
                      default="0"),
        InputArgument(
            name="priority",
            description="Priority of entry (higher number takes precedence) when conflicting entry in the block list.",
            default="0"),
        InputArgument(
            name="time_url_expires_in_minutes",
            description="The expiration time in minutes for the entry (0 indicates an entry that does not expire).",
            default="0"),
        InputArgument(name="note", description="Note added to the entry.", required=False),
    ],
    outputs_list=[
        OutputArgument(name="message", description="Operation result.", output_type=str),
    ]
)
def add_entity_to_block_list_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    """Adds domains, IPs, and/or URLs to a block list
    """
    """
    Args:
        client (Client): iboss client to use.
        entity (str): required. Domains, IPs, and/or URLs to add to a block list.
        current_policy_being_edited: required. The group/policy number to update. defaultValue=1.
        allow_keyword (ZeroOneEnum): Whether to enforced blocked keywords. Options=[0, 1]. defaultValue=0.
        direction: Which direction(s) to match. Options=[0, 1, 2]. defaultValue=2.
        start_port (ZeroOneTwoEnum): Which start port(s) to match. 0 indicates all ports. defaultValue=0.
        end_port (ZeroOneTwoEnum): Which end ports(s) to match. 0 indicates all ports. defaultValue=0.
        global (ZeroOneEnum): Whether to apply to all groups. defaultValue=0. Options=[0, 1]. defaultValue=0
        is_regex (ZeroOneEnum): Whether entity consists of a regex pattern. Options=[0, 1]. defaultValue=0
        priority: Priority of entry (higher number takes precedence) when conflicting entry in allow list. defaultValue=0
        time_url_expires_in_minutes: The expiration time in minutes for the entry (0 indicates an entry that does not expire). defaultValue=0.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``, that contains the update result of the entry.

    Context Outputs:
        message (str): Update result.
    """

    # entity = args.get('entity')
    entities = _get_validate_argument("entity", args, validator=lambda x: x and len(x) > 0,
                                      message="value is not specified")

    current_policy_being_edited = _get_validate_argument(
        "current_policy_being_edited", args, validator=lambda x: (x or x == 0) and x > 0, message="value must be >= 0",
        return_type=int)
    allow_keyword = _get_validate_argument(
        "allow_keyword", args, validator=lambda x: x in [0, 1], message="value must be 0 or 1",
        return_type=int)
    direction = _get_validate_argument(
        "direction", args, validator=lambda x: x in [0, 1, 2], message="value must be 0, 1, or 2", return_type=int)
    end_port = _get_validate_argument(
        "end_port", args, validator=lambda x: (x or x == 0) and x >= 0, message="value must be >= 0", return_type=int)
    apply_global = _get_validate_argument(
        "global", args, validator=lambda x: x in [0, 1], message="value must be 0 or 1", return_type=int)
    is_regex = _get_validate_argument(
        "is_regex", args, validator=lambda x: x in [0, 1], message="value must be 0 or 1", return_type=int)
    priority = _get_validate_argument(
        "priority", args, validator=lambda x: (x or x == 0) and x >= 0, message="value must be >= 0", return_type=int)
    start_port = _get_validate_argument(
        "start_port", args, validator=lambda x: (x or x == 0) and x >= 0, message="value must be >= 0", return_type=int)
    time_url_expires_in_minutes = _get_validate_argument(
        "time_url_expires_in_minutes", args, validator=lambda x: (x or x == 0) and x >= 0, message="value must be >= 0",
        return_type=int)
    is_timed_url = 0
    if time_url_expires_in_minutes > 0:
        is_timed_url = 1

    note = _get_validate_argument("note", args)

    # Initialize an empty list of CommandResults to return,
    # each CommandResult will contain context standard for Domain
    command_results = []

    for entry in argToList(entities):
        result = client.add_entity_to_block_list(
            url=entry, current_policy_being_edited=current_policy_being_edited,
            allow_keyword=allow_keyword,
            direction=direction, end_port=end_port, apply_global=apply_global, is_regex=is_regex,
            is_timed_url=is_timed_url, note=note,
            priority=priority, start_port=start_port, time_url_expires_in_minutes=time_url_expires_in_minutes)
        command_results.append(CommandResults(
            readable_output=result['message'],
            outputs_prefix='iboss.AddEntityToBlockList',
            outputs_key_field='message',
            outputs=result,
        ))

    return command_results


@metadata_collector.command(
    command_name='iboss-remove-entity-from-block-list',
    description="Removes domains, IPs, and/or URLs to a block list.",
    outputs_prefix='iboss.RemoveEntityFromBlockList',
    inputs_list=[
        InputArgument(name="entity", description="Domains, IPs, and/or URLs to remove from a block list.",
                      required=True,
                      is_array=True),
        InputArgument(name="current_policy_being_edited", description="The group/policy number to update.", default="1")
    ],
    outputs_list=[
        OutputArgument(name="message", description="Operation result.", output_type=str)
    ])
def remove_entity_from_block_list_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    """Removes entities from a block list

     Args:
        client (Client): iboss client to use.
        entity: required. Domains, IPs, and/or URLs to remove from a block list.
        current_policy_being_edited: required. The group/policy number to update. defaultValue=1.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``, that contains the status of the removed entity.

    Context Outputs:
        message (str): Update result.
    """

    entities = _get_validate_argument(
        "entity", args, validator=lambda x: x and len(x) > 0, message="value is not specified")

    current_policy_being_edited = _get_validate_argument(
        "current_policy_being_edited", args, validator=lambda x: (x or x == 0) and x > 0, message="value must be >= 0",
        return_type=int)

    command_results = []
    for entry in argToList(entities):
        result = client.remove_entity_from_block_list(url=entry,
                                                      current_policy_being_edited=current_policy_being_edited)

        # Update with friendlier message when user attempts to remove entry that is not present on list
        if result.get("errorCode", -1) == 0 and result.get("message", "") == "Failed to remove URL.":
            result["message"] = "URL not found in list."

        command_results.append(CommandResults(
            readable_output=result["message"],
            outputs_prefix="iboss.RemoveEntityFromBlockList",
            outputs_key_field="message",
            outputs=result,
        ))

    return command_results


@metadata_collector.command(
    command_name='iboss-add-entity-to-allow-list', outputs_prefix='iboss.AddEntityToAllowList',
    description="Adds domains, IPs, and/or URLs to an allow list.",
    inputs_list=[
        InputArgument(name="entity", description="Domains, IPs, and/or URLs to add to an allow list.", required=True,
                      is_array=True),
        InputArgument(name="current_policy_being_edited", description="The group/policy number to update.",
                      default="1"),
        InputArgument(name="allow_keyword", description="Whether to enforce blocked keywords.",
                      options=["0", "1"], default="0"),
        InputArgument(name="direction", description="Which direction(s) to match.", options=["0", "1", "2"],
                      default="2"),
        InputArgument(name="start_port", description="Which start port(s) to match; 0 indicates all ports.",
                      default="0"),
        InputArgument(name="end_port", description="Which end port(s) to match; 0 indicates all ports.",
                      default="0"),
        InputArgument(name="global", description="Whether to apply to all groups.", options=["0", "1"], default="0"),
        InputArgument(name="is_regex", description="Whether entity consists of a regex pattern.", options=["0", "1"],
                      default="0"),
        InputArgument(
            name="priority",
            description="Priority of entry (higher number takes precedence) when conflicting entry in allow list.",
            default="0"),
        InputArgument(
            name="time_url_expires_in_minutes",
            description="The expiration time in minutes for the entry (0 indicates an entry that does not expire).",
            default="0"),
        InputArgument(name="note", description="Note added to the entry.", required=False),
    ],
    outputs_list=[
        OutputArgument(name="message", description="Operation result.", output_type=str),
    ]
)
def add_entity_to_allow_list_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    """Adds domains, IPs, and/or URLs to an allow list

    Args:
        client (Client): iboss client to use.
        entity: required. Domains, IPs, and/or URLs to add to an allow list.
        current_policy_being_edited: required. The group/policy number to update. defaultValue=1.
        allow_keyword (ZeroOneEnum): Whether to enforced blocked keywords. Options=[0, 1]. defaultValue=0.
        direction: Which direction(s) to match. Options=[0, 1, 2]. defaultValue=2.
        start_port (ZeroOneTwoEnum): Which start port(s) to match. 0 indicates all ports. defaultValue=0.
        end_port (ZeroOneTwoEnum): Which end ports(s) to match. 0 indicates all ports. defaultValue=0.
        global (ZeroOneEnum): Whether to apply to all groups. defaultValue=0. Options=[0, 1]. defaultValue=0
        is_regex (ZeroOneEnum): Whether entity consists of a regext pattern. Options=[0, 1]. defaultValue=0
        time_url_expires_in_minutes: The expiration time in minutes for the entry (0 indicates an entry that does not expire). defaultValue=0.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``, that contains the update result of the entry.

    Context Outputs:
        message (str): Update result.
    """

    # entity = args.get('entity')
    entities = _get_validate_argument(
        "entity", args, validator=lambda x: x and len(x) > 0, message="value is not specified")

    current_policy_being_edited = _get_validate_argument(
        "current_policy_being_edited", args, validator=lambda x: (x or x == 0) and x > 0, message="value must be >= 0",
        return_type=int)
    allow_keyword = _get_validate_argument(
        "allow_keyword", args, validator=lambda x: x in [0, 1], message="value must be 0 or 1",
        return_type=int)
    direction = _get_validate_argument(
        "direction", args, validator=lambda x: x in [0, 1, 2], message="value must be 0, 1, or 2", return_type=int)
    end_port = _get_validate_argument(
        "end_port", args, validator=lambda x: (x or x == 0) and x >= 0, message="value must be >= 0", return_type=int)
    apply_global = _get_validate_argument(
        "global", args, validator=lambda x: x in [0, 1], message="value must be 0 or 1", return_type=int)
    is_regex = _get_validate_argument(
        "is_regex", args, validator=lambda x: x in [0, 1], message="value must be 0 or 1", return_type=int)
    note = _get_validate_argument("note", args)
    priority = _get_validate_argument(
        "priority", args, validator=lambda x: (x or x == 0) and x >= 0, message="value must be >= 0", return_type=int)
    start_port = _get_validate_argument(
        "start_port", args, validator=lambda x: (x or x == 0) and x >= 0, message="value must be >= 0", return_type=int)
    time_url_expires_in_minutes = _get_validate_argument(
        "time_url_expires_in_minutes", args, validator=lambda x: (x or x == 0) and x >= 0, message="value must be >= 0",
        return_type=int)
    is_timed_url = 0
    if time_url_expires_in_minutes > 0:
        is_timed_url = 1

    # Initialize an empty list of CommandResults to return,
    # each CommandResult will contain context standard for Domain
    command_results = []

    for entry in argToList(entities):
        result = client.add_entity_to_allow_list(
            url=entry, current_policy_being_edited=current_policy_being_edited,
            allow_keyword=allow_keyword,
            direction=direction, end_port=end_port, apply_global=apply_global, is_regex=is_regex,
            is_timed_url=is_timed_url, note=note,
            priority=priority, start_port=start_port, time_url_expires_in_minutes=time_url_expires_in_minutes)

        command_results.append(CommandResults(
            readable_output=result['message'],
            outputs_prefix='iboss.AddEntityToAllowList',
            outputs_key_field='message',
            outputs=result,
        ))

    return command_results


@metadata_collector.command(
    command_name='iboss-remove-entity-from-allow-list',
    outputs_prefix='iboss.RemoveEntityFromAllowList',
    description="Removes domains, IPs, and/or URLs from an allow list",
    inputs_list=[
        InputArgument(name="entity", description="Domains, IPs, and/or URLs to remove from an allow list.",
                      required=True,
                      is_array=True),
        InputArgument(name="current_policy_being_edited", description="The group/policy number to update.", default="1")
    ],
    outputs_list=[
        OutputArgument(name="message", description="Operation result.", output_type=str)
    ])
def remove_entity_from_allow_list_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    """Removes entities from an allow list

     Args:
        client (Client): iboss client to use.
        entity: required. Domains, IPs, and/or URLs to remove from an allow list.
        current_policy_being_edited: required. The group/policy number to update. defaultValue=1.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``, that contains the status of the removed entity.

    Context Outputs:
        message (str): Update result.
    """

    entities = _get_validate_argument(
        "entity", args, validator=lambda x: x and len(x) > 0, message="value is not specified")

    current_policy_being_edited = _get_validate_argument(
        "current_policy_being_edited", args, validator=lambda x: (x or x == 0) and x > 0, message="value must be >= 0",
        return_type=int)

    command_results = []
    for entry in argToList(entities):
        result = client.remove_entity_from_allow_list(
            url=entry,
            current_policy_being_edited=current_policy_being_edited)

        # Update with friendlier message when user attempts to remove entry that is not present on list
        if result.get("errorCode", -1) == 0 and result.get("message", "") == "Failed to remove URL.":
            result["message"] = "URL not found in list."

        command_results.append(CommandResults(
            readable_output=result['message'],
            outputs_prefix='iboss.RemoveEntityFromAllowList',
            outputs_key_field='message',
            outputs=result,
        ))

    return command_results


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """

    demisto.debug("Enter MAIN method")

    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    username = params.get('auth', {}).get('identifier')
    password = params.get('auth', {}).get('password')
    account_settings_id = params.get('account_settings_id')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            username=username,
            password=password,
            account_settings_id=account_settings_id,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'ip':
            return_results(ip_lookup(client, args))
        elif command == 'url':
            return_results(url_lookup(client, args))
        elif command == 'domain':
            return_results(domain_lookup(client, args))
        elif command == 'iboss-add-entity-to-block-list':
            return_results(add_entity_to_block_list_command(client, args))
        elif command == 'iboss-remove-entity-from-block-list':
            return_results(remove_entity_from_block_list_command(client, args))
        elif command == 'iboss-add-entity-to-allow-list':
            return_results(add_entity_to_allow_list_command(client, args))
        elif command == 'iboss-remove-entity-from-allow-list':
            return_results(remove_entity_from_allow_list_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
