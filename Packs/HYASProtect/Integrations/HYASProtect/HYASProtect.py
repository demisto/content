from CommonServerPython import *

import urllib3
# Disable insecure warnings
urllib3.disable_warnings()

# CORTEX XSOAR COMMAND CONSTANTS
INTEGRATION_NAME = 'HYAS PROTECT'
INTEGRATION_COMMAND_NAME = 'hyas'
INTEGRATION_CONTEXT_NAME = 'HYAS'
DOMAIN_VERDICT_SUB_CONTEXT = 'DomainVerdict'
IP_VERDICT_SUB_CONTEXT = "IPVerdict"
NAMESERVER_VERDICT_SUB_CONTEXT = "NameserverVerdict"
FQDN_VERDICT_SUB_CONTEXT = "FQDNVerdict"

# HYAS API BASE URL
HYAS_API_BASE_URL = 'https://api.hyas.com/protect/'
TIMEOUT = 60

# HYAS API endpoints
DOMAIN_ENDPOINT = 'domain'
IP_ENDPOINT = "ip"
FQDN_ENDPOINT = "fqdn"
NAMESERVER_ENDPOINT = "nameserver"

# HYAS API INPUT PARAMETERS
DOMAIN_PARAM = 'domain'
IP_PARAM = 'ip'
FQDN_PARAM = "fqdn"
NAMESERVER_PARAM = "nameserver"


def to_demisto_score(verdict: str):
    if verdict.lower() == "deny":
        return Common.DBotScore.BAD
    if verdict.lower() == "suspicious":
        return Common.DBotScore.SUSPICIOUS
    if verdict.lower() == "allow":
        return Common.DBotScore.GOOD
    return Common.DBotScore.NONE


class Client(BaseClient):
    def __init__(self, base_url: str, apikey: str, verify=None, proxy=None):
        BaseClient.__init__(
            self,
            base_url,
            verify=verify,
            headers={
                'Content-type': 'application/json',
                'X-API-Key': apikey,
                'User-Agent': 'Cortex XSOAR'
            },
            proxy=proxy,
            ok_codes=(200,),
        )
        self.apikey = apikey

    def fetch_data_from_hyas_api(self, end_point: str, ind_value: str) -> Dict:
        """
        :param end_point: HYAS endpoint
        :param ind_value: indicator_value provided in the command
        :return: return the raw api response from HYAS API.
        """
        return self.query(end_point, ind_value)

    def query(self, end_point: str, ind_value: str) -> Dict:
        """
        :param end_point: HYAS endpoint
        :param ind_value: indicator_value provided in the command
        :return: return the raw api response from HYAS API.
        """
        url_path = f'{end_point}/{ind_value}'
        response = self._http_request(
            'GET',
            url_suffix=url_path,
            timeout=TIMEOUT
        )
        return response

    def test_module(self) -> str:
        """
        :return: connection ok

        """

        try:
            self.query(DOMAIN_ENDPOINT, "www.hyas.com")
        except DemistoException as e:
            if '401' in str(e):
                return 'Authorization Error: Provided apikey is not valid'
            else:
                raise e
        return 'ok'


def check_valid_indicator_value(indicator_type: str,
                                indicator_value: str) -> bool:
    """

    :param indicator_type: Indicator type provided in the command
    :param indicator_value: Indicator value provided in the command
    :return: true if the indicator value provided for the indicator
     type is valid

    """
    # not using default urlRegex for domain validation
    # as it is failing in some cases, for example
    # 'fluber12.duckdns.org' is validated as invalid
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)'  # Sub domain + hostname
        r'+[A-Za-z0-9][A-Za-z0-9-_]{0,61}'  # First 61 characters of the gTLD
        r'[A-Za-z]$'  # Last character of the gTLD
    )

    if indicator_type == NAMESERVER_PARAM:
        if not re.match(domain_regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value}'
                f' for indicator_type {indicator_type}'
            )
    elif indicator_type == FQDN_PARAM:
        if not re.match(domain_regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value}'
                f' for indicator_type {indicator_type}'
            )
    elif indicator_type == DOMAIN_PARAM:
        if not re.match(domain_regex, indicator_value):
            raise ValueError(
                f'Invalid indicator_value: {indicator_value}'
                f' for indicator_type {indicator_type}')
    elif indicator_type == IP_PARAM:
        if not re.match(ipv4Regex, indicator_value):
            if not re.match(ipv6Regex, indicator_value):
                raise ValueError(
                    f'Invalid indicator_value: {indicator_value}'
                    f' for indicator_type {indicator_type}')
            raise ValueError(
                f'Invalid indicator_value: {indicator_value}'
                f' for indicator_type {indicator_type}')

    return True


def get_command_title_string(sub_context: str, indicator_type: str,
                             indicator_value: str) -> str:
    """

    :param sub_context: Commands sub_context
    :param indicator_type: Indicator type provided in the command
    :param indicator_value: Indicator value provided in the command
    :return: returns the title for the readable output

    """
    return INTEGRATION_CONTEXT_NAME + " " + sub_context + " verdict for " + indicator_value


@logger
def indicator_verdict_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('verdict', 'verdict', str),
            ('reasons', 'reasons', list),
    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    return ctx


@logger
def indicator_verdict_lookup_to_markdown(results: dict, title: str) -> str:
    out = []
    row = {
        "Verdict": results.get("verdict"),
        "Reasons": results.get("reasons")
    }
    out.append(row)

    return tableToMarkdown(title, out, headers=["Verdict", "Reasons"],
                           removeNull=True)


@logger
def get_domain_verdict(client, args):
    indicator_type = DOMAIN_PARAM
    indicator_value = args.get('domain')

    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string("Domain", indicator_type, indicator_value)

    raw_api_response = client.fetch_data_from_hyas_api(DOMAIN_ENDPOINT,
                                                       indicator_value)
    verdict = raw_api_response.get("verdict")
    db_score = ""
    if verdict:
        db_score = to_demisto_score(verdict)

    dbot_score = Common.DBotScore(
        indicator=indicator_value, indicator_type=DBotScoreType.DOMAIN,
        integration_name=INTEGRATION_CONTEXT_NAME, score=db_score,
        malicious_description=raw_api_response.get("reasons") if raw_api_response.get(
            "reasons") else None
    )
    domain = Common.Domain(domain=indicator_value, dbot_score=dbot_score)

    return CommandResults(
        readable_output=indicator_verdict_lookup_to_markdown(raw_api_response,
                                                             title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{DOMAIN_VERDICT_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=[indicator_verdict_result_context(raw_api_response)],
        indicator=domain
    )


@logger
def get_ip_verdict(client, args):
    indicator_type = IP_PARAM
    indicator_value = args.get('ip')

    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string("IP", indicator_type, indicator_value)

    raw_api_response = client.fetch_data_from_hyas_api(IP_ENDPOINT,
                                                       indicator_value)
    verdict = raw_api_response.get("verdict")
    db_score = ""
    if verdict:
        db_score = to_demisto_score(verdict)

    dbot_score = Common.DBotScore(indicator=indicator_value, indicator_type=DBotScoreType.IP,
                                  integration_name=INTEGRATION_CONTEXT_NAME, score=db_score,
                                  malicious_description=raw_api_response.get("reasons") if raw_api_response.get(
                                      "reasons") else None)
    ip = Common.IP(ip=indicator_value, dbot_score=dbot_score)

    return CommandResults(
        readable_output=indicator_verdict_lookup_to_markdown(raw_api_response,
                                                             title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{IP_VERDICT_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=[indicator_verdict_result_context(raw_api_response)],
        indicator=ip,
    )


@logger
def get_fqdn_verdict(client, args):
    indicator_type = FQDN_PARAM
    indicator_value = args.get('fqdn')

    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string("FQDN", indicator_type, indicator_value)

    raw_api_response = client.fetch_data_from_hyas_api(FQDN_ENDPOINT,
                                                       indicator_value)
    verdict = raw_api_response.get("verdict")
    db_score = ""
    if verdict:
        db_score = to_demisto_score(verdict)

    dbot_score = Common.DBotScore(
        indicator=indicator_value, indicator_type=DBotScoreType.DOMAIN,
        integration_name=INTEGRATION_CONTEXT_NAME, score=db_score, malicious_description=raw_api_response.get("reasons")
        if raw_api_response.get("reasons") else None
    )
    fqdn = Common.Domain(domain=indicator_value, dbot_score=dbot_score)
    return CommandResults(
        readable_output=indicator_verdict_lookup_to_markdown(raw_api_response,
                                                             title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{FQDN_VERDICT_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=[indicator_verdict_result_context(raw_api_response)],
        indicator=fqdn
    )


@logger
def get_nameserver_verdict(client, args):
    indicator_type = NAMESERVER_PARAM
    indicator_value = args.get('nameserver')

    check_valid_indicator_value(indicator_type, indicator_value)
    title = get_command_title_string("Nameserver", indicator_type,
                                     indicator_value)

    raw_api_response = client.fetch_data_from_hyas_api(NAMESERVER_ENDPOINT,
                                                       indicator_value)
    return CommandResults(
        readable_output=indicator_verdict_lookup_to_markdown(raw_api_response,
                                                             title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{NAMESERVER_VERDICT_SUB_CONTEXT}',
        outputs_key_field='',
        outputs=[indicator_verdict_result_context(raw_api_response)],
    )


@logger
def test_module(client):
    return client.test_module()


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    apikey = demisto.params().get('X-API-Key')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    try:
        client = Client(
            HYAS_API_BASE_URL,
            apikey,
            verify=verify_certificate,
            proxy=proxy)

        command = demisto.command()
        LOG(f'Command being called is {command}')
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-domain-verdict':
            return_results(get_domain_verdict(client, demisto.args()))
        elif command == f"{INTEGRATION_COMMAND_NAME}-get-ip-verdict":
            return_results(get_ip_verdict(client, demisto.args()))
        elif command == f"{INTEGRATION_COMMAND_NAME}-get-fqdn-verdict":
            return_results(get_fqdn_verdict(client, demisto.args()))
        elif command == f"{INTEGRATION_COMMAND_NAME}-get-nameserver-verdict":
            return_results(get_nameserver_verdict(client, demisto.args()))
    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
