import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib.parse
import warnings
from CommonServerUserPython import *

''' IMPORTS '''

# Disable insecure warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'{ip}'
        )

    def get_email_reputation(self, email: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'{email}'
        )

    def get_url_reputation(self, url: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'{url}'
        )


def get_reputation_reliability(reliability):
    if reliability == "A+ - 3rd party enrichment":
        return DBotScoreReliability.A_PLUS
    if reliability == "A - Completely reliable":
        return DBotScoreReliability.A
    if reliability == "B - Usually reliable":
        return DBotScoreReliability.B
    if reliability == "C - Fairly reliable":
        return DBotScoreReliability.C
    if reliability == "D - Not usually reliable":
        return DBotScoreReliability.D
    if reliability == "E - Unreliable":
        return DBotScoreReliability.E
    if reliability == "F - Reliability cannot be judged":
        return DBotScoreReliability.F


def test_module(client):
    result = client.get_ip_reputation("8.8.8.8")
    if result.get('success', False):
        return 'ok'
    else:
        return result.get("message", result)


def ip_command(client, args, ip_suspicious_score_threshold, ip_malicious_score_threshold, reliability):
    ips = argToList(args.get("ip"), ",")
    results = []
    for ip in ips:
        result = client.get_ip_reputation(ip)
        result['address'] = ip

        human_readable = tableToMarkdown(f"IPQualityScore Results for {ip}", result, result.keys())

        if result.get('fraud_score', 0) >= ip_malicious_score_threshold:
            score = 3
        elif result.get('fraud_score', 0) >= ip_suspicious_score_threshold:
            score = 2
        else:
            score = 0

        reputation = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            score=score,
            integration_name='IPQualityScore',
            reliability=get_reputation_reliability(reliability)
        )

        ip_context = Common.IP(
            ip=ip,
            dbot_score=reputation,
            asn=result.get('ASN'),
            hostname=result.get('host'),
            geo_country=result.get('country_code'),
            geo_longitude=result.get('longitude'),
            geo_latitude=result.get('latitude')
        )

        results.append(CommandResults(
            readable_output=human_readable,
            indicator=ip_context,
            outputs_prefix='IPQualityScore.IP',
            outputs_key_field='address',
            outputs=result,
            raw_response=result))
    return results


def email_command(client, args, email_suspicious_score_threshold, email_malicious_score_threshold, reliability):
    emails = argToList(args.get("email"), ",")
    results = []
    for email in emails:
        email_encoded = urllib.parse.quote(email, safe="")
        result = client.get_email_reputation(email_encoded)
        result['address'] = email

        human_readable = tableToMarkdown(f"IPQualityScore Results for {email}", result, result.keys())

        if result.get('fraud_score', 0) >= email_malicious_score_threshold:
            score = 3
        elif result.get('fraud_score', 0) >= email_suspicious_score_threshold:
            score = 2
        else:
            score = 0

        reputation = Common.DBotScore(
            indicator=email,
            indicator_type=DBotScoreType.EMAIL,
            score=score,
            integration_name='IPQualityScore',
            reliability=get_reputation_reliability(reliability)
        )

        ip_context = Common.EMAIL(
            address=email,
            dbot_score=reputation,
            domain=result.get('sanitized_email', email).split("@")[-1]
        )

        results.append(CommandResults(
            readable_output=human_readable,
            indicator=ip_context,
            outputs_prefix='IPQualityScore.Email',
            outputs_key_field='address',
            outputs=result,
            raw_response=result))
    return results


def url_command(client, args, url_suspicious_score_threshold, url_malicious_score_threshold, reliability):
    urls = argToList(args.get("url"), ",")
    results = []
    for url in urls:
        url_encoded = urllib.parse.quote(url, safe="")
        result = client.get_url_reputation(url_encoded)
        result['url'] = url

        human_readable = tableToMarkdown(f"IPQualityScore Results for {url}", result, result.keys())

        if result.get('risk_score', 0) >= url_malicious_score_threshold:
            score = 3
        elif result.get('risk_score', 0) >= url_suspicious_score_threshold:
            score = 2
        else:
            score = 0

        reputation = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            score=score,
            integration_name='IPQualityScore',
            reliability=get_reputation_reliability(reliability)
        )

        ip_context = Common.URL(
            url=url,
            dbot_score=reputation
        )

        results.append(CommandResults(
            readable_output=human_readable,
            indicator=ip_context,
            outputs_prefix='IPQualityScore.Url',
            outputs_key_field='url',
            outputs=result,
            raw_response=result))
    return results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    apikey = demisto.params().get('apikey')

    # get the service API url
    base_url_ip = urljoin('https://ipqualityscore.com/api/json/ip/', apikey)
    base_url_email = urljoin('https://ipqualityscore.com/api/json/email/', apikey)
    base_url_url = urljoin('https://ipqualityscore.com/api/json/url/', apikey)

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)
    LOG(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            client = Client(
                base_url=base_url_ip,
                verify=verify_certificate,
                proxy=proxy)
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'ip':
            ip_suspicious_score_threshold = int(demisto.params().get('ip_suspicious_score_threshold'))
            ip_malicious_score_threshold = int(demisto.params().get('ip_malicious_score_threshold'))
            reliability = demisto.params().get('feedReliability')
            client = Client(
                base_url=base_url_ip,
                verify=verify_certificate,
                proxy=proxy)
            return_results(ip_command(client, demisto.args(), ip_suspicious_score_threshold,
                                      ip_malicious_score_threshold, reliability))

        elif demisto.command() == 'email':
            email_suspicious_score_threshold = int(demisto.params().get('email_suspicious_score_threshold'))
            email_malicious_score_threshold = int(demisto.params().get('email_malicious_score_threshold'))
            reliability = demisto.params().get('feedReliability')
            client = Client(
                base_url=base_url_email,
                verify=verify_certificate,
                proxy=proxy)
            return_results(email_command(client, demisto.args(), email_suspicious_score_threshold,
                                         email_malicious_score_threshold, reliability))

        elif demisto.command() == 'url':
            url_suspicious_score_threshold = int(demisto.params().get('url_suspicious_score_threshold'))
            url_malicious_score_threshold = int(demisto.params().get('url_malicious_score_threshold'))
            reliability = demisto.params().get('feedReliability')
            client = Client(
                base_url=base_url_url,
                verify=verify_certificate,
                proxy=proxy)
            return_results(url_command(client, demisto.args(), url_suspicious_score_threshold,
                                       url_malicious_score_threshold, reliability))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
