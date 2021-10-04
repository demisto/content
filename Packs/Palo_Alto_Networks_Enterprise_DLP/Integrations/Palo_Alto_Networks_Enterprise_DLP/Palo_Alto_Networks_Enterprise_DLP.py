import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *


# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
MAX_ATTEMPTS = 3
BASE_URL = 'https://api.dlp.paloaltonetworks.com/v1/'
REPORT_URL = 'public/report/{}'
REFRESH_TOKEN_URL = 'public/oauth/refreshToken'


class Client(BaseClient):

    def __init__(self, refresh_token, access_token, insecure, proxy):
        super().__init__(base_url=BASE_URL, headers=None, verify=not insecure, proxy=proxy)
        self.refresh_token = refresh_token
        self.access_token = access_token

    def _refresh_token(self):
        """Refreshes Access Token"""
        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json"
        }
        params = {
            "refresh_token": self.refresh_token
        }
        r = self._http_request(
            method='POST',
            headers=headers,
            url_suffix=REFRESH_TOKEN_URL,
            json_data=params,
            ok_codes=[200, 201, 204]
        )
        new_token = r.get('access_token')
        if new_token:
            self.access_token = new_token

    def _handle_403_errors(self, res):
        """
        Handles 403 exception on get-dlp-report and tries to refresh token
        Args:
            res: Response of DLP API call
        """
        if res.status_code != 403:
            return
        try:
            self._refresh_token()
        except Exception:
            pass

    def _get_dlp_api_call(self, url_suffix: str):
        """
        Makes a HTTPS Get call on the DLP API
        Args:
            url_suffix: URL suffix for dlp api call
        """
        count = 0
        while count < MAX_ATTEMPTS:
            res = self._http_request(
                method='GET',
                headers={'Authorization': "Bearer " + self.access_token},
                url_suffix=url_suffix,
                ok_codes=[200, 201, 204],
                error_handler=self._handle_403_errors,
                resp_type='',
                return_empty_response=True
            )
            if res.status_code != 403:
                break
            count += 1

        if res.status_code < 200 or res.status_code >= 300:
            raise DemistoException("Request to {} failed with status code {}".format(url_suffix, res.status_code))

        result_json = {} if res.status_code == 204 else res.json()
        return result_json, res.status_code

    def get_dlp_report(self, report_id: str, fetch_snippets=False):
        """
        Fetches DLP reports
        Args:
            report_id: Report ID to fetch from DLP service
            fetch_snippets: if True, fetches the snippets

        Returns: DLP Report json
        """
        url = REPORT_URL.format(report_id)
        if fetch_snippets:
            url = url + "?fetchSnippets=true"

        return self._get_dlp_api_call(url)


def parse_data_pattern_rule(report_json, verdict_field, results_field):
    """
    Parses data pattern matches from a given rule in DLP report JSON
    Args:
        report_json: DLP report json
        verdict_field: Name of the verdict field
        results_field: Name of the result field

    Returns: data pattern matches for the given rule

    """
    if report_json.get(verdict_field) != "MATCHED":
        return []
    data_patterns = []
    for dp in report_json.get("scanContentRawReport", {}).get(results_field, []):
        if (dp.get("state") == "EVALUATED") and (dp.get("unique_detection_frequency", 0) >= 1):
            data_patterns.append({
                'DataPatternName': dp.get('name'),
                'LowConfidenceFrequency': dp.get('low_confidence_frequency'),
                'HighConfidenceFrequency': dp.get('high_confidence_frequency'),
                'MediumConfidenceFrequency': dp.get('medium_confidence_frequency'),
                'Detections': dp.get("detections")
            })
    return data_patterns


def parse_data_patterns(report_json):
    """
    Parse data pattern matches from the raw report
    Args:
        report_json: DLP report JSON

    Returns: Data pattern matches
    """
    data_patterns = []
    data_patterns.extend(
        parse_data_pattern_rule(report_json, "data_pattern_rule_1_verdict", "data_pattern_rule_1_results"))
    data_patterns.extend(
        parse_data_pattern_rule(report_json, "data_pattern_rule_2_verdict", "data_pattern_rule_2_results"))
    return {
        'DataProfile': report_json.get("data_profile_name"),
        'DataPatternMatches': data_patterns
    }


def convert_to_human_readable(data_patterns):
    """
    Converts the results for human readable format
    Args:
        data_patterns: Data Pattern matches

    Returns: Human Readable Format result
    """
    matches: list = []
    if not data_patterns:
        return matches
    headers = ['DataPatternName', 'ConfidenceFrequency']
    for k in data_patterns.get("DataPatternMatches", []):
        match = {
            'DataPatternName': k.get('DataPatternName'),
            'ConfidenceFrequency': {
                'Low': k.get('LowConfidenceFrequency'),
                'Medium': k.get('MediumConfidenceFrequency'),
                'High': k.get('HighConfidenceFrequency')
            }
        }
        index = 1
        detections = k.get('Detections', [])
        if detections:
            for detection in detections:
                col = 'Detection {}'.format(index)
                if col not in headers:
                    headers.append(col)
                match[col] = detection
                index += 1
        matches.append(match)
    title = 'DLP Report for profile: {}'.format(data_patterns.get("DataProfile"))
    return tableToMarkdown(title, matches, headers)


def parse_dlp_report(report_json):
    """
    Parses DLP Report for display
    Args:
        report_json: DLP report json

    Returns: DLP report results
    """
    data_patterns = parse_data_patterns(report_json)
    results = CommandResults(
        outputs_prefix='DLP.Report',
        outputs_key_field='DataPatternName',
        outputs=data_patterns,
        readable_output=convert_to_human_readable(data_patterns),
        raw_response=report_json
    )
    return_results(results)


def test(client):
    """ Test Function to test validity of access and refresh tokens"""
    report_json, status_code = client.get_dlp_report('1')
    if status_code in [200, 204]:
        return_results("ok")
    else:
        raise DemistoException("Integration test failed: Unexpected status ({})".format(status_code))


def main():
    """ Main Function"""
    try:
        demisto.info('Command is %s' % (demisto.command(),))
        params = demisto.params()
        access_token = params.get('access_token')
        refresh_token = params.get('refresh_token')

        client = Client(refresh_token, access_token, params.get('insecure'), params.get('proxy'))

        if demisto.command() == 'pan-dlp-get-report':
            args = demisto.args()
            report_id = args.get('report_id')
            fetch_snippets = argToBoolean(args.get('fetch_snippets'))
            report_json, status_code = client.get_dlp_report(report_id, fetch_snippets)
            parse_dlp_report(report_json)

        if demisto.command() == "test-module":
            test(client)

    except Exception as e:
        demisto.debug('Unknown Command')
        error_message = str(e)
        return_error(error_message)


if __name__ in ["__builtin__", "builtins"]:
    main()
