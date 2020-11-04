import requests
import collections
from time import sleep
from urllib.parse import urljoin

''' GLOBALS/PARAMS '''
MAX_ATTEMPTS = 3
BASE_URL = 'https://api.dlp.paloaltonetworks.com/v1/'
REPORT_URL = 'public/report/{}'
REFRESH_TOKEN_URL = BASE_URL + 'public/oauth/refreshToken'
ACCESS_TOKEN = ''
REFRESH_TOKEN = ''


def makehash():
    """Creates a hashmap with recursive default values"""
    return collections.defaultdict(makehash)


def refreshtoken(access_token, refresh_token):
    """Refreshes Access Token"""
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json"
    }
    params = {
        "refresh_token": refresh_token
    }
    r = requests.post(REFRESH_TOKEN_URL, json=params, headers=headers)
    return r.json()['access_token'] if r.ok else None


def get_dlp_api_call(url):
    """ Makes a HTTPS Get call on the DLP API"""

    global ACCESS_TOKEN
    count = 0
    while count < MAX_ATTEMPTS:
        res = requests.get(url=url, headers={'Authorization': "Bearer " + ACCESS_TOKEN})
        if res.status_code != 403:
            break
        new_token = refreshtoken(ACCESS_TOKEN, REFRESH_TOKEN)
        if new_token:
            ACCESS_TOKEN = new_token
        count += 1
        sleep(count)
    if res.status_code < 200 or res.status_code >= 300:
        raise Exception("Request to {} failed with status code {}".format(url, res.status_code))
    result_json = {} if res.status_code == 204 else res.json()
    return result_json, res.status_code


def parse_data_pattern_rule(report_json, verdict_field, results_field):
    """Parse data pattern matches for a given rule"""
    if report_json.get(verdict_field) != "MATCHED":
        return []
    data_patterns = []
    for dp in report_json.get("scanContentRawReport", {}).get(results_field, []):
        if (dp.get("state") == "EVALUATED") and (dp.get("unique_detection_frequency", 0) >= 1):
            data_patterns.append({
                'Data Pattern Name': dp["name"],
                'Low Confidence Frequency': dp["low_confidence_frequency"],
                'High Confidence Frequency': dp["high_confidence_frequency"],
                'Medium Confidence Frequency': dp["medium_confidence_frequency"],
                'Detections': dp.get("detections")
            })
    return data_patterns


def parse_data_patterns(report_json):
    """Parse data pattern matches from the raw report"""
    data_patterns = []
    data_patterns.extend(
        parse_data_pattern_rule(report_json, "data_pattern_rule_1_verdict", "data_pattern_rule_1_results"))
    data_patterns.extend(
        parse_data_pattern_rule(report_json, "data_pattern_rule_2_verdict", "data_pattern_rule_2_results"))
    return {
        'data_profile': report_json.get("data_profile_name"),
        'data_patterns': data_patterns
    }


def get_dlp_report(report_id, fetch_snippets=False):
    """Fetches DLP reports"""
    url = urljoin(BASE_URL, REPORT_URL.format(report_id))
    if fetch_snippets:
        url = url + "?fetchSnippets=true"

    return get_dlp_api_call(url)


def convert_to_human_readable(data_patterns):
    """Converts the results for human readable format"""
    matches = []
    if not data_patterns:
        return matches
    headers = ['Data Pattern Name', 'Confidence Frequency']
    for k in data_patterns.get("data_patterns", []):
        match = {
            'Data Pattern Name': k.get('Data Pattern Name'),
            'Confidence Frequency': {
                'Low': k.get('Low Confidence Frequency'),
                'Medium': k.get('Medium Confidence Frequency'),
                'High': k.get('High Confidence Frequency')
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
    title = 'DLP Report for profile: {}'.format(data_patterns.get("data_profile"))
    return tableToMarkdown(title, matches, headers)


def parse_dlp_report(report_json):
    """Parses DLP Report for display"""

    data_patterns = parse_data_patterns(report_json)

    results = CommandResults(
        outputs_prefix='DLP.Reports',
        outputs_key_field='Data_Profile',
        outputs={
            'Data_Profile': data_patterns.get("data_profile"),
            'DataPatternMatches': data_patterns.get("data_patterns")
        },
        readable_output=convert_to_human_readable(data_patterns)
    )
    return_results(results)


def test():
    """ Test Function to test validity of access and refresh tokens"""
    report_json, status_code = get_dlp_report('1')
    if status_code in [200, 204]:
        return_results("ok")
    else:
        raise Exception("Integration test failed: Unexpected status ({})".format(status_code))


def main():
    """ Main Function"""
    try:
        LOG('Command is %s' % (demisto.command(),))
        global ACCESS_TOKEN, REFRESH_TOKEN
        ACCESS_TOKEN = demisto.params().get('access_token')
        REFRESH_TOKEN = demisto.params().get('refresh_token')

        if demisto.command() == 'get-dlp-report':
            report_id = demisto.args().get('report_id')
            fetch_snippets = demisto.args().get('fetch_snippets', 'false') == 'true'
            report_json, status_code = get_dlp_report(report_id, fetch_snippets)
            parse_dlp_report(report_json)

        if demisto.command() == "test-module":
            test()

    except Exception as e:
        demisto.debug('Unknown Command')
        error_message = str(e)
        return_error(error_message)

    finally:
        LOG.print_log()


if __name__ in ["__builtin__", "builtins"]:
    main()

