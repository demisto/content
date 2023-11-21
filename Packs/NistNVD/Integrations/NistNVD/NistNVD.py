import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import sys
from datetime import datetime, timedelta

import requests


''' CONSTANTS '''
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

VERIFY_SSL = not demisto.params().get('insecure', False)

if not demisto.params().get('proxy', False):
    handle_proxy()


def test_module() -> str:
    try:
        base_url = urljoin(demisto.params()['url'], '/rest/json/cves/1.0')
        headers = {'Accept': 'application/json'}
        req = requests.get(base_url, headers=headers, verify=VERIFY_SSL)
        if req.status_code != 200:
            http_status = 'HTTP status is' + str(req.status_code)
            return_error(http_status)
    except Exception as e:
        return_error(e)
    return 'ok'


def connection(url, additional_parameters):

    headers = {'Accept': 'application/json'}
    endpoint = url + additional_parameters
    req = requests.get(endpoint, headers=headers, verify=VERIFY_SSL)
    if req.status_code != 200:
        return_results(req.content)
        sys.exit(1)
    else:
        return req.json()


# Process of extraction vulnerability details in the NVD
def extractVulnDetails(requestfromconnection):
    req = requestfromconnection
    pretty_list = []  # list()
    if (not ('vulns') in req):
        for i in req['result']['CVE_Items']:
            pretty_dict = {}
            pretty_dict['CVE ID'] = i['cve']['CVE_data_meta']['ID']
            pretty_dict['Published Date'] = i['publishedDate']
            pretty_dict['Last Modified Date'] = i['lastModifiedDate']
            for k in i['cve']['description']['description_data']:
                pretty_dict['Description'] = k['value']
            reference_data = []
            for j in i['cve']['references']['reference_data']:
                reference_data.append(j['url'])
            pretty_dict['References'] = reference_data
            if (('impact') in i and ('baseMetricV3') in i['impact']):
                pretty_dict['CVSSv3 Base Score'] = i['impact']['baseMetricV3']['cvssV3']['baseScore']
                pretty_dict['CVSSv3 Base Severity'] = i['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                pretty_dict['Exploitability Score'] = i['impact']['baseMetricV3']['exploitabilityScore']
                pretty_dict['Impact Score'] = i['impact']['baseMetricV3']['impactScore']
                pretty_dict['CVSSv3 Version'] = i['impact']['baseMetricV3']['cvssV3']['version']
                pretty_dict['CVSSv3 Vector String'] = i['impact']['baseMetricV3']['cvssV3']['vectorString']
                pretty_dict['CVSSv3 Attack Vector'] = i['impact']['baseMetricV3']['cvssV3']['attackVector']
                pretty_dict['CVSSv3 Attack Complexity'] = i['impact']['baseMetricV3']['cvssV3']['attackComplexity']
                pretty_dict['CVSSv3 Privileges Required'] = i['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
                pretty_dict['CVSSv3 User Interaction'] = i['impact']['baseMetricV3']['cvssV3']['userInteraction']
                pretty_dict['CVSSv3 Scope'] = i['impact']['baseMetricV3']['cvssV3']['scope']
                pretty_dict['CVSSv3 Confidentiality Impact'] = i['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
                pretty_dict['CVSSv3 Integrity Impact'] = i['impact']['baseMetricV3']['cvssV3']['integrityImpact']
                pretty_dict['CVSSv3 Availability Impact'] = i['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
            """if (('configurations') in i):
                cpe23UriString = ''
                for l in i['configurations']['nodes']:
                    if(('children') in l):
                        for m in l['children']:
                            cpe23Uri = []
                            for n in m['cpe_match']:
                                cpe23Uri += n['cpe23Uri']+ '\n' #+ n['vulnerable']
                                #pretty_dict['vulnerable'] = n['vulnerable']
                                #pretty_dict['cpe23Uri'] = n['cpe23Uri']
                        pretty_dict['configurations'] = cpe23UriString
                    elif(('cpe_match') in l):
                        for m in l['cpe_match']:
                            cpe23UriString += m['cpe23Uri'] + '\n' #+ m['vulnerable']
                            #pretty_dict['vulnerable'] = m['vulnerable']
                            #pretty_dict['cpe23Uri'] = m['cpe23Uri']
                        pretty_dict['configurations'] = cpe23UriString"""
            pretty_list.append(pretty_dict)
    elif ('vulns') in req:
        if (not len(req['vulns'])):
            demisto.results("Vendor name may be wrong or no CPE added")

    if (('result') in req):
        if (not len(req['result']['CVE_Items'])):
            demisto.results("There were no vulnerability in the criteria you were looking for.")
    return pretty_list


def generalSearch():

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/1.0')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(hours=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S:000')
    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')
    additional_parameters = '?modStartDate=' + start_date + ' UTC-00:00' + \
        '&startIndex=' + str(startIndex) + '&resultsPerPage=' + str(resultsPerPage)
    generalSearchRequest = connection(base_url, additional_parameters)
    demisto.results(generalSearchRequest)
    generalVulnerabilityList = extractVulnDetails(generalSearchRequest)

    headers = ['CVE ID', 'Description', 'Published Date', 'Last Modified Date', 'References']
    markdown = 'General Search\n'
    markdown += tableToMarkdown('Vulnerabilities', generalVulnerabilityList, headers=headers, removeNull=True)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='NistNVD.GeneralSearch',
        outputs_key_field='CVE ID',
        outputs=generalVulnerabilityList
    )

    return_results(results)


def keywordSearch():

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/1.0')
    keyword = demisto.args().get('keyword')
    isExactMatch = demisto.args().get('isExactMatch')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(hours=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S:000')
    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')
    additional_parameters = '?modStartDate=' + start_date + ' UTC-00:00' + '&keyword=' + keyword + \
        '&isExactMatch=' + isExactMatch + '&startIndex=' + str(startIndex) + '&resultsPerPage=' + str(resultsPerPage)
    generalSearchRequest = connection(base_url, additional_parameters)
    generalVulnerabilityList = extractVulnDetails(generalSearchRequest)

    headers = ['CVE ID', 'Description', 'Published Date', 'Last Modified Date', 'References']
    markdown = 'Keyword Search\n'
    markdown += tableToMarkdown('Vulnerabilities', generalVulnerabilityList, headers=headers, removeNull=True)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='NistNVD.KeywordSearch',
        outputs_key_field='CVE ID',
        outputs=generalVulnerabilityList
    )

    return_results(results)


def cvssSearch():

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/1.0')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(hours=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S:000')

    cvssType = demisto.args().get('cvssType')
    key = demisto.args().get('key')
    searchParameters = cvssType + key
    value = demisto.args().get('value')

    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')

    additional_parameters = '?modStartDate=' + start_date + ' UTC-00:00' + '&' + searchParameters + \
        '=' + value + '&startIndex=' + str(startIndex) + '&resultsPerPage=' + str(resultsPerPage)
    generalSearchRequest = connection(base_url, additional_parameters)
    generalVulnerabilityList = extractVulnDetails(generalSearchRequest)

    headers = ['CVE ID', 'Description', 'Published Date', 'Last Modified Date', 'References']
    markdown = 'CVSS Search\n'
    markdown += tableToMarkdown('Vulnerabilities', generalVulnerabilityList, headers=headers, removeNull=True)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='NistNVD.CVSSSearch',
        outputs_key_field='CVE ID',
        outputs=generalVulnerabilityList
    )

    return_results(results)


def cweSearch():

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/1.0')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(hours=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S:000')

    cweId = demisto.args().get('cweId')
    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')

    additional_parameters = '?modStartDate=' + start_date + ' UTC-00:00' + '&cweId=' + \
        cweId + '&startIndex=' + str(startIndex) + '&resultsPerPage=' + str(resultsPerPage)
    generalSearchRequest = connection(base_url, additional_parameters)
    generalVulnerabilityList = extractVulnDetails(generalSearchRequest)

    headers = ['CVE ID', 'Description', 'Published Date', 'Last Modified Date', 'References']
    markdown = 'CWE Search\n'
    markdown += tableToMarkdown('Vulnerabilities', generalVulnerabilityList, headers=headers, removeNull=True)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='NistNVD.CWESearch',
        outputs_key_field='CVE ID',
        outputs=generalVulnerabilityList
    )

    return_results(results)


def cpeSearch():

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/1.0')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(hours=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S:000')

    cpeMatchString = demisto.args().get('cpe')
    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')

    additional_parameters = '?modStartDate=' + start_date + ' UTC-00:00' + '&cpeMatchString=' + \
        cpeMatchString + '&startIndex=' + str(startIndex) + '&resultsPerPage=' + str(resultsPerPage)
    generalSearchRequest = connection(base_url, additional_parameters)
    generalVulnerabilityList = extractVulnDetails(generalSearchRequest)

    headers = ['CVE ID', 'Description', 'Published Date', 'Last Modified Date', 'References']
    markdown = 'CPE Search\n'
    markdown += tableToMarkdown('Vulnerabilities', generalVulnerabilityList, headers=headers, removeNull=True)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='NistNVD.CPESearch',
        outputs_key_field='CVE ID',
        outputs=generalVulnerabilityList
    )

    return_results(results)


def cveSearch():

    base_url = urljoin(demisto.params()['url'], '/rest/json/cve/1.0/')
    cve = demisto.args().get('cve')

    additional_parameters = cve
    generalSearchRequest = connection(base_url, additional_parameters)
    demisto.results(generalSearchRequest)
    generalVulnerabilityList = extractVulnDetails(generalSearchRequest)
    headers = ['CVE ID', 'Description', 'Published Date', 'Last Modified Date',
               'References', 'CVSSv3 Base Score', 'CVSSv3 Base Severity',
               'Exploitability Score', 'Impact Score', 'CVSSv3 Version',
               'CVSSv3 Vector String', 'CVSSv3 Attack Vector', 'CVSSv3 Attack Complexity',
               'CVSSv3 Privileges Required', 'CVSSv3 User Interaction', 'CVSSv3 Scope',
               'CVSSv3 Confidentiality Impact', 'CVSSv3 Integrity Impact', 'CVSSv3 Availability Impact']
    markdown = 'CVE Search\n'
    markdown += tableToMarkdown('Vulnerabilities', generalVulnerabilityList, headers=headers, removeNull=True)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='NistNVD.CVESearch',
        outputs_key_field='CVE ID',
        outputs=generalVulnerabilityList
    )

    return_results(results)


def main() -> None:
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    ''' EXECUTION '''
    demisto.debug(f'Command being called is {demisto.command()}')

    ''' EXECUTION '''
    LOG('command is %s' % (demisto.command(), ))
    try:
        if demisto.command() == 'test-module':
            demisto.results(test_module())
        elif demisto.command() == 'nvd-get-vulnerability':
            generalSearch()
        elif demisto.command() == 'nvd-search-keyword':
            keywordSearch()
        elif demisto.command() == 'nvd-search-cvss':
            cvssSearch()
        elif demisto.command() == 'nvd-search-cwe':
            cweSearch()
        elif demisto.command() == 'nvd-search-cpe':
            cpeSearch()
        elif demisto.command() == 'nvd-search-cve':
            cveSearch()
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
