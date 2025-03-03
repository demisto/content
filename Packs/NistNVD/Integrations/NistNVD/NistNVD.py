import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import sys
from datetime import datetime, timedelta
import requests


VERIFY_SSL = not demisto.params().get('insecure', False)

if not demisto.params().get('proxy', False):
    handle_proxy()


def test_module() -> str:
    try:
        base_url = urljoin(demisto.params()['url'], '/rest/json/cves/2.0')
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
    req = requests.get(url, headers=headers, params=additional_parameters, verify=VERIFY_SSL)
    if req.status_code != 200:
        return_results(req.content)
        sys.exit(1)
    else:
        return req.json()


# Process of extraction vulnerability details in the NVD
def extractVulnDetails(requestfromconnection):
    req = requestfromconnection
    pretty_list = []  # list()

    def get_value_from_hierarchy(mapping, key_chain):
        """Retrieve value from a nested dictionary based on a dot-separated key chain."""
        keys = key_chain.split('.')
        value = mapping
        for key in keys:
            if key in value:
                value = value[key]
            else:
                return None
        return value

    key_locations = {
        'CVSS Attack Vector': ['cvssData.attackVector', 'cvssData.accessVector', 'attackVector'],
        'CVSS Attack Complexity': ['cvssData.attackComplexity', 'cvssData.accessComplexity', 'attackComplexity'],
        'CVSS Base Score': ['cvssData.baseScore', 'baseScore'],
        'CVSS Base Severity': ['cvssData.baseSeverity', 'baseSeverity'],
        'Exploitability Score': ['cvssData.exploitabilityScore', 'exploitabilityScore'],
        'Impact Score': ['cvssData.impactScore', 'impactScore'],
        'CVSS Version': ['cvssData.version', 'version'],
        'CVSS Vector String': ['cvssData.vectorString', 'vectorString'],
        'CVSS Privileges Required': ['cvssData.privilegesRequired', 'obtainAllPrivilege'],
        'CVSS User Interaction': ['cvssData.userInteraction', 'userInteractionRequired'],
        'CVSS Scope': ['cvssData.scope'],
        'CVSS Confidentiality Impact': ['cvssData.confidentialityImpact', 'confidentialityImpact'],
        'CVSS Integrity Impact': ['cvssData.integrityImpact', 'integrityImpact'],
        'CVSS Availability Impact': ['cvssData.availabilityImpact', 'availabilityImpact']
    }

    if ('vulns' not in req):
        for i in req['vulnerabilities']:
            pretty_dict = {}
            pretty_dict['CVE ID'] = i['cve']['id']
            pretty_dict['Published Date'] = i['cve']['published']
            pretty_dict['Last Modified Date'] = i['cve']['lastModified']
            description = []
            for k in i['cve']['descriptions']:
                description.append(k['value'])
            pretty_dict['Description'] = description
            reference_data = []
            for j in i['cve']['references']:
                reference_data.append(j['url'])
            pretty_dict['References'] = reference_data
            pretty_dict['Vulnerability Status'] = i['cve']['vulnStatus']

            if ('metrics' in list(i['cve'].keys())):
                cvssmetricslist = []

                for _cvssmetrickey, cvssmetric in i['cve']['metrics'].items():
                    cvssmetricsdict = {}
                    cvssmetric = cvssmetric[0]

                    for key, locations in key_locations.items():
                        cvssmetricsdict[key] = next(
                            (
                                get_value_from_hierarchy(cvssmetric, loc)
                                for loc in locations
                                if get_value_from_hierarchy(cvssmetric, loc) is not None
                            ),
                            None,
                        )
                    cvssmetricslist.append(cvssmetricsdict)

            pretty_dict['metrics'] = cvssmetricslist
            pretty_list.append(pretty_dict)
    elif ('vulns') in req and (not len(req['vulns'])):
        demisto.results("Vendor name may be wrong or no CPE added")

    if (('result') in req) and (not len(req['result']['CVE_Items'])):
        demisto.results("There were no vulnerability in the criteria you were looking for.")
    return pretty_list


def generalSearch():

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/2.0')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(days=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date = datetime.today().strftime('%Y-%m-%dT%H:%M:%S.000')
    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')
    additional_parameters = {"lastModStartDate": f"{start_date}+00:00", "lastModEndDate": f"{end_date}+00:00",
                             "startIndex": f"{startIndex}", "resultsPerPage": f"{resultsPerPage}"}

    generalSearchRequest = connection(base_url, additional_parameters)
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

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/2.0')
    keyword = demisto.args().get('keyword')
    isExactMatch = argToBoolean(demisto.args().get('isExactMatch'))
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(days=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S%z')
    end_date = datetime.today().strftime('%Y-%m-%dT%H:%M:%S.000')
    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')
    additional_parameters = {"lastModStartDate": f"{start_date}+00:00", "lastModEndDate": f"{end_date}+00:00",
                             "keywordSearch": keyword, "startIndex": f"{startIndex}", "resultsPerPage": f"{resultsPerPage}"}
    if isExactMatch:
        additional_parameters["keywordExactMatch"] = None
        additional_parameters = '&'.join([k if v is None else
                                          f"{k}={v}" for k, v in additional_parameters.items()])  # type: ignore
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

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/2.0')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(days=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date = datetime.today().strftime('%Y-%m-%dT%H:%M:%S.000')

    cvssType = demisto.args().get('cvssType')
    key = demisto.args().get('key')
    searchParameters = cvssType + key
    value = demisto.args().get('value')

    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')

    additional_parameters = {"lastModStartDate": f"{start_date}+00:00", "lastModEndDate": f"{end_date}+00:00",
                             f"{searchParameters}": f"{value}", "startIndex": f"{startIndex}",
                             "resultsPerPage": f"{resultsPerPage}"}
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

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/2.0')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(days=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date = datetime.today().strftime('%Y-%m-%dT%H:%M:%S.000')

    cweId = demisto.args().get('cweId')
    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')

    additional_parameters = {"lastModStartDate": f"{start_date}+00:00", "lastModEndDate": f"{end_date}+00:00",
                             "cweId": f"{cweId}", "startIndex": f"{startIndex}", "resultsPerPage": f"{resultsPerPage}"}
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

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/2.0')
    time = int(demisto.args().get('time'))
    last_time = datetime.today() - timedelta(days=int(time))
    start_date = last_time.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date = datetime.today().strftime('%Y-%m-%dT%H:%M:%S.000')

    cpeName = demisto.args().get('cpe')
    startIndex = demisto.args().get('startIndex')
    resultsPerPage = demisto.args().get('resultsPerPage')

    additional_parameters = {"lastModStartDate": f"{start_date}+00:00", "lastModEndDate": f"{end_date}+00:00",
                             "cpeName": f"{cpeName}", "startIndex": f"{str(startIndex)}",
                             "resultsPerPage": f"{str(resultsPerPage)}"}
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

    base_url = urljoin(demisto.params()['url'], '/rest/json/cves/2.0/')
    cve = demisto.args().get('cve')

    additional_parameters = {"cveId": cve}
    generalSearchRequest = connection(base_url, additional_parameters)
    generalVulnerabilityList = extractVulnDetails(generalSearchRequest)
    headers = ['CVE ID', 'Description', 'Published Date', 'Last Modified Date',
               'References', 'CVSS Base Score', 'CVSS Base Severity',
               'Exploitability Score', 'Impact Score', 'CVSS Version',
               'CVSS Vector String', 'CVSS Attack Vector', 'CVSS Attack Complexity',
               'CVSS Privileges Required', 'CVSS User Interaction', 'CVSS Scope',
               'CVSS Confidentiality Impact', 'CVSS Integrity Impact', 'CVSS Availability Impact', 'Vulnerability Status']
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
    demisto.info(f'command is {demisto.command()}')
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
