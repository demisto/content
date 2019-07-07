import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import requests
import urllib.parse

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

# Remove trailing slash to prevent wrong URL path to service
API_URL = demisto.params()['api_url'].rstrip('/')

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    os.environ.pop('HTTP_PROXY', None)
    os.environ.pop('HTTPS_PROXY', None)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)

CLIENT_ID = demisto.params()['client_id']

CLIENT_SECRET = demisto.params()['client_secret']

''' HELPER FUNCTIONS '''


def get_oath_toekn():
    # Workaround ParseResult immutability
    parse_result = list(urllib.parse.urlparse(API_URL))
    parse_result[2] = '/oauth/token'
    oath_url = urllib.parse.urlunparse(parse_result)

    return requests.post(oath_url,
                         verify=USE_SSL,
                         data={
                             'client_id': CLIENT_ID,
                             'client_secret': CLIENT_SECRET,
                             'grant_type': 'client_credentials'
                         }).json()['access_token']


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_oath_toekn()


def vulndb_get_vuln_by_id_command():
    vulndb_id = demisto.args()['vuln_id']

    res = requests.get(f'{API_URL}/vulnerabilities/{vulndb_id}',
                       verify=USE_SSL,
                       headers={'Authorization': f'Bearer {get_oath_toekn()}'}
                       ).json()

    if 'error' in res:
        return_error(res['error'])
    else:
        vulnerability_data = res['vulnerability']
        vulnerability_details = {
            'Title': vulnerability_data.get('title', ''),
            'Description': vulnerability_data.get('description', ''),
            'Keywords': vulnerability_data.get('keywords', ''),
            'PublishedDate': vulnerability_data.get('vulndb_published_date', ''),
            'TDescription': vulnerability_data.get('t_description', ''),
            'SolutionDate': vulnerability_data.get('solution_date', ''),
            'DiscoveryDate': vulnerability_data.get('disclosure_date', ''),
            'ExploitPublishDate': vulnerability_data.get('exploit_publish_date', ''),
        }

        cve_ext_reference_values = [ext_reference['value'] for ext_reference in
                                    vulnerability_data.get('ext_references', [])]

        cvss_metrics_details = [{
            'Id': cvss_metrics_data.get('id', 0),
            'AccessVector': cvss_metrics_data.get('access_vector', ''),
            'AccessComplexity': cvss_metrics_data.get('access_complexity', ''),
            'Authentication': cvss_metrics_data.get('authentication', ''),
            'ConfidentialityImpact': cvss_metrics_data.get('confidentiality_impact', ''),
            'IntegrityImpact': cvss_metrics_data.get('integrity_impact', ''),
            'AvailabilityImpact': cvss_metrics_data.get('availability_impact', ''),
            'GeneratedOn': cvss_metrics_data.get('generated_on', ''),
            'Score': cvss_metrics_data.get('score', 0),
        } for cvss_metrics_data in vulnerability_data['cvss_metrics']]

        vendor_details = [{'Id': vendor.get('vendor', {'id': 0})['id'], 'Name': vendor.get('vendor', {'name': ''})['name']}
                          for vendor in vulnerability_data['vendors']]

        product_details = []
        for product in vulnerability_data['products']:
            product_versions = [{'Id': version.get('id', ''), 'Name': version.get('name', '')} for version in
                                product.get('versions', [])]
            product_details.append({
                'Id': product.get('id', ''),
                'Name': product.get('name', ''),
                'Versions': product_versions
            })

        default_classification = {'longname': '', 'description': ''}
        classification_details = [{'Longname': classification.get('classification', default_classification)['longname'],
                                   'Description': classification.get('classification', default_classification)['description']}
                                  for classification in vulnerability_data['classifications']]

        ec = {
            'VulnDB': {
                'Vulnerability': vulnerability_details,
                'CVE-ExtReference': {
                    'Value': cve_ext_reference_values
                },
                'CvssMetrics': cvss_metrics_details,
                'Vendor': vendor_details,
                'Products': product_details,
                'Classification': classification_details
            }
        }

        human_readable = tableToMarkdown(f'Result for vulnerability ID: {vulndb_id}', {
            'Title': ec['VulnDB']['Vulnerability']['Title'],
            'Description': ec['VulnDB']['Vulnerability']['Description'],
            'Publish Date': ec['VulnDB']['Vulnerability']['PublishedDate'],
            'Solution Date': ec['VulnDB']['Vulnerability']['SolutionDate']
        })

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': res,
            'ContentsFormat': formats['json'],
            'HumanReadable': human_readable,
            'HumanReadableFormat': formats['markdown'],
            'EntryContext': ec
        })


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    test_module()
    demisto.results('ok')
if demisto.command() == 'vulndb-get-vuln-by-id':
    vulndb_get_vuln_by_id_command()
