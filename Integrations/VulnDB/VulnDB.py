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


def vulndb_vulnerability_to_entry(vuln):
    vulnerability_details = {
        'ID': vuln.get('vulndb_id', 0),
        'Title': vuln.get('title', ''),
        'Description': vuln.get('description', '').rstrip('Z'),
        'Keywords': vuln.get('keywords', ''),
        'PublishedDate': vuln.get('vulndb_published_date', '').rstrip('Z'),
        'TDescription': vuln.get('t_description', ''),
        'SolutionDate': vuln.get('solution_date', '').rstrip('Z'),
        'DiscoveryDate': vuln.get('disclosure_date', '').rstrip('Z'),
        'ExploitPublishDate': vuln.get('exploit_publish_date', '').rstrip('Z'),
    }

    cve_ext_reference_values = [ext_reference['value'] for ext_reference in
                                vuln.get('ext_references', [])]

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
    } for cvss_metrics_data in vuln['cvss_metrics']]

    vendor_details = [{'Id': vendor.get('vendor', {'id': 0})['id'], 'Name': vendor.get('vendor', {'name': ''})['name']}
                      for vendor in vuln['vendors']]

    product_details = []
    for product in vuln['products']:
        product_versions = [{'Id': version.get('id', ''), 'Name': version.get('name', '')} for version in
                            product.get('versions', [])]
        product_details.append({
            'Id': product.get('id', ''),
            'Name': product.get('name', ''),
            'Versions': product_versions
        })

    default_classification = {'longname': '', 'description': ''}
    classification_details = [{'Longname': classification.get('classification', default_classification)['longname'],
                               'Description': classification.get('classification', default_classification)[
                                   'description']}
                              for classification in vuln['classifications']]

    return {
            'Vulnerability': vulnerability_details,
            'CVE-ExtReference': {
                'Value': cve_ext_reference_values
            },
            'CvssMetrics': cvss_metrics_details,
            'Vendor': vendor_details,
            'Products': product_details,
            'Classification': classification_details
        }


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

        ec = {
            'VulnDB': vulndb_vulnerability_to_entry(vulnerability_data)
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


def vulndb_get_vuln_by_vendor_and_product_name_command():
    vendor_name = demisto.args()['vendor_name']
    product_name = demisto.args()['product_name']

    res = requests.get(f'{API_URL}/vulnerabilities/find_by_vendor_and_product_name?vendor_name={vendor_name}&product_name={product_name}',
                       verify=USE_SSL,
                       headers={'Authorization': f'Bearer {get_oath_toekn()}'}
                       ).json()

    if 'error' in res:
        return_error(res['error'])
    else:
        results = res['results']
        for result in results:
            ec = {
                'VulnDB': vulndb_vulnerability_to_entry(result)
            }

            human_readable = tableToMarkdown(f'Result for vulnerability ID: {ec["VulnDB"]["Vulnerability"]["ID"]}', {
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


def vulndb_get_vuln_by_vendor_and_product_id_command():
    vendor_id = demisto.args()['vendor_id']
    product_id = demisto.args()['product_id']

    res = requests.get(f'{API_URL}/vulnerabilities/find_by_vendor_and_product_id?vendor_id={vendor_id}&product_id={product_id}',
                       verify=USE_SSL,
                       headers={'Authorization': f'Bearer {get_oath_toekn()}'}
                       ).json()

    if 'error' in res:
        return_error(res['error'])
    else:
        results = res['results']
        for result in results:
            ec = {
                'VulnDB': vulndb_vulnerability_to_entry(result)
            }

            human_readable = tableToMarkdown(f'Result for vulnerability ID: {ec["VulnDB"]["Vulnerability"]["ID"]}', {
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
elif demisto.command() == 'vulndb-get-vuln-by-vendor-and-product-name':
    vulndb_get_vuln_by_vendor_and_product_name_command()
elif demisto.command() == 'vulndb-get-vuln-by-vendor-and-product-id':
    vulndb_get_vuln_by_vendor_and_product_id_command()
