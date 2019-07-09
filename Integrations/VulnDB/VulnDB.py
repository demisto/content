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


def get_oath_token():
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


def http_request(url, size=None):
    params = {'size': size} if size else None
    return requests.get(url,
                        verify=USE_SSL,
                        headers={'Authorization': f'Bearer {get_oath_token()}'},
                        params=params).json()


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


def vulndb_vulnerability_results_to_demisto_results(res):
    if 'error' in res:
        return_error(res['error'])
    else:
        if 'vulnerability' in res:
            results = [res['vulnerability']]
        elif 'results' in res:
            results = res['results']
        else:
            demisto.results({
                'Type': entryTypes['error'],
                'Contents': res,
                'ContentsFormat': formats['json'],
                'HumanReadable': 'No "vulnerability" or "results" keys in the returned JSON',
                'HumanReadableFormat': formats['text']
            })
            return

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


def vulndb_vendor_to_entry(vendor):
    return {
        'Results': {
            'Id': vendor.get('id', ''),
            'Name': vendor.get('name', ''),
            'ShortName': vendor.get('short_name', ''),
            'VendorUrl': vendor.get('vendor_url', '')
        }
    }


def vulndb_vendor_results_to_demisto_results(res):
    if 'error' in res:
        return_error(res['error'])
    else:
        if 'vendor' in res:
            results = [res['vendor']]
        elif 'results' in res:
            results = res['results']
        else:
            demisto.results({
                'Type': entryTypes['error'],
                'Contents': res,
                'ContentsFormat': formats['json'],
                'HumanReadable': 'No "vendor" or "results" keys in the returned JSON',
                'HumanReadableFormat': formats['text']
            })
            return

        for result in results:
            ec = {
                'VulnDB': vulndb_vendor_to_entry(result)
            }

            human_readable = tableToMarkdown(f'Result for vendor ID: {ec["VulnDB"]["Results"]["Id"]}', {
                'ID': ec['VulnDB']['Results']['Id'],
                'Name': ec['VulnDB']['Results']['Name'],
                'Short Name': ec['VulnDB']['Results']['ShortName'],
                'Vendor URL': ec['VulnDB']['Results']['VendorUrl']
            })

            demisto.results({
                'Type': entryTypes['note'],
                'Contents': res,
                'ContentsFormat': formats['json'],
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })


def vulndb_product_to_entry(product):
    return {
        'Results': {
            'Id': product.get('id', ''),
            'Name': product.get('name', '')
        }
    }


def vulndb_product_results_to_demisto_results(res):
    if 'error' in res:
        return_error(res['error'])
    else:
        if 'results' in res:
            results = res['results']
        else:
            demisto.results({
                'Type': entryTypes['error'],
                'Contents': res,
                'ContentsFormat': formats['json'],
                'HumanReadable': 'No "results" key in the returned JSON',
                'HumanReadableFormat': formats['text']
            })
            return

        for result in results:
            ec = {
                'VulnDB': vulndb_product_to_entry(result)
            }

            human_readable = tableToMarkdown(f'Result for product ID: {ec["VulnDB"]["Results"]["Id"]}', {
                'ID': ec['VulnDB']['Results']['Id'],
                'Name': ec['VulnDB']['Results']['Name']
            })

            demisto.results({
                'Type': entryTypes['note'],
                'Contents': res,
                'ContentsFormat': formats['json'],
                'HumanReadable': human_readable,
                'HumanReadableFormat': formats['markdown'],
                'EntryContext': ec
            })


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_oath_token()


def vulndb_get_vuln_by_id_command():
    vulndb_id = demisto.args()['vuln_id']

    res = requests.get(f'{API_URL}/vulnerabilities/{vulndb_id}',
                       verify=USE_SSL,
                       headers={'Authorization': f'Bearer {get_oath_token()}'}
                       ).json()

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_vendor_and_product_name_command():
    vendor_name = demisto.args()['vendor_name']
    product_name = demisto.args()['product_name']
    max_size = demisto.args().get('max_size')

    res = http_request(
        f'{API_URL}/vulnerabilities/find_by_vendor_and_product_name?vendor_name={vendor_name}&product_name={product_name}',
        max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_vendor_and_product_id_command():
    vendor_id = demisto.args()['vendor_id']
    product_id = demisto.args()['product_id']
    max_size = demisto.args().get('max_size')

    res = http_request(
        f'{API_URL}/vulnerabilities/find_by_vendor_and_product_id?vendor_id={vendor_id}&product_id={product_id}',
        max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_vendor_id_command():
    vendor_id = demisto.args()['vendor_id']
    max_size = demisto.args().get('max_size')

    res = http_request(f'{API_URL}/vulnerabilities/find_by_vendor_id?vendor_id={vendor_id}',
                       max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_product_id_command():
    product_id = demisto.args()['product_id']
    max_size = demisto.args().get('max_size')

    res = http_request(f'{API_URL}/vulnerabilities/find_by_product_id?product_id={product_id}',
                       max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_cve_id_command():
    cve_id = demisto.args()['cve_id']
    max_size = demisto.args().get('max_size')

    res = http_request(f'{API_URL}/vulnerabilities/{cve_id}/find_by_cve_id',
                       max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_updates_by_dates_or_hours_command():
    start_date = demisto.args().get('start_date')
    end_date = demisto.args().get('end_date')
    hours_ago = demisto.args().get('hours_ago')
    max_size = demisto.args().get('max_size')

    if start_date:
        url = f'{API_URL}/vulnerabilities/find_by_date?start_date={start_date}'
        if end_date:
            url += f'&end_date={end_date}'

        res = http_request(url,
                           max_size)
    elif hours_ago is not None:
        res = http_request(f'{API_URL}/vulnerabilities/find_by_time?hours_ago={hours_ago}',
                           max_size)
    else:
        return_error('Must provide either start date or hours ago.')

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vendor_command():
    vendor_id = demisto.args().get('vendor_id')
    vendor_name = demisto.args().get('vendor_name')
    max_size = demisto.args().get('max_size')

    if vendor_id is not None and vendor_name is not None:
        return_error('Provide either vendor id or vendor name or neither, not both.')
    elif vendor_id:
        res = http_request(f'{API_URL}/vendors/{vendor_id}',
                           max_size)
    elif vendor_name:
        res = http_request(f'{API_URL}/vendors/by_name?vendor_name={vendor_name}',
                           max_size)
    else:
        res = http_request(f'{API_URL}/vendors',
                           max_size)

    vulndb_vendor_results_to_demisto_results(res)


def vulndb_get_product_command():
    vendor_id = demisto.args().get('vendor_id')
    vendor_name = demisto.args().get('vendor_name')
    max_size = demisto.args().get('max_size')

    if vendor_id is not None and vendor_name is not None:
        return_error('Provide either vendor id or vendor name or neither, not both.')
    elif vendor_id:
        res = http_request(f'{API_URL}/products/by_vendor_id?vendor_id={vendor_id}',
                           max_size)
    elif vendor_name:
        res = http_request(f'{API_URL}/products/by_vendor_name?vendor_name={vendor_name}',
                           max_size)
    else:
        res = http_request(f'{API_URL}/products',
                           max_size)

    vulndb_product_results_to_demisto_results(res)


def vulndb_get_version_command():
    product_id = demisto.args().get('product_id')
    product_name = demisto.args().get('product_name')
    max_size = demisto.args().get('max_size')

    if product_id is not None and product_name is not None:
        return_error('Provide either product id or vendor name, not both.')
    elif product_id:
        res = http_request(f'{API_URL}/versions/by_product_id?product_id={product_id}',
                           max_size)
    elif product_name:
        res = http_request(f'{API_URL}/versions/by_product_name?product_name={product_name}',
                           max_size)

    vulndb_product_results_to_demisto_results(res)


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
elif demisto.command() == 'vulndb-get-vuln-by-vendor-id':
    vulndb_get_vuln_by_vendor_id_command()
elif demisto.command() == 'vulndb-get-vuln-by-product-id':
    vulndb_get_vuln_by_product_id_command()
elif demisto.command() == 'vulndb-get-vuln-by-cve-id':
    vulndb_get_vuln_by_cve_id_command()
elif demisto.command() == 'vulndb-get-vendor':
    vulndb_get_vendor_command()
elif demisto.command() == 'vulndb-get-product':
    vulndb_get_product_command()
elif demisto.command() == 'vulndb-get-version':
    vulndb_get_version_command()
elif demisto.command() == 'vulndb-get-updates-by-dates-or-hours':
    vulndb_get_updates_by_dates_or_hours_command()
