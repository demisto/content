import urllib.parse
import urllib3
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
demisto.debug('pack name = VulnDB, pack version = 1.0.12')


''' IMPORTS '''


# Disable insecure warnings
urllib3.disable_warnings()

''' HELPER FUNCTIONS '''


class Client(BaseClient):

    def __init__(self, proxy, use_ssl, base_url, client_id, client_secret):
        super().__init__(base_url=base_url, verify=use_ssl, proxy=proxy)
        access_token = self.get_oath_token(client_id, client_secret)
        headers = {'Content-Type': 'application/json',
                   'Authorization': f'Bearer {access_token}'}
        self._headers = headers

    def get_oath_token(self, client_id, client_secret):
        # Workaround ParseResult immutability
        parse_result = list(urllib.parse.urlparse(self._base_url))
        parse_result[2] = '/oauth/token'
        oath_url = urllib.parse.urlunparse(parse_result)
        res = self._http_request('POST',
                                 '',
                                 json_data={
                                     'client_id': client_id,
                                     'client_secret': client_secret,
                                     'grant_type': 'client_credentials'
                                 },
                                 full_url=oath_url)
        return res.get('access_token')

    def http_request(self, url_suffix, size=None):
        params = {'size': size} if size else None
        res = self._http_request("GET",
                                 url_suffix=url_suffix,
                                 params=params)
        # The details could reside in either error or details, not both
        for error_attribute in ['error', 'details']:
            if error_attribute in res:
                raise DemistoException(res[error_attribute])
        return res

    def http_file_request(self, url_suffix):
        res = self._http_request("GET",
                                 url_suffix=url_suffix,
                                 resp_type='bytes')
        return res


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
        'TechnicalDescription': vuln.get('t_description', '')
    }

    cve_ext_reference_values = [ext_reference['value'] for ext_reference in
                                vuln.get('ext_references', [])]

    cvss_metrics_details = [{
        'Id': cvss_metrics_data.get('cve_id', 0),
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
    timeline_details = {
        'DiscoveryDate': vuln.get('discovery_date', '').rstrip('Z'),
        'DisclosureDate': vuln.get('disclosure_date', '').rstrip('Z'),
        'VendorInformedDate': vuln.get('vendor_informed_date', '').rstrip('Z'),
        'VendorAckDate': vuln.get('vendor_ack_date', '').rstrip('Z'),
        'ExploitPublishDate': vuln.get('exploit_publish_date', '').rstrip('Z'),
        'ExploitWildDate': vuln.get('exploited_in_the_wild_date', '').rstrip('Z'),
        'SolutionDate': vuln.get('solution_date', '').rstrip('Z'),
        'ThirdPartySolutionDate': vuln.get('third_party_solution_date', '').rstrip('Z'),
    }
    return {
        'Vulnerability': vulnerability_details,
        'CVE-ExtReference': {
            'Value': cve_ext_reference_values
        },
        'CvssMetrics': cvss_metrics_details,
        'Vendor': vendor_details,
        'Products': product_details,
        'Classification': classification_details,
        'Timeline': timeline_details
    }


def vulndb_vulnerability_results_to_demisto_results(res):
    results = []
    if 'vulnerability' in res:
        results = [res['vulnerability']]
    elif 'results' in res:
        results = res['results']
    else:
        return_error('No "vulnerability" or "results" keys in the returned JSON')
    for result in results:
        ec = {
            'VulnDB': vulndb_vulnerability_to_entry(result)
        }
        human_readable = tableToMarkdown(f'Result for vulnerability ID: {ec["VulnDB"]["Vulnerability"]["ID"]}', {
            'Title': ec['VulnDB']['Vulnerability']['Title'],
            'Description': ec['VulnDB']['Vulnerability']['Description'],
            'Publish Date': ec['VulnDB']['Vulnerability']['PublishedDate'],
            'Solution Date': ec['VulnDB']['Vulnerability']['SolutionDate'],

        })

        return_outputs(readable_output=human_readable, outputs=ec, raw_response=res)


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


def test_module(client: Client, client_id, client_secret):
    """
    Performs basic get request to get item samples
    """
    client.get_oath_token(client_id, client_secret)


def vulndb_get_vuln_by_id_command(args: dict, client: Client):
    vulndb_id = args['vuln_id']

    res = client.http_request(f'/vulnerabilities/{vulndb_id}')

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_vendor_and_product_name_command(args: dict, client: Client):
    vendor_name = args['vendor_name']
    product_name = args['product_name']
    max_size = args.get('max_size')

    res = client.http_request(
        f'/vulnerabilities/find_by_vendor_and_product_name?vendor_name={vendor_name}&product_name={product_name}',
        max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_vendor_and_product_id_command(args: dict, client: Client):
    vendor_id = args['vendor_id']
    product_id = args['product_id']
    max_size = args.get('max_size')

    res = client.http_request(
        f'/vulnerabilities/find_by_vendor_and_product_id?vendor_id={vendor_id}&product_id={product_id}', max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_vendor_id_command(args: dict, client: Client):
    vendor_id = args['vendor_id']
    max_size = args.get('max_size')

    res = client.http_request(f'/vulnerabilities/find_by_vendor_id?vendor_id={vendor_id}', max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_product_id_command(args: dict, client: Client):
    product_id = args['product_id']
    max_size = args.get('max_size')

    res = client.http_request(f'/vulnerabilities/find_by_product_id?product_id={product_id}', max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vuln_by_cve_id_command(args: dict, client: Client):
    cve_id = args['cve_id']
    max_size = args.get('max_size')

    res = client.http_request(f'/vulnerabilities/{cve_id}/find_by_cve_id', max_size)

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_updates_by_dates_or_hours_command(args: dict, client: Client):
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    hours_ago = args.get('hours_ago')
    max_size = args.get('max_size')

    res = ""
    if start_date:
        url_suffix = f'/vulnerabilities/find_by_date?start_date={start_date}'
        if end_date:
            url_suffix += f'&end_date={end_date}'

        res = client.http_request(url_suffix, max_size)
    elif hours_ago is not None:
        res = client.http_request(f'/vulnerabilities/find_by_time?hours_ago={hours_ago}', max_size)
    else:
        return_error('Must provide either start date or hours ago.')

    vulndb_vulnerability_results_to_demisto_results(res)


def vulndb_get_vendor_command(args: dict, client: Client):
    vendor_id = args.get('vendor_id')
    vendor_name = args.get('vendor_name')
    max_size = args.get('max_size')

    res = ""
    if vendor_id is not None and vendor_name is not None:
        return_error('Provide either vendor id or vendor name or neither, not both.')
    elif vendor_id:
        res = client.http_request(f'/vendors/{vendor_id}', max_size)
    elif vendor_name:
        res = client.http_request(f'/vendors/by_name?vendor_name={vendor_name}', max_size)
    else:
        res = client.http_request('/vendors', max_size)

    vulndb_vendor_results_to_demisto_results(res)


def vulndb_get_product_command(args: dict, client: Client):
    vendor_id = args.get('vendor_id')
    vendor_name = args.get('vendor_name')
    max_size = args.get('max_size')

    res = ""
    if vendor_id is not None and vendor_name is not None:
        return_error('Provide either vendor id or vendor name or neither, not both.')
    elif vendor_id:
        res = client.http_request(f'/products/by_vendor_id?vendor_id={vendor_id}', max_size)
    elif vendor_name:
        res = client.http_request(f'/products/by_vendor_name?vendor_name={vendor_name}', max_size)
    else:
        res = client.http_request('/products', max_size)

    vulndb_product_results_to_demisto_results(res)


def vulndb_get_version_command(args: dict, client: Client):
    product_id = args.get('product_id')
    product_name = args.get('product_name')
    max_size = args.get('max_size')

    res = ""
    if product_id is not None and product_name is not None:
        return_error('Provide either product id or vendor name, not both.')
    elif product_id:
        res = client.http_request(f'/versions/by_product_id?product_id={product_id}', max_size)
    elif product_name:
        res = client.http_request(f'/versions/by_product_name?product_name={product_name}', max_size)
    else:
        res = ""
        demisto.debug(f"No product_id and no product_name -> {res=}")

    vulndb_product_results_to_demisto_results(res)


def vulndb_get_cve_command(args: dict, client: Client, dbot_score_reliability: DBotScoreReliability):
    cve_ids = args.get('cve_id', '') or args.get('cve', '')

    if not cve_ids:
        raise DemistoException("You must provide a value to the `cve` argument")

    cve_ids = argToList(cve_ids)
    max_size = args.get('max_size')
    command_results = []
    for cve_id in cve_ids:
        response = client.http_request(f'/vulnerabilities/{cve_id}/find_by_cve_id', max_size)
        results = response.get("results")
        if not results:
            return_error('Could not find "results" in the returned JSON')
        result = results[0]
        cvss_metrics_details = result.get("cvss_metrics", [])

        data = {
            "ID": cve_id,
            "CVSS": cvss_metrics_details[0].get("score", "0") if cvss_metrics_details else "0",
            "Published": result.get('vulndb_published_date', '').rstrip('Z'),
            "Modified": result.get('vulndb_last_modified', '').rstrip('Z'),
            "Description": result.get("description", ''),
        }

        cve_data = Common.CVE(
            id=data["ID"],
            cvss=data["CVSS"],
            published=data["Published"],
            modified=data["Modified"],
            description=data["Description"],
            dbot_score=Common.DBotScore(
                indicator=cve_id,
                indicator_type=DBotScoreType.CVE,
                integration_name="VulnDB",
                score=Common.DBotScore.NONE,
                reliability=dbot_score_reliability,
            ),
        )

        command_results.append(CommandResults(
            indicator=cve_data,
            readable_output=tableToMarkdown(f'Result for CVE ID: {cve_id}', data, removeNull=True),
            raw_response=response,
        ))
    return_results(command_results)


'''
Returns a PDF report summary of the vulnerability from VulnDB

Inputs:
    vuln_id: Unique ID for the vulnerability
Returns:
    file_entry: PDF report for the vulnerability
'''


def vulndb_get_vuln_report_command(args: dict, client: Client) -> fileResult:
    vulndb_id = args['vuln_id']
    res = client.http_file_request(f'/vulnerabilities/{vulndb_id}.pdf')

    # Byte data of the result file
    report_file = res.content

    file_entry = fileResult(f'VulnDB ID {vulndb_id}.pdf', report_file, file_type=EntryType.ENTRY_INFO_FILE)
    return_results(file_entry)


'''
Returns a list of CPE values for the given VulnDB vulnerability.

Inputs:
    vuln_id: Unique ID for the vulnerability
Returns:
    output: Sorted and deduplicated list of CPE values from VulnDB
'''


def vulndb_get_cpe_command(args: dict, client: Client) -> CommandResults:
    vulndb_id = args['vuln_id']

    res = client.http_request(f'/vulnerabilities/{vulndb_id}?show_cpe=true')
    all_cpes = []
    for product in res.get('vulnerability').get('products'):
        for version in product.get('versions'):
            for cpe in version.get('cpe'):
                all_cpes.append(cpe.get('cpe'))
    # Convert to set to deduplicate, then back to list to be sorted
    deduplicated_set = set(all_cpes)
    output = sorted(deduplicated_set)

    return_results(CommandResults(
        outputs_prefix='VulnDB.CPE.Value',
        outputs=output,
        readable_output=str(output),
        raw_response=res

    ))


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    # Remove trailing slash to prevent wrong URL path to service
    api_url = params['api_url']
    client_id = params.get('credentials', {}).get('identifier') or params.get('client_id')
    client_secret = params.get('credentials', {}).get('password') or params.get('client_secret')
    if not (client_id and client_secret):
        return_error('Please provide a Client ID and Secret')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    dbot_score_reliability = params['integration_reliability']
    client = Client(proxy, use_ssl, api_url, client_id, client_secret)
    args = demisto.args()
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module(client, client_id, client_secret)
            demisto.results('ok')
        if command == 'vulndb-get-vuln-by-id':
            vulndb_get_vuln_by_id_command(args, client)
        elif command == 'vulndb-get-vuln-by-vendor-and-product-name':
            vulndb_get_vuln_by_vendor_and_product_name_command(args, client)
        elif command == 'vulndb-get-vuln-by-vendor-and-product-id':
            vulndb_get_vuln_by_vendor_and_product_id_command(args, client)
        elif command == 'vulndb-get-vuln-by-vendor-id':
            vulndb_get_vuln_by_vendor_id_command(args, client)
        elif command == 'vulndb-get-vuln-by-product-id':
            vulndb_get_vuln_by_product_id_command(args, client)
        elif command == 'vulndb-get-vuln-by-cve-id':
            vulndb_get_vuln_by_cve_id_command(args, client)
        elif command == 'vulndb-get-vendor':
            vulndb_get_vendor_command(args, client)
        elif command == 'vulndb-get-product':
            vulndb_get_product_command(args, client)
        elif command == 'vulndb-get-version':
            vulndb_get_version_command(args, client)
        elif command == 'vulndb-get-updates-by-dates-or-hours':
            vulndb_get_updates_by_dates_or_hours_command(args, client)
        elif command == 'cve':
            vulndb_get_cve_command(args, client, dbot_score_reliability)
        elif command == 'vulndb-get-vuln-report-by-vuln-id':
            vulndb_get_vuln_report_command(args, client)
        elif command == 'vulndb-get-cpe-by-vuln-id':
            vulndb_get_cpe_command(args, client)
        else:
            return_error(f'{command} is not a supported command.')
    except Exception as e:
        error_message = f'Failed to execute {command} command. Error: {str(e)}'
        return_error(error_message)


if __name__ in ('__main__', 'builtins'):
    main()
