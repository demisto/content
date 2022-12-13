import time
import requests

from datetime import datetime, timedelta

from typing import Optional, Dict, List, Union
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

class OpenCVE():
    '''
    This is a Class for the OpenCVE APIs.
    The Postman used to create these is available here:
        https://www.postman.com/rfortress-pan/workspace/opencve/collection/22097521-c2b14aab-829a-41e1-9cb9-0d859345a2a1
    '''
    def __init__(self, url, username, password, verify_ssl, tlp, reliability):
        self.domain = url
        self.url = f'{url}/api/'
        self.username = username
        self.password = password
        self.headers = {
            'Content-Type': 'application/json'
        }
        self.verify_ssl = verify_ssl
        self.tlp = tlp
        self.reliability = reliability

        # Pagination is defined in the OpenCVE config file
        # https://opencve.io uses 20 for each value
        self.pagination = {
            'cves_per_page': 20,
            'vendors_per_page': 20,
            'products_per_page': 20,
            'cwes_per_page': 20,
            'reports_per_page': 20,
            'alerts_per_page': 20,
            'tags_per_page': 20,
            'activities_per_page': 20
        }
        self.rate_limit = 200     # False or delay in ms
        self.api_count = 0
        self.maps = {
            'HIGH': 'High (H)',
            'MEDIUM': 'Medium (M)',
            'LOW': 'Low (L)',
            'NONE': 'None (N)',
            'NETWORK': 'Network (N)',
            'ADJACENT': 'Adjacent (A)',
            'ADJACENT_NETWORK': 'Ajdacent Network (A)',
            'LOCAL': 'Local (L)',
            'PHYSICAL': 'Physical (P)',
            'REQUIRED': 'Required (R)',
            'UNCHANGED': 'Unchanged (U)',
            'CHANGED': 'Changed (C)',
            'NOT_DEFINED': 'Not Defined (X)',
            'FUNCTIONAL': 'Functional (F)',
            'PROOF-OF-CONCEPT': 'Proof-of-concept (P)',
            'UNPROVEN': 'Unproven (U)',
            'UNAVAILABLE': 'Unavailable (U)',
            'WORKAROUND': 'Workaround (W)',
            'TEMPRORARY_FIX': 'Temprorary Fix (T)',
            'OFFICIAL_FIX': 'Official Fix (O)',
            'PARTIAL': 'Partial (P)',
            'COMPLETE': 'Complete (C)',
            'SINGLE': 'Single (S)'
        }

    def _map(self, needle: str):
        if needle in self.maps:
            return self.maps[needle]
        return needle

    def _get(self, path: str, params: Optional[Dict] = {}):
        '''
        Builds an indicator list for the query
        Args:
            path: URI path to use
            params: Any optional params to be sent

        Returns:
            response: A dict of the response
        '''
        self.api_count += 1
        success_codes = [200]

        r = requests.get(f'{self.url}{path}', auth=(self.username, self.password),
                         params=params, headers=self.headers, verify=self.verify_ssl)

        if self.rate_limit is not False:
            time.sleep(self.rate_limit / 1000)

        if r.status_code in success_codes:
            return r.json()

        raise Exception(f'ERROR: [{r.status_code}] {r.text}')

    def get_my_vendors(self) -> CommandResults:
        '''
        List the vendors subscriptions of the authenticated user.

        Args:
            none
        Returns:
            A dict of the http response
        '''
        return self._get('account/subscriptions/vendors')

    def get_my_products(self) -> Dict:
        '''
        List the products subscriptions of the authenticated user.

        Args:
            none
        Returns:
            A dict of the http response
        '''
        return self._get('account/subscriptions/products')

    def get_cves(self, params: Optional[Dict] = {}) -> Dict:
        '''
        List the CVEs.

        Args:
            params: Available params are: search, vendor, product, cvss, cwe, page   (dict)
        Returns:
            A dict of the http response
        '''
        return self._get('cve')

    def get_cve(self, cve_id: str) -> Dict:
        '''
        Get the details of a specific CVE.

        Args:
            cve_id: The ID of the CVE to get        (str)
        Returns:
            A dict of the http response
        '''
        return self._get(f'cve/{cve_id}')

    def get_vendors(self, params: Optional[Dict] = {}) -> Dict:
        '''
        List the vendors.

        Args:
            params: Available params are: search, letter, page
        Returns:
            A dict of the http response
        '''
        return self._get('vendors', params=params)

    def get_vendor(self, vendor_name: str) -> Dict:
        '''
        Get a specific vendor.

        Args:
            vendor_name: The name of the vendor to get          (str)
        Returns:
            A dict of the http response
        '''
        return self._get(f'vendors/{vendor_name}')

    def get_cves_by_vendor(self, vendor_name: str, params: Optional[Dict] = {}) -> Dict:
        '''
        Get all CVEs by vendor name

        Args:
            vendor_name: The name of the vendor to get CVEs     (str)
            params:
                search: (optional): filter by keyword in summary
                product: (optional): filter by product name
                cvss: (optional): filter by CVSS (one of none, low, medium, high, critical)
                cwe: (optional): filter by CWE
                page: (optional, default: 1): the page to start
        Returns:
            A dict of the http response
        '''
        return self._get(f'vendors/{vendor_name}/cve')

    def get_vendor_products(self, vendor_name: str, params: Optional[Dict] = {}) -> Dict:
        '''
        List the products associated to a vendor.

        Args:
            vendor_name: the name of the vendor
            params:
                search: (optional): filter by keyword
                page: (optional, default: 1): the page to start

        Returns:
            A dict of the http response
        '''
        # Available params are: search, page
        return self._get(f'vendors/{vendor_name}/products', params=params)

    def get_vendor_product(self, vendor_name: str, product_name: str) -> Dict:
        '''
        Get a specific product of a vendor.

        Args:
            vendor_name: The name of the vendor
            product_name: The name of the product
        Returns:
            A dict of the http response
        '''
        return self._get(f'vendors/{vendor_name}/products/{product_name}')

    def get_cves_by_product(self, vendor_name: str, product_name: str, params: Optional[Dict] = {}) -> Dict:
        '''
        Get the list of CVEs associated to a product.

        Args:
            vendor_name: the name of the vendor
            product_name: the name of the vendor's product
            params:
                search: (optional): filter by keyword in summary
                cvss: (optional): filter by CVSS (one of none, low, medium, high, critical)
                cwe: (optional): filter by CWE
                page: (optional, default: 1): the page to start
        Returns:
            A dict of the http response
        '''
        # Available params are: search, cvss, cwe, page
        return self._get(f'vendors/{vendor_name}/products/{product_name}/cve',
                         params=params)

    def get_reports(self) -> Dict:
        '''
        List the reports of the authenticated user.

        Args:
            none
        Returns:
            A dict of the http response
        '''
        return self._get('reports')

    def get_report(self, report_id: str) -> Dict:
        '''
        Get a specific report.

        Args:
            report_id: the id of the report to get
        Returns:
            A dict of the http response
        '''
        return self._get(f'reports/{report_id}')

    def get_alerts(self, report_id: str, params: Optional[Dict] = {}) -> Dict:
        '''
        List the alerts of a report.

        Args:
            report_id: the id of the report to get
            params:
                page: (optional, default: 1): the page to start
        Returns:
            A dict of the http response
        '''
        return self._get(f'reports/{report_id}/alerts', params=params)

    def get_alert(self, report_id: str, alert_id: str) -> Dict:
        '''
        Get the details of an alert.

        Args:
            report_id: the id of the report to get
            alert_id: the id of the alert to get
        Returns:
            A dict of the http response
        '''
        # Available params are: page
        return self._get(f'reports/{report_id}/alerts/{alert_id}')


def largest(*vals: Union[int, float]):
    '''
    Given a list of numbers, return the largest

    Args:
        vals: Integers to be comapred
    Returns:
        The largest integer
    '''
    largest = None
    for val in vals:
        if type(val) == int or type(val) == float:
            if largest is None or val > largest:
                largest = val

    return largest


def cve_to_warroom(cve: Dict) -> Dict[str, str]:
    '''
    Returning a cve structure with the following fields:
    * ID: The cve ID.
    * CVSS: The cve score scale/
    * Published: The date the cve was published.
    * Modified: The date the cve was modified.
    * Description: the cve's description

    Args:
        cve: The dict of a CVE
    Returns:
        The cve structure.
    '''
    return {
        'ID': cve.get('value', ''),
        'CVSS': cve.get('fields', {}).get('cvss', 'N/A'),
        'Published': cve.get('fields', {}).get('published', 'N/A'),
        'Modified': cve.get('fields', {}).get('modified', 'N/A'),
        'Description': cve.get('fields', {}).get('cvedescription', 'N/A')
    }


def cve_to_indicator(cve: Dict) -> Common.CVE:
    '''
    Converts a parsed_cve to a Common.CVE. This can be used in
        CommandResults() as the indicator argument.

    Args:
        cve: A single parsed_cve
    Returns:
        A Common.CVE object
    '''
    return Common.CVE(
        id=cve.get('value'),
        cvss=cve.get('fields', {}).get('cvss'),
        description=cve.get('fields', {}).get('summary'),
        published=cve.get('fields', {}).get('published').replace('Z', ''),
        modified=cve.get('fields', {}).get('modified').replace('Z', '')
    )


def get_score_color(score: int, version: Optional[int] = 1) -> str:
    '''
    Creates a markdown string representing the score provided

    Args
        score: 0-10 CVSS score                      (int)
        version: 1 or 2 for the different formats   (int)
    Returns
        a string with the results
    '''

    if score >= 7:
        score_color = '{{background:#fd0800}}({{color:#f3f3f3}}(___))'
    elif score >= 4 and score < 7:
        score_color = '{{background:#fd9a14}}({{color:#f3f3f3}}(___))'
    elif score < 4:
        score_color = '{{background:#b7b7b7}}({{color:#f3f3f3}}(___))'
    else:
        score_color = 'Error: {score}'

    if version == 1:
        score_color = score_color.replace('___', f' {score} ')
        score_color = f'# <-:-> {score_color}'
    if version == 2:
        distance = ' ' * round((score * 10) / 3)
        score_color = score_color.replace('___', f'{distance}{score}{distance}')
        score_color = f'# <-:-> {score_color}'

    return score_color


def parse_cve(ocve: OpenCVE, args: Dict, cve: Dict) -> Dict[str, str]:
    '''
    This method parses the CVE information and creates a dict of the results

    Args:
        ocve: OpenCVE object
        args: Values input from XSOAR
        cve: The raw CVE from OpenCVE
    Returns
        A dict of the CVE for ingestion into XSOAR
    '''
    parsed_cve = {
        'type': 'CVE',
        'value': cve.get('id'),
        'reliability': args.get('reliability', None),
        'fields': {
            'description': f'### {cve.get("summary", "No description available...")}',
            'cvedescription': cve.get('summary', 'No description available...'),
            'opencvelink': f'{ocve.domain}/cve/{cve.get("id")}',
            'nvdlink': f'https://nvd.nist.gov/vuln/detail/{cve.get("id")}',
            'mitrelink': f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.get("id")}',
            'published': cve.get('created_at'),
            'modified': cve.get('updated_at'),
            'cvss': largest(cve.get('cvss', {}).get('v2', None),
                            cve.get('cvss', {}).get('v3', None)),
            'trafficlightprotocol': 'White'
        }
    }

    # Save the vendors and the products
    if 'vendors' in cve:
        vendors = []
        products = []
        tags = []
        for vendor in cve['vendors']:
            vendors.append(vendor)
            tags.append(vendor)
            for product in cve['vendors'][vendor]:
                products.append(product)
                tags.append(product)
        parsed_cve['fields']['vendors'] = vendors
        parsed_cve['fields']['products'] = products
        parsed_cve['fields']['tags'] = tags

    if 'raw_nvd_data' in cve:
        if 'cve' in cve['raw_nvd_data']:
            # Save the references
            if 'references' in cve['raw_nvd_data']['cve']:
                if 'reference_data' in cve['raw_nvd_data']['cve']['references']:
                    references = []

                    for reference in cve['raw_nvd_data']['cve']['references']['reference_data']:
                        new_reference = {
                            'name': reference.get('name', None),
                            'link': reference.get('url', None),
                            'resource': reference.get('tags', None),
                            'referencesource': reference.get('refsource', None)
                        }
                        references.append(new_reference)

                    parsed_cve['fields']['references'] = references

        if 'impact' in cve['raw_nvd_data']:
            # Save the cvss v2 info
            cvssV2 = None
            if 'baseMetricV2' in cve['raw_nvd_data']['impact']:
                if 'cvssV2' in cve['raw_nvd_data']['impact']['baseMetricV2']:
                    cvssV2 = cve['raw_nvd_data']['impact']['baseMetricV2']['cvssV2']
                    score_color = get_score_color(cvssV2.get('baseScore'), version=2)

                    # Set the cvss v2 fields
                    parsed_cve['fields']['cvssv2bigscore'] = f'{score_color}'
                    parsed_cve['fields']['cvssv2score'] = cvssV2.get('baseScore', None)
                    parsed_cve['fields']['cvssv2accessvectorav'] = ocve._map(cvssV2.get('accessVector', None))
                    parsed_cve['fields']['cvssv2vector'] = ocve._map(cvssV2.get('vectorString', None))
                    parsed_cve['fields']['cvssv2authenticationau'] = ocve._map(cvssV2.get('authentication', None))
                    parsed_cve['fields']['cvssv2integrityimpact'] = ocve._map(cvssV2.get('integrityImpact', None))
                    parsed_cve['fields']['cvssv2accesscomplexityac'] = ocve._map(cvssV2.get('accessComplexity', None))
                    parsed_cve['fields']['cvssv2availabilityimpacta'] = ocve._map(cvssV2.get('availabilityImpact', None))
                    parsed_cve['fields']['cvssv2confidentialityimpactc'] = ocve._map(cvssV2.get('confidentialityImpact', None))

            # Save the cvss v3 info
            cvssV3 = None
            if 'baseMetricV3' in cve['raw_nvd_data']['impact']:
                if 'cvssV3' in cve['raw_nvd_data']['impact']['baseMetricV3']:
                    cvssV3 = cve['raw_nvd_data']['impact']['baseMetricV3']['cvssV3']
                    score_color = get_score_color(cvssV3.get('baseScore'), version=2)

                    # Set the cvss v3 fields
                    parsed_cve['fields']['cvssv3bigscore'] = f'{score_color}'
                    parsed_cve['fields']['cvssv3score'] = cvssV3.get('baseScore', None)
                    parsed_cve['fields']['cvssv3scopes'] = ocve._map(cvssV3.get('scope', None))
                    parsed_cve['fields']['cvssv3attackvectorav'] = ocve._map(cvssV3.get('attackVector', None))
                    parsed_cve['fields']['cvssv3vector'] = ocve._map(cvssV3.get('vectorString', None))
                    parsed_cve['fields']['cvssv3integrityimpacti'] = ocve._map(cvssV3.get('integrityImpact', None))
                    parsed_cve['fields']['cvssv3userinteractionui'] = ocve._map(cvssV3.get('userInteraction', None))
                    parsed_cve['fields']['cvssv3attackcomplexityac'] = ocve._map(cvssV3.get('attackComplexity', None))
                    parsed_cve['fields']['cvssv3availabilityimpacta'] = ocve._map(cvssV3.get('availabilityImpact', None))
                    parsed_cve['fields']['cvssv3privilegesrequiredpr'] = ocve._map(cvssV3.get('privilegesRequired', None))

    return parsed_cve


def create_cves(parsed_cves: List[Dict[str, str]]):
    '''
    Creates CVEs in bulk.

    Args:
        parsed_cves: A list of parsed_cves
    Returns:
        Nothing
    '''
    for iter_ in batch(parsed_cves, batch_size=2000):
        demisto.createIndicators(iter_)


def valid_cve_id_format(cve_id: str) -> bool:
    '''
    Validates that the given cve_id is a valid cve ID.
    For more details see: https://cve.mitre.org/cve/identifiers/syntaxchange.html

    Args:
        cve_id: ID to validate
    Returns:
        True if cve_id is a valid cve ID else False
    '''
    return bool(re.match(cveRegex, cve_id))


def dedupe_cves(cves: List[Dict[str, str]]) -> List[Dict[str, str]]:
    '''
    Loop through a list and remove duplicates

    Args
        cves: a list of CVEs to iterate through
    Return
        A deduplicated list of results
    '''
    tracking = []
    deduped = []
    for cve in cves:
        if cve['value'] not in tracking:
            tracking.append(cve['value'])
            deduped.append(cve)
    return deduped

# Commands
def test_module(ocve: OpenCVE) -> str:
    '''
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        ocve: OpenCVE object            (obj)
    Returns:
        'ok' if test passed, anything else will fail the test.
    '''
    try:
        ocve.get_my_vendors()

    except Exception as e:
        if 'Read timed out.' not in str(e):
            raise

    return 'ok'


def cve_latest(ocve: OpenCVE, args: Dict) -> CommandResults:
    '''
    Gets the latest reports and pulls all alerts. From each alert all CVEs
        are looped through and returned as a CommandResult.

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        Single CommandResults with a list of CVEs
    '''
    parsed_cves = []
    lastRun = args.get('lastRun', {})

    if lastRun == {}:
        # No timestamp for lastRun was given. Default to 7 days ago
        now = datetime.now()
        fetch_time = now - timedelta(days=7)
    else:
        # Convert lastRun timestamp to object
        fetch_time = datetime.strptime(lastRun['fetch_time'], '%Y-%m-%dT%H:%M:%SZ')

    reports = ocve.get_reports()

    for report in reports:
        # Check to see if this report is prior to the lastRun time
        created = datetime.strptime(report['created_at'], '%Y-%m-%dT%H:%M:%SZ')
        if created < fetch_time:
            continue

        alerts = ocve.get_alerts(report['id'])
        for alert in alerts:
            cve_id = alert['cve']
            response = ocve.get_cve(cve_id)
            parsed_cve = parse_cve(ocve, args, response)
            parsed_cves.append(parsed_cve)

    # Create the IOCs that have been gathered so far
    parsed_cves = dedupe_cves(parsed_cves)
    create_cves(parsed_cves)

    # Update the lastRun timestamp
    now = datetime.now()                                # Get an object of the current timestamp
    lastRun = now.strftime('%Y-%m-%dT%H:%M:%SZ')        # Convert the object to a string of the current timestamp
    demisto.setLastRun({                                # Save the current run info as the lastRun variable
        'fetch_time': lastRun,
        'fetch_count': len(parsed_cves)
    })

    return CommandResults(
        outputs_prefix='OpenCVE.CVE',
        outputs=parsed_cves
    )


def get_cve(ocve: OpenCVE, args: Dict) -> List[CommandResults]:
    '''
    Gets a single or multiple CVEs. Multiple are separated with a comma.

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        A list of CommandResults. Each CommandResult has a single CVE
    '''
    cves = args.get('cve_id', None)
    cves = cves.split(',')

    results = []
    parsed_cves = []

    for cve in cves:
        cve_info = ocve.get_cve(cve)
        parsed_cve = parse_cve(ocve, args, cve_info)
        parsed_cves.append(parsed_cve)

        pretty_results = cve_to_warroom(parsed_cve)
        readable = tableToMarkdown(parsed_cve.get('value'), pretty_results)
        results.append(CommandResults(
            outputs_prefix='OpenCVE.CVE',
            outputs=parsed_cve,
            readable_output=readable,
            raw_response=cve_info,
            indicator=cve_to_indicator(parsed_cve)
        ))

    ## Test this to verify if it is neeeded
    # create_cves(parsed_cves)

    return results


def get_my_vendors(ocve: OpenCVE) -> CommandResults:
    '''
    Gets the vendors that the registered user is subscribed to.

    Args:
        ocve: OpenCVE object
    Returns:
        CommandResults with a list of vendors
    '''
    my_vendors = ocve.get_my_vendors()
    return CommandResults(
        outputs_prefix='OpenCVE.myVendors',
        outputs=my_vendors
    )


def get_my_products(ocve: OpenCVE) -> CommandResults:
    '''
    Gets the products taht the registered user is subscribed to

    Args:
        ocve: OpenCVE object
    Returns:
        CommandResults with a list of products
    '''
    my_products = ocve.get_my_products()
    return CommandResults(
        outputs_prefix='OpenCVE.myProducts',
        outputs=my_products
    )


def get_vendor(ocve: OpenCVE, args: Dict) -> CommandResults:
    '''
    Get a specific vendor machine name and human readable name

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        CommandResults with a dict of the results
    '''
    vendor = args.get('vendor_name', None)
    return CommandResults(
        outputs_prefix=f'OpenCVE.{vendor}',
        outputs=ocve.get_vendor(vendor)
    )


def get_vendors(ocve: OpenCVE, args: Dict) -> CommandResults:
    '''
    Gets vendors based on filter criteria

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        CommandResults with a list of dicts of vendors
    '''
    params = {}
    if 'search' in args:
        params['search'] = args.get('search')
    if 'letter' in args:
        params['letter'] = args.get('letter')
    if 'page' in args:
        params['page'] = args.get('page')

    return CommandResults(
        outputs_prefix='OpenCVE.Vendors',
        outputs=ocve.get_vendors(params)
    )


def get_vendor_cves(ocve: OpenCVE, args: Dict) -> List[CommandResults]:
    '''
    Gets CVEs related to a vendor

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        A list of CommandResults with a single CVE per CommandResult
    '''
    vendor = args.get('vendor_name', None)
    params = {}
    if 'search' in args:
        params['search'] = args.get('search')
    if 'product' in args:
        params['product'] = args.get('product')
    if 'cvss' in args:
        params['cvss'] = args.get('cvss')
    if 'cwe' in args:
        params['cwe'] = args.get('cwe')
    if 'page' in args:
        params['page'] = args.get('page')

    cves = ocve.get_cves_by_vendor(vendor, params=params)

    results = []
    parsed_cves = []

    for cve in cves:
        cve_info = ocve.get_cve(cve['id'])
        parsed_cve = parse_cve(ocve, args, cve_info)
        parsed_cves.append(parsed_cve)

        pretty_results = cve_to_warroom(parsed_cve)
        readable = tableToMarkdown(cve.get('value'), pretty_results)
        results.append(CommandResults(
            outputs_prefix=f'OpenCVE.{vendor}.CVE',
            outputs=parsed_cve,
            readable_output=readable,
            raw_response=parsed_cve,
            indicator=cve_to_indicator(parsed_cve)
        ))

    create_cves(parsed_cves)
    return results


def get_products(ocve: OpenCVE, args: Dict) -> CommandResults:
    '''
    Gets a list of products for a specific vendor based on the provided filters

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        CommandREsults with a list of products
    '''
    vendor = args.get('vendor_name', None)
    params = {}
    if 'search' in args:
        params['search'] = args.get('search', None)
    if 'page' in args:
        params['page'] = args.get('page', None)

    return CommandResults(
        outputs_prefix=f'OpenCVE.{vendor}.Products',
        outputs=ocve.get_vendor_products(vendor, params=params)
    )


def get_product(ocve: OpenCVE, args: Dict) -> CommandResults:
    '''
    Gets info for a specific product

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        CommandResults with a dict of the results
    '''
    vendor = args.get('vendor_name', None)
    product = args.get('product_name', None)

    return CommandResults(
        outputs_prefix=f'OpenCVE.{vendor}.{product}',
        outputs=ocve.get_vendor_product(vendor, product)
    )


def get_product_cves(ocve: OpenCVE, args: Dict) -> List[CommandResults]:
    '''
    Gets CVEs related to a specific product.

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        A list of CommandResults with one CVE per CommandResult
    '''
    vendor = args.get('vendor_name', None)
    product = args.get('product_name', None)
    params = {}

    if 'search' in args:
        params['search'] = args.get('search', None)
    if 'cvss' in args:
        params['cvss'] = args.get('cvss', None)
    if 'cwe' in args:
        params['cwe'] = args.get('cwe', None)
    if 'page' in args:
        params['page'] = args.get('page', None)

    cves = ocve.get_cves_by_product(vendor, product, params=params)

    results = []
    parsed_cves = []

    for cve in cves:
        cve_info = ocve.get_cve(cve['id'])
        parsed_cve = parse_cve(ocve, args, cve_info)
        parsed_cves.append(parsed_cve)

        pretty_results = cve_to_warroom(parsed_cve)
        readable = tableToMarkdown(cve.get('value'), pretty_results)
        results.append(CommandResults(
            outputs_prefix=f'OpenCVE.{vendor}.CVE',
            outputs=parsed_cve,
            readable_output=readable,
            raw_response=parsed_cve,
            indicator=cve_to_indicator(parsed_cve)
        ))

    create_cves(parsed_cves)
    return results


def get_reports(ocve: OpenCVE) -> CommandResults:
    '''
    Gets all reports

    Args:
        ocve: OpenCVE object
    Returns:
        CommandResult with a list of reports
    '''
    return CommandResults(
        outputs_prefix='OpenCVE.Reports',
        outputs=ocve.get_reports()
    )


def get_report(ocve: OpenCVE, args: Dict) -> CommandResults:
    '''
    Gets a specific report

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        CommandResults with a dict of the report
    '''
    report_id = args.get('report_id', None)

    return CommandResults(
        outputs_prefix=f'OpenCVE.Reports.{report_id}',
        outputs=ocve.get_report(report_id)
    )


def get_alerts(ocve: OpenCVE, args: Dict) -> CommandResults:
    '''
    Gets all alerts from a report

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        CommandResults with a list of alerts
    '''
    params = {}
    report_id = args.get('report_id', None)
    if 'page' in args:
        params['page'] = args.get('page', None)

    return CommandResults(
        outputs_prefix='OpenCVE.Reports.Alerts',
        outputs=ocve.get_alerts(report_id, params=params)
    )


def get_alert(ocve: OpenCVE, args: Dict) -> CommandResults:
    '''
    Gets a specific alert

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        CommandResults witha dict of the alert
    '''
    report_id = args.get('report_id', None)
    alert_id = args.get('alert_id', None)

    return CommandResults(
        outputs_prefix=f'OpenCVE.Reports.Alerts.{alert_id}',
        outputs=ocve.get_alert(report_id, alert_id)
    )


def main():
    params = demisto.params()
    url = params.get('url', 'https://opencve.io')
    username = params.get('username')
    password = params.get('password')
    verify_ssl = not params.get('insecure', True)
    tlp = params.get('tlp', 'White')
    reliability = params.get('feedReliability', DBotScoreReliability.A)

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception('Please provide a valid value for the Source Reliability parameter.')

    # Instantiate the OpenCVE object
    ocve = OpenCVE(url=url, username=username, password=password,
                   verify_ssl=verify_ssl, tlp=tlp, reliability=reliability)

    command = demisto.command()
    args = demisto.args()

    LOG(f'Command being called is {command}')
    try:
        if command == 'test-module':
            return_outputs(*test_module(ocve))

        elif command == 'cve-latest' or command == 'fetch-indicators':
            return_results(cve_latest(ocve, args))

        elif command == 'cve' or command == 'ocve-get-cve':
            return_results(get_cve(ocve, args))

        elif command == 'ocve-get-my-vendors':
            return_results(get_my_vendors(ocve))

        elif command == 'ocve-get-my-products':
            return_results(get_my_products(ocve))

        elif command == 'ocve-get-vendors':
            return_results(get_vendors(ocve, args))

        elif command == 'ocve-get-vendor':
            return_results(get_vendor(ocve, args))

        elif command == 'ocve-get-vendor-cves':
            return_results(get_vendor_cves(ocve, args))

        elif command == 'ocve-get-products':
            return_results(get_products(ocve, args))

        elif command == 'ocve-get-product':
            return_results(get_product(ocve, args))

        elif command == 'ocve-get-product-cves':
            return_results(get_product_cves(ocve, args))

        elif command == 'ocve-get-reports':
            return_results(get_reports(ocve))

        elif command == 'ocve-get-report':
            return_results(get_report(ocve, args))

        elif command == 'ocve-get-alerts':
            return_results(get_alerts(ocve, args))

        elif command == 'ocve-get-alert':
            return_results(get_alert(ocve, args))

        else:
            raise NotImplementedError(f'{command} is not an existing CVE Search command')

    except Exception as err:
        return_error(f'Failed to execute {command} command. Error: {str(err)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
