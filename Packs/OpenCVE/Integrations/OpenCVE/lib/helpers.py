import time
import requests

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
        published=cve.get('fields', {}).get('published'),
        modified=cve.get('fields', {}).get('modified')
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
        'rawJSON': {'value': cve.get('id'), 'type': 'CVE'},
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
            # 'cvssscore': largest(cve.get('cvss', {}).get('v2', None),
            #                 cve.get('cvss', {}).get('v3', None)),
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
