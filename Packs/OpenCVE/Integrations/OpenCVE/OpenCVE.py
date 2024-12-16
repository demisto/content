import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime, timedelta


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, server_url, verify, proxy, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, auth=auth)

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
            'ADJACENT_NETWORK': 'Adjacent Network (A)',
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
            'TEMPORARY_FIX': 'Temporary Fix (T)',
            'OFFICIAL_FIX': 'Official Fix (O)',
            'PARTIAL': 'Partial (P)',
            'COMPLETE': 'Complete (C)',
            'SINGLE': 'Single (S)'
        }

    def _map(self, needle: str):
        if needle in self.maps:
            return self.maps[needle]
        return needle

    def get_my_vendors_request(self):
        """
        list the vendors subscriptions of the authenticated user.

        Args:
            none
        Returns:
            A dict of the http response
        """
        response = self._http_request('GET', 'account/subscriptions/vendors')
        return response

    def get_my_products_request(self) -> dict:
        """
        list the products subscriptions of the authenticated user.

        Args:
            none
        Returns:
            A dict of the http response
        """
        response = self._http_request('GET', 'account/subscriptions/products')
        return response

    def get_cve_request(self, cve_id='', params: dict = {}) -> dict:
        """
        list the CVEs.

        Args:
            params: Available params are: search, vendor, product, cvss, cwe, page   (dict)
        Returns:
            A dict of the http response
        """
        if cve_id:
            return self._http_request('GET', f'cve/{cve_id}')

        else:
            return self._http_request(method='GET', url_suffix='cve', params=params)

    def get_vendors_request(self, vendor: str = '', params: dict | None = {}) -> dict:
        """
        list the vendors.

        Args:
            params: Available params are: search, letter, page
        Returns:
            A dict of the http response
        """

        if vendor:
            return self._http_request('GET', f'vendors/{vendor}')

        else:
            return self._http_request('GET', 'vendors', params=params)

    def get_cves_by_vendor_request(self, vendor_name: str, params: dict | None = {}) -> dict:
        """
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
        """
        response = self._http_request('GET', f'vendors/{vendor_name}/cve')
        return response

    def get_vendor_products_request(self, vendor_name: str, product_name: str = '', params: dict = {}) -> dict:
        """
        Get a specific product of a vendor.

        Args:
            vendor_name: The name of the vendor
            product_name: The name of the product
        Returns:
            A dict of the http response
        """
        if vendor_name and product_name:
            return self._http_request('GET', f'vendors/{vendor_name}/products/{product_name}')

        else:
            return self._http_request('GET', f'vendors/{vendor_name}/products', params=params)

    def get_cves_by_product_request(self, vendor_name: str, product_name: str, params: dict | None = {}) -> dict:
        """
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
        """
        # Available params are: search, cvss, cwe, page
        response = self._http_request('GET', f'vendors/{vendor_name}/products/{product_name}/cve',
                                      params=params)
        return response

    def get_reports_request(self, report_id: str = '', params: dict = {}) -> dict:
        """
        Get a specific report.

        Args:
            report_id: the id of the report to get
        Returns:
            A dict of the http response
        """
        if report_id:
            return self._http_request('GET', f'reports/{report_id}')

        else:
            return self._http_request('GET', 'reports', params=params)

    def get_alerts_request(self, report_id: str, alert_id: str = '', params: dict = {}) -> dict:
        """
        Get the details of an alert.

        Args:
            report_id: the id of the report to get
            alert_id: the id of the alert to get
        Returns:
            A dict of the http response
        """
        # Available params are: page
        if report_id and alert_id:
            return self._http_request('GET', f'reports/{report_id}/alerts/{alert_id}')

        else:
            return self._http_request('GET', f'reports/{report_id}/alerts', params=params)


class OpenCVE():
    """
    This is a Class for the OpenCVE APIs.
    The Postman used to create these is available here:
        https://www.postman.com/rfortress-pan/workspace/opencve/collection/22097521-c2b14aab-829a-41e1-9cb9-0d859345a2a1
    """

    def __init__(self, tlp):
        self.tlp = tlp

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
            'ADJACENT_NETWORK': 'Adjacent Network (A)',
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
            'TEMPORARY_FIX': 'Temporary Fix (T)',
            'OFFICIAL_FIX': 'Official Fix (O)',
            'PARTIAL': 'Partial (P)',
            'COMPLETE': 'Complete (C)',
            'SINGLE': 'Single (S)'
        }

    def _map(self, needle: str):
        if needle in self.maps:
            return self.maps[needle]
        return needle


def parse_cpes(nodes: list) -> list[Common.CPE]:
    """
    Parse nodes to get CPEs for the CVE
    :param nodes: A list of nodes
    :return: A set of CPEs
    """
    def parse_children(node: dict) -> set:
        """
        Check each chiled within the nodes for CPEs
        :param node: A single node of CPEs
        :return: A set of CPEs
        """
        final_cpes: set = set()
        children = node.get('children', [])

        if children:
            for child in node.get('children', []):
                final_cpes = final_cpes.union(parse_children(child))

        cpes = node.get('cpe_match', [])

        for cpe in cpes:
            if cpe.get('vulnerable', False):
                final_cpes.add(cpe.get('cpe23Uri'))

        return final_cpes

    vulnerable_products: set = set()

    for node in nodes:
        vulnerable_products = vulnerable_products.union(parse_children(node))

    return [Common.CPE(cpe) for cpe in vulnerable_products]


def cve_to_warroom(cve: dict) -> dict[str, str]:
    """
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
    """
    return {
        'ID': cve.get('value', ''),
        'CVSS Score': cve.get('fields', {}).get('cvssscore', 'N/A'),
        'Published': cve.get('timestamp', 'N/A'),
        'Modified': cve.get('modified', 'N/A'),
        'Description': cve.get('fields', {}).get('description', 'N/A')
    }


def cve_to_indicator(cve: dict, ocve: OpenCVE, relationships: list) -> Common.CVE:
    """
    Converts a parsed_cve to a Common.CVE. This can be used in
        CommandResults() as the indicator argument.

    Args:
        cve: A single parsed_cve
    Returns:
        A Common.CVE object
    """

    fields = cve.get('fields', {})

    indicator = Common.CVE(
        id=cve.get('value'),
        cvss=fields.get('cvssscore', ''),
        cvss_score=fields.get('cvssscore', ''),
        description=fields.get('description', ''),
        published=cve.get('timestamp', '').replace('Z', ''),
        modified=cve.get('modified', '').replace('Z', ''),
        cvss_version=fields.get('cvssversion', ''),
        cvss_vector=fields.get('cvssvector', ''),
        traffic_light_protocol=fields.get("trafficlightprotocol", ocve.tlp)
    )

    publications = [Common.Publications(title=publication['title'],
                                        source=publication['source'],
                                        link=publication['link']) for publication in fields.get('publications', [])]

    if publications:
        indicator.publications = publications

    if fields.get('nodes', {}):
        indicator.vulnerable_products = parse_cpes(fields.get('nodes'))

    if fields.get('tags', []):
        indicator.tags = fields.get('tags')

    if relationships:
        indicator.relationships = relationships

    if fields.get('cvsstable', []):
        indicator.cvss_table = fields.get('cvsstable')

    return indicator


def parse_tags(vendors: dict, cve_id: str, cwes: list) -> tuple[list[EntityRelationship], list]:
    """
    Parse the tags out of the `vendors` key
    :param vendors: A dict of vendors and products as values
    :return: set of tags for XSOAR
    """
    def clean_tag(cpe):
        """
        Clean up a single tag
        :param cpe: A single tag string
        :return: clean tag string
        """
        return cpe.replace('_', ' ').replace('\\', '').capitalize()

    tags = {clean_tag(vendor) for vendor in vendors}
    relationships = []
    relationships.extend([EntityRelationship(name="targets",
                                             entity_a=cve_id,
                                             entity_a_type="cve",
                                             entity_b=vendor,
                                             entity_b_type="identity") for vendor in tags])

    for vendor in vendors.values():
        products = {clean_tag(product) for product in vendor}
        tags = tags | products | set(cwes)
        relationships.extend([EntityRelationship(name="targets",
                                                 entity_a=cve_id,
                                                 entity_a_type="cve",
                                                 entity_b=product,
                                                 entity_b_type="software") for product in products])

    return relationships, list(tags)


def parse_cve(ocve: OpenCVE, cve: dict):
    """
    This method parses the CVE information and creates a dict of the results

    Args:
        ocve: OpenCVE object
        cve: The raw CVE from OpenCVE
    Returns
        A dict of the CVE for ingestion into XSOAR
    """

    cvss_version = None
    if cve.get('cvss', None) is not None:
        if cve['cvss'].get('v3', None) is not None:
            cvss_version = 3
        elif cve['cvss'].get('v2', None) is not None:
            cvss_version = 2

    parsed_cve: dict = {
        'type': 'CVE',
        'value': cve.get('id'),
        'timestamp': cve.get('created_at'),
        'modified': cve.get('updated_at'),
        'fields': {
            'description': f'{cve.get("summary", "No description available")}',
            'trafficlightprotocol': ocve.tlp
        }
    }

    # Save the vendors and the products
    vendors = cve.get('vendors', {})
    cwes = cve.get('cwes', [])
    relationships, tags = parse_tags(vendors, parsed_cve.get('value', ''), cwes)
    parsed_cve['fields']['tags'] = tags
    parsed_cve['relationships'] = [relationship.to_entry() for relationship in relationships if relationship.to_entry()]

    references = cve.get('raw_nvd_data', {}).get('cve', {}).get('references', {}).get('reference_data', [])
    parsed_cve['fields']['publications'] = [{'title': reference.get('name', None),
                                             'source': reference.get('source', None),
                                             'link': reference.get('url', None)} for reference in references]

    cvssV2 = None
    cvssV3 = None

    impact = cve.get('raw_nvd_data', {}).get('impact', '')
    if impact:
        if cvss_version == 3:
            cvssV3 = cve['raw_nvd_data']['impact']['baseMetricV3']['cvssV3']

            # Set the cvss v3 fields
            parsed_cve['fields']['cvssscore'] = cvssV3.get('baseScore')
            parsed_cve['fields']['cvssvector'] = ocve._map(cvssV3.get('vectorString', None))
            parsed_cve['fields']['cvsstable'] = [
                {'metrics': 'Scope', 'value': ocve._map(cvssV3.get('scope', None))},
                {'metrics': 'Attack Vector', 'value': ocve._map(cvssV3.get('attackVector', None))},
                {'metrics': 'Integrity', 'value': ocve._map(cvssV3.get('integrityImpact', None))},
                {'metrics': 'User Interaction', 'value': ocve._map(cvssV3.get('userInteraction', None))},
                {'metrics': 'Attack Complexity', 'value': ocve._map(cvssV3.get('attackComplexity', None))},
                {'metrics': 'Availability Impact', 'value': ocve._map(cvssV3.get('availabilityImpact', None))},
                {'metrics': 'Privileges Required', 'value': ocve._map(cvssV3.get('privilegesRequired', None))}
            ]

            if cvss_version_regex := re.match('CVSS:(?P<version>.+?)/', parsed_cve['fields']['cvssvector']):
                # Update cvss version with subversion
                parsed_cve['fields']['cvssversion'] = cvss_version_regex.group("version")

        elif cvss_version == 2:
            cvssV2 = cve['raw_nvd_data']['impact']['baseMetricV2']['cvssV2']

            # Set the cvss v2 fields
            parsed_cve['fields']['cvssscore'] = cvssV2.get('baseScore')
            parsed_cve['fields']['cvssvector'] = ocve._map(cvssV2.get('vectorString', None))
            parsed_cve['fields']['cvsstable'] = [
                {'metrics': 'Access Vector', 'value': ocve._map(cvssV2.get('accessVector', None))},
                {'metrics': 'Authentication', 'value': ocve._map(cvssV2.get('authentication', None))},
                {'metrics': 'Integrity Impact', 'value': ocve._map(cvssV2.get('integrityImpact', None))},
                {'metrics': 'Complexity', 'value': ocve._map(cvssV2.get('accessComplexity', None))},
                {'metrics': 'Availability', 'value': ocve._map(cvssV2.get('availabilityImpact', None))},
                {'metrics': 'Confidentiality', 'value': ocve._map(cvssV2.get('confidentialityImpact', None))}
            ]

    # Backwards compatibility, the configuration used to be a dict. Now it is a list.
    configurations = cve.get('raw_nvd_data', {}).get('configurations')
    nodes = []
    if isinstance(configurations, dict):
        nodes = configurations.get('nodes', [])
    elif isinstance(configurations, list):
        for config in configurations:
            nodes.extend(config.get('nodes', []))
    # Design decision: The nodes are aggregated into a single list, this means we won't support 'AND' Statements in CPE matching,
    # As it's also not supported in XSOAR platform.
    parsed_cve['fields']['nodes'] = nodes
    parsed_cve['fields']['cwes'] = cve.get('cwes', [])

    # To handle the case where the CVSS score is found under the "metrics" key
    if not parsed_cve['fields'].get('cvssscore'):
        cvss = cve.get('cvss', {})
        parsed_cve['fields']['cvssscore'] = cvss.get('v3') or cvss.get('v2')
    return relationships, parsed_cve


def valid_cve_format(cve_id: str) -> bool:
    """
    Validates that the given cve_id is a valid cve ID.
    For more details see: https://cve.mitre.org/cve/identifiers/syntaxchange.html

    Args:
        cve_id: ID to validate
    Returns:
        True if cve_id is a valid cve ID else False
    """
    return bool(re.match(cveRegex, cve_id))


def dedupe_cves(cves: list[dict[str, str]]) -> list[dict[str, str]]:
    """
    Loop through a list and remove duplicates

    Args
        cves: a list of CVEs to iterate through
    Return
        A deduplicated list of results
    """
    tracking = []
    deduped = []
    for cve in cves:
        if cve['value'] not in tracking:
            tracking.append(cve['value'])
            deduped.append(cve)
    return deduped


# Commands
def module_test_command(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Client object            (obj)
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.get_my_vendors_request()
        return 'ok'

    except Exception:
        demisto.error('Failed to execute module_test_command.')
        raise

    return ''


def cve_latest_command(client: Client, ocve: OpenCVE, args: dict) -> CommandResults:
    """
    Gets the latest reports and pulls all alerts. From each alert all CVEs
        are looped through and returned as a CommandResult.

    Args:
        client: Client object
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        Single CommandResults with a list of CVEs
    """
    parsed_cves = []
    lastRun = args.get('lastRun', {})

    if not lastRun:
        # No timestamp for lastRun was given. Default to 7 days ago
        now = datetime.now()
        fetch_time = now - timedelta(days=7)
    else:
        # Convert lastRun timestamp to object
        fetch_time = datetime.strptime(lastRun['fetch_time'], '%Y-%m-%dT%H:%M:%SZ')

    reports = client.get_reports_request()

    for report in reports:
        # Check to see if this report is prior to the lastRun time
        created = datetime.strptime(report['created_at'], '%Y-%m-%dT%H:%M:%SZ')
        if created < fetch_time:
            continue

        alerts = client.get_alerts_request(report['id'])
        for alert in alerts:
            cve_id = alert['cve']
            response = client.get_cve_request(cve_id)
            _, parsed_cve = parse_cve(ocve, response)
            parsed_cves.append(parsed_cve)

    # Create the IOCs that have been gathered so far
    parsed_cves = dedupe_cves(parsed_cves)

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


def get_cve_command(client: Client, ocve: OpenCVE, args: dict) -> list[CommandResults]:
    """
    Gets a single or multiple CVEs. Multiple are separated with a comma.

    Args:
        client: Client object
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        A list of CommandResults. Each CommandResult has a single CVE
    """
    cves = args.get('cve', None)
    cves = argToList(cves)
    cves = [cve for cve in cves if valid_cve_format(cve)]

    results = []

    for cve in cves:
        cve_info = client.get_cve_request(cve_id=cve)
        relationships, parsed_cve = parse_cve(ocve, cve_info)

        pretty_results = cve_to_warroom(parsed_cve)

        readable = tableToMarkdown(parsed_cve.get('value'), pretty_results)
        cve_indicator = cve_to_indicator(parsed_cve, ocve, relationships)

        results.append(CommandResults(
            outputs_prefix='OpenCVE.CVE',
            outputs=pretty_results,
            readable_output=readable,
            raw_response=cve_info,
            indicator=cve_indicator,
            relationships=relationships
        ))

    return results


def get_my_vendors_command(client: Client) -> CommandResults:
    """
    Gets the vendors that the registered user is subscribed to.

    Args:
        ocve: OpenCVE object
    Returns:
        CommandResults with a list of vendors
    """
    result = client.get_my_vendors_request()
    return CommandResults(
        outputs_prefix='OpenCVE.myVendors',
        outputs=result
    )


def get_my_products_command(client: Client) -> CommandResults:
    """
    Gets the products taht the registered user is subscribed to

    Args:
        cleint: Client object
    Returns:
        CommandResults with a list of products
    """
    result = client.get_my_products_request()
    return CommandResults(
        outputs_prefix='OpenCVE.myProducts',
        outputs=result
    )


def get_vendors_command(client: Client, args: dict) -> CommandResults:
    """
    Gets vendors based on filter criteria

    Args:
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        CommandResults with a list of dicts of vendors
    """

    if vendor := args.get('vendor_name', ''):
        result = client.get_vendors_request(vendor=vendor)
        return CommandResults(
            outputs_prefix=f'OpenCVE.{vendor}',
            outputs=result
        )

    else:
        params = {}

        if search := args.get('search', ''):
            params['search'] = search
        if letter := args.get('letter', ''):
            params['letter'] = letter
        if page := args.get('page', ''):
            params['page'] = page

        vendors = client.get_vendors_request(params=params)
        return CommandResults(
            outputs_prefix='OpenCVE.Vendors',
            outputs=vendors
        )


def get_vendor_cves_command(client: Client, ocve: OpenCVE, args: dict) -> list[CommandResults]:
    """
    Gets CVEs related to a vendor

    Args:
        client: Client object
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        A list of CommandResults with a single CVE per CommandResult
    """
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

    cves = client.get_cves_by_vendor_request(vendor, params=params)

    results = []

    for cve in cves:
        cve_info = client.get_cve_request(cve['id'])
        relationships, parsed_cve = parse_cve(ocve, cve_info)

        pretty_results = cve_to_warroom(parsed_cve)
        readable = tableToMarkdown(cve.get('value'), pretty_results)
        results.append(CommandResults(
            outputs_prefix=f'OpenCVE.{vendor}.CVE',
            outputs=parsed_cve,
            readable_output=readable,
            raw_response=parsed_cve,
            indicator=cve_to_indicator(parsed_cve, ocve, relationships),
            relationships=relationships
        ))

    return results


def get_products_command(client: Client, args: dict) -> CommandResults | None:
    """
    Gets a list of products for a specific vendor based on the provided filters

    Args:
        client: Client object
        args: demisto.args
    Returns:
        CommandREsults with a list of products
    """
    if vendor := args.get('vendor_name', None):
        if product := args.get('product_name', None):
            results = client.get_vendor_products_request(vendor_name=vendor, product_name=product)
            return CommandResults(
                outputs_prefix=f'OpenCVE.{vendor}.{product}',
                outputs=results
            )

        else:
            params = {}

            if search := args.get('search', None):
                params['search'] = search
            if page := args.get('page', None):
                params['page'] = page

            results = client.get_vendor_products_request(vendor_name=vendor, params=params)
            return CommandResults(
                outputs_prefix=f'OpenCVE.{vendor}.Products',
                outputs=results
            )
    else:
        return_error('Vendor is mandatory')
        return None


def get_product_cves_command(client: Client, ocve: OpenCVE, args: dict) -> list[CommandResults]:
    """
    Gets CVEs related to a specific product.

    Args:
        client: Client object
        ocve: OpenCVE object
        args: demisto.args
    Returns:
        A list of CommandResults with one CVE per CommandResult
    """
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

    cves = client.get_cves_by_product_request(vendor, product, params=params)
    results = []
    for cve in cves:
        cve_info = client.get_cve_request(cve['id'])
        relationships, parsed_cve = parse_cve(ocve, cve_info)
        pretty_results = cve_to_warroom(parsed_cve)
        readable = tableToMarkdown(cve.get('value'), pretty_results)
        results.append(CommandResults(
            outputs_prefix=f'OpenCVE.{vendor}.CVE',
            outputs=parsed_cve,
            readable_output=readable,
            raw_response=parsed_cve,
            indicator=cve_to_indicator(parsed_cve, ocve, relationships),
            relationships=relationships
        ))

    return results


def get_reports_command(client: Client, args: dict) -> CommandResults:
    """
    Gets a specific report

    Args:
        client: Client object
        args: demisto.args
    Returns:
        CommandResults with a dict of the report
    """
    if report_id := args.get('report_id', None):
        results = client.get_reports_request(report_id)
        return CommandResults(
            outputs_prefix=f'OpenCVE.Reports.{report_id}',
            outputs=results
        )

    else:
        params = {}

        if page := args.get('page', ''):
            params['page'] = page

        results = client.get_reports_request(params=params)

        return CommandResults(
            outputs_prefix='OpenCVE.Reports',
            outputs=results
        )


def get_alerts_command(client: Client, args: dict) -> CommandResults | None:
    """
    Gets all alerts from a report

    Args:
        client: Client object
        args: demisto.args
    Returns:
        CommandResults with a list of alerts
    """
    if report_id := args.get('report_id', None):
        if alert_id := args.get('alert_id', None):
            results = client.get_alerts_request(report_id, alert_id)
            return CommandResults(
                outputs_prefix=f'OpenCVE.Reports.Alerts.{alert_id}',
                outputs=results
            )
        else:
            params = {}

            if page := args.get('page', None):
                params['page'] = page

            results = client.get_alerts_request(report_id, params=params)
            return CommandResults(
                outputs_prefix='OpenCVE.Reports.Alerts',
                outputs=results
            )

    return_error('Report ID is mandatory')
    return None


def main():  # pragma: no cover
    params: dict[str, Any] = demisto.params()
    args: dict = demisto.args()
    url = params.get('url', 'https://www.opencve.io')
    verify_ssl: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    tlp = params.get('tlp_color', 'RED')

    credentials: Any = params.get('credentials')
    username = credentials['identifier']
    password = credentials['password']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    # Instantiate the OpenCVE object
    ocve = OpenCVE(tlp=tlp)

    demisto.info(f'Command being called is {command}')
    try:
        client: Client = Client(urljoin(url, '/api'), verify_ssl, proxy, auth=(username, password))

        if command == 'opencve-latest':
            return_results(cve_latest_command(client, ocve, args))

        elif command == 'cve':
            return_results(get_cve_command(client, ocve, args))

        elif command == 'opencve-get-my-vendors':
            return_results(get_my_vendors_command(client))

        elif command == 'opencve-get-my-products':
            return_results(get_my_products_command(client))

        elif command == 'opencve-get-vendors':
            return_results(get_vendors_command(client, args))

        elif command == 'opencve-get-vendor-cves':
            return_results(get_vendor_cves_command(client, ocve, args))

        elif command == 'opencve-get-products':
            return_results(get_products_command(client, args))

        elif command == 'opencve-get-product-cves':
            return_results(get_product_cves_command(client, ocve, args))

        elif command == 'opencve-get-reports':
            return_results(get_reports_command(client, args))

        elif command == 'opencve-get-alerts':
            return_results(get_alerts_command(client, args))

        elif command == 'test-module':
            return_results(module_test_command(client))

        else:
            raise NotImplementedError(f'{command} is not an existing CVE Search command')

    except Exception as err:
        demisto.debug(f'Exception {str(err)} ')
        return_error(f'Failed to execute {command} command. Error: {str(err)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
