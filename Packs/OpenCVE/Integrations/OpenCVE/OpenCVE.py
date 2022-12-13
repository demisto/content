from lib.helpers import *

from datetime import datetime, timedelta

from typing import Dict, List
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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
            raw_response=parsed_cve,
            indicator=cve_to_indicator(parsed_cve)
        ))

    create_cves(parsed_cves)

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
