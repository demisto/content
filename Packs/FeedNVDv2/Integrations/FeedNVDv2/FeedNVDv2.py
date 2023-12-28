import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
import contextlib
import datetime         # type: ignore
from dateparser import parse


# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000"  # ISO8601 format with UTC, default in XSOAR


def parse_cpe(cpes: list[str], cve_id: str) -> tuple[list[str], list[EntityRelationship]]:
    """
    Parses a CPE to return the correct tags and relationships needed for the CVE.

    Args:
        cpe: A list representing a single CPE, see 
        "https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7695.pdf" # disable-secrets-detection

    Returns:
        A tuple consisting of a list of tags and a list of EntityRelationships.

    """

    cpe_parts = {
        "a": "Application",
        "o": "Operating-System",
        "h": "Hardware"
    }

    vendors = set()
    products = set()
    parts = set()

    for cpe in cpes:
        cpe_split = re.split(r'(?<!\\):', cpe)

        with contextlib.suppress(IndexError):
            if (vendor := cpe_split[3].capitalize().replace("\\", "").replace("_", " ")):
                vendors.add(vendor)

        with contextlib.suppress(IndexError):
            if (product := cpe_split[4].capitalize().replace("\\", "").replace("_", " ")):
                products.add(product)

        with contextlib.suppress(IndexError):
            parts.add(cpe_parts[cpe_split[2]])

    relationships = [EntityRelationship(name="targets",
                                        entity_a=cve_id,
                                        entity_a_type="cve",
                                        entity_b=vendor,
                                        entity_b_type="identity").to_indicator() for vendor in vendors]

    relationships.extend([EntityRelationship(name="targets",
                                             entity_a=cve_id,
                                             entity_a_type="cve",
                                             entity_b=product,
                                             entity_b_type="software").to_indicator() for product in products])

    return list(vendors | products | parts), relationships


def test_module(client: BaseClient, params: Dict[str, Any]):

    api_key = params.get('apiKey', {}).get('password')
    try:
        headers = {
            'apiKey': api_key
        }
        client._http_request('GET', full_url='https://services.nvd.nist.gov/rest/'
                             + 'json/cves/2.0?cveId=CVE-2021-44228',  # disable-secrets-detection
                             headers=headers)
        return_results('ok')

    except Exception as e:  # pylint: disable=broad-except
        return_error("Invalid API key specified in integration instance configuration\nError Message: " + str(e))    # noqa: UP034


def retrieve_cves(client, params):
    command = demisto.command()
    api_key = params.get('apiKey', {}).get('password')
    has_kev = params.get('hasKev') or None  # type: ignore
    s_date = params.get('start_date')
    try:
        datetime.date.fromisoformat(s_date)  # type: ignore[attr-defined]
    except ValueError:
        return_error("Incorrect date format specified. Should be in the format of YYYY-MM-DD")
    start_date = datetime.datetime.strptime(s_date, "%Y-%m-%d")  # type: ignore[attr-defined]

    exceeds_span = True
    url = "/rest/json/cves/2.0/?noRejected"
    now = datetime.datetime.now()  # type: ignore[attr-defined]
    param = {}  # Store API build call parameters
    start_index = 0  # Current starting index for API calls
    results_per_page = 2000  # NIST NVD recommends restricting API calls to 2000 results
    total_items = 0
    data_items = []  # type: ignore
    iteration = 0  # Track total iterations for debug purposes

    # If there is no last run date, use the history specified in the params
    last_run_data = demisto.getLastRun()

    # Is last_run_data empty? If not then this isn't the first run
    if last_run_data:
        last_run = parse(last_run_data.get("lastRun"))

    # nvd-get-indicators manual call
    if command == 'nvd-get-indicators':
        history = demisto.getArg('history')
        demisto.debug(f'Retrieving last {history} days of CVEs using nvd-get-indicators')
        last_run = (now - timedelta(days=int(history)))
    # First run of the integration
    elif "lastRun" not in last_run_data:
        last_run = start_date
    # last_run is present so parse last date
    else:
        last_run = parse(last_run_data.get("lastRun"))

    last_mod_start_date = last_run
    last_mod_end_date = datetime.datetime.now()  # type: ignore[attr-defined]

    # Set up parameters for API calls
    headers = {
        "apiKey": api_key
    }

    if last_mod_start_date and last_mod_end_date:
        param['lastModStartDate'] = last_mod_start_date.strftime(DATE_FORMAT)  # type: ignore
        param['lastModEndDate'] = last_mod_end_date.strftime(DATE_FORMAT)  # type: ignore

    if has_kev:
        url += '&hasKev'

    while exceeds_span and last_mod_end_date and last_mod_start_date:
        delta = (last_mod_end_date - last_mod_start_date).days  # type: ignore
        if delta > 120:
            last_mod_end_date = last_mod_start_date + timedelta(days=120)  # type: ignore
        else:
            exceeds_span = False
        param['startIndex'] = start_index  # type: ignore
        param['resultsPerPage'] = results_per_page  # type: ignore

        if last_mod_start_date and last_mod_end_date:
            param['lastModStartDate'] = last_mod_start_date.strftime(DATE_FORMAT)  # type: ignore
            param['lastModEndDate'] = last_mod_end_date.strftime(DATE_FORMAT)  # type: ignore

        total_results = 1
        iteration_count = 0

        # Collect all the indicators together
        while iteration_count < total_results:
            demisto.debug(f'\n\nlastModStartDate: {last_mod_start_date.strftime(DATE_FORMAT)}'
                          + f'\nlastModEndDate: {last_mod_end_date.strftime(DATE_FORMAT)}'
                          + f'\nFetch Iteration: {str(iteration)}' + '\nIteration Count: '
                          + str(iteration_count) + '\nTotal Results for Iteration: ' + str(total_results)
                          + '\nCurrent Total Fetched Indicator Count: ' + str(total_items) + '\n\n')
            try:
                res = client._http_request('GET', url, params=param, headers=headers, timeout=300)
                # Check to see if there are any errors
                if "error" in res:
                    return_error(res.get('error'))
                total_results = res.get('totalResults', 0)

                if total_results:
                    data_items += res.get('vulnerabilities')

                    param['startIndex'] += results_per_page  # type: ignore

                    process_cves(params, data_items)
                    total_items += len(data_items)
                    data_items = []  # type: ignore

                    iteration_count += results_per_page
                    iteration += 1

            except Exception as e:  # pylint: disable=broad-except
                demisto.debug(e)  # noqa: T201
            finally:
                time.sleep(.5)

        last_mod_start_date = last_mod_end_date
        last_mod_end_date = now

        # Update module health
        demisto.updateModuleHealth(str(total_items) + " CVEs retrieved")

    demisto.debug(f"Total NVD CVE indicators fetched {total_items}")


def process_cves(params, cve_list):
    feed_tags = params.get('feedTags')

    indicators = []

    for cve in cve_list:
        indicator: Dict[Any, Any] = {}
        cvss_metric = ""
        metrics: List = []
        cpes: List = []
        refs: List = []

        indicator = {"value": cve.get('cve').get('id')}

        fields = {"description": cve.get('cve').get('descriptions')[0].get('value')}
        fields["cvemodified"] = cve.get('cve').get('lastModified')
        fields["published"] = cve.get('cve').get('published')
        fields["updateddate"] = cve.get('cve').get('lastModified')
        fields["vulnerabilities"] = cve.get('cve').get('weaknesses')

        # Process references
        if len(cve.get('cve').get('references')) > 1:
            for ref in cve.get('cve').get('references'):
                url = ref.get('url')
                source = ref.get('source')
                refs.append({'title': indicator['value'], 'source': source, 'link': url})
        elif len(cve.get('cve').get('references')) == 1:
            url = cve.get('cve').get('references')[0].get('url')
            source = cve.get('cve').get('references')[0].get('source')
            refs.append({'title': indicator['value'], 'source': source, 'link': url})
        fields["publications"] = refs

        # Process CPEs
        if "configurations" in cve.get('cve'):
            for conf in cve.get('cve').get('configurations'):
                for node in conf['nodes']:
                    if "cpeMatch" in node:
                        cpes.extend({"CPE": cpe['criteria']} for cpe in node['cpeMatch'])
            fields["vulnerableproducts"] = cpes

        # Check for which CVSS Metric scoring data is available in the CVE response
        # Use the newest CVSS standard to set the CVSS Version, vector, severity, and score
        if "cvssMetricV2" in cve.get('cve').get('metrics'):
            cvss_metric = 'cvssMetricV2'
            fields["cvssversion"] = "2"
        elif "cvssMetricV30" in cve.get('cve').get('metrics'):
            cvss_metric = 'cvssMetricV30'
            fields["cvssversion"] = "3"
        elif "cvssMetricV31" in cve.get('cve').get('metrics'):
            cvss_metric = 'cvssMetricV31'
            fields["cvssversion"] = "3.1"

        if cvss_metric:
            fields["cvssscore"] = cve.get('cve').get('metrics').get(cvss_metric)[0].get('impactScore')
            fields["cvssvector"] = cve.get('cve').get('metrics').get(cvss_metric)[0].get('cvssData')\
                .get('vectorString')
            fields["sourceoriginalseverity"] = cve.get('cve').get('metrics').get(cvss_metric)[0]\
                .get('impactScore')

            for key, value in cve.get('cve').get('metrics').get(cvss_metric)[0].items():
                if key == "cvssData":
                    cvss = cve.get('cve').get('metrics').get(cvss_metric)[0]['cvssData']
                    for new_item in cvss:
                        metrics.append({"metrics": str(new_item), "value": cvss[new_item]})
                else:
                    metrics.append({"metrics": str(key), "value": value})

            fields["cvsstable"] = metrics

        if cpes:
            tags, relationships = parse_cpe([d['CPE'] for d in cpes], cve.get('cve').get('id'))
            if feed_tags:
                tags.append(str(feed_tags))

        else:
            tags = []
            relationships = []

        fields["tags"] = tags
        indicator["relationships"] = relationships

        indicator["type"] = FeedIndicatorType.CVE
        indicator["rawJSON"] = {'value': cve.get('cve').get('id'), 'type': 'CVE'}
        indicator["fields"] = fields
        indicator["score"] = 0

        indicators.append(indicator)

    demisto.debug(f'First CVE of run: {str(indicators[0]["value"])}\nLast CVE of run: {str(indicators[-1]["value"])}')

    demisto.createIndicators(indicators)


def fetch_indicators_command(client, params):
    fetch_start = datetime.datetime.now(datetime.timezone.utc)  # type: ignore[attr-defined]

    retrieve_cves(client, params)

    fetch_finish = datetime.datetime.now(datetime.timezone.utc)  # type: ignore[attr-defined]

    # Output final stats to debug
    demisto.debug(f"NVD CVE Fetch started at: {fetch_start.strftime(DATE_FORMAT)}")
    demisto.debug(f"NVD CVE Fetch completed at: {fetch_finish.strftime(DATE_FORMAT)}")

    # Set new integration lastRun value
    demisto.setLastRun({"lastRun": datetime.datetime.now(datetime.timezone.utc).isoformat()})  # type: ignore[attr-defined]


# COMMAND CONSTANTS

commands = {
    'test-module': test_module,
    'nvd-get-indicators': fetch_indicators_command,
    'fetch-indicators': fetch_indicators_command
}


def main() -> None:
    params = demisto.params()
    base_url = "https://services.nvd.nist.gov"  # disable-secrets-detection
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_cert,
            proxy=proxy,
        )

        commands[command](client, params)  # type: ignore

    except Exception as e:  # pylint: disable=broad-except
        demisto.error(traceback.format_exc())  # demisto.info the traceback
        return_error(f'Failed to execute {command} command.\nError: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
