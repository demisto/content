# pylint: disable=invalid-name,protected-access,unused-wildcard-import,wildcard-import,wrong-import-order
"""
NVD Feed Integration to retrieve CVEs from NIST NVD and parse them
into a normalized XSOAR CVE indicator data structure 
for threat intelligence management
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
import contextlib
from datetime import date, timezone, datetime  # type: ignore[no-redef]
from dateparser import parse

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000"  # ISO8601 format with UTC, default in XSOAR


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool,
                 api_key: str, tlp_color: str, has_kev: bool, start_date: str,
                 feed_tags: list[str]):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._base_url = base_url
        self.tlp_color = tlp_color
        self.verify = verify
        self.proxy = proxy
        self.api_key = api_key
        self.has_kev = has_kev
        self.feed_tags = feed_tags
        self.start_date = start_date

    def http_get(self, path: str, params: dict):  # pragma: no cover
        """
        Perform a basic HTTP call using specified headers and parameters
        """

        headers = {
            'apiKey': self.api_key
        }

        full_url = self._base_url + path

        try:
            resp = self._http_request('GET', full_url=full_url, headers=headers, params=params, resp_type='json', timeout=300)
        except Exception as e:
            demisto.debug(e)

        return resp


def build_indicators(client: Client, raw_cves: List):
    """
    Iteratively processes the retrieved CVEs from retrieve_cves function
    and parses the returned JSON into the required XSOAR data structure

    Args:
        cve_list: CVEs retrieved using the retrieve_cves function

    Returns:
        None

    """

    indicators = []

    for raw_cve in raw_cves:
        indicator: dict[Any, Any] = {}
        cvss_metric = ""
        metrics: List = []
        cpes: List = []
        refs: List = []

        indicator = {"value": raw_cve.get('cve').get('id')}

        fields = {"description": raw_cve.get('cve').get('descriptions')[0].get('value')}
        fields["cvemodified"] = raw_cve.get('cve').get('lastModified')
        fields["published"] = raw_cve.get('cve').get('published')
        fields["updateddate"] = raw_cve.get('cve').get('lastModified')
        fields["vulnerabilities"] = raw_cve.get('cve').get('weaknesses')

        # Process references
        if len(raw_cve.get('cve').get('references')) > 1:
            for ref in raw_cve.get('cve').get('references'):
                url = ref.get('url')
                source = ref.get('source')
                refs.append({'title': indicator['value'], 'source': source, 'link': url})
        elif len(raw_cve.get('cve').get('references')) == 1:
            url = raw_cve.get('cve').get('references')[0].get('url')
            source = raw_cve.get('cve').get('references')[0].get('source')
            refs.append({'title': indicator['value'], 'source': source, 'link': url})
        fields["publications"] = refs

        # Process CPEs
        if "configurations" in raw_cve.get('cve'):
            for conf in raw_cve.get('cve').get('configurations'):
                for node in conf['nodes']:
                    if "cpeMatch" in node:
                        cpes.extend({"CPE": cpe['criteria']} for cpe in node['cpeMatch'])
            fields["vulnerableproducts"] = cpes

        # Check for which CVSS Metric scoring data is available in the CVE response
        # Use the newest CVSS standard to set the CVSS Version, vector, severity, and score
        if "cvssMetricV2" in raw_cve.get('cve').get('metrics'):
            cvss_metric = 'cvssMetricV2'
            fields["cvssversion"] = "2"
        elif "cvssMetricV30" in raw_cve.get('cve').get('metrics'):
            cvss_metric = 'cvssMetricV30'
            fields["cvssversion"] = "3"
        elif "cvssMetricV31" in raw_cve.get('cve').get('metrics'):
            cvss_metric = 'cvssMetricV31'
            fields["cvssversion"] = "3.1"

        if cvss_metric:
            fields["cvssscore"] = raw_cve.get('cve').get('metrics').get(cvss_metric)[0]\
                .get('impactScore')
            fields["cvssvector"] = raw_cve.get('cve').get('metrics').get(cvss_metric)[0]\
                .get('cvssData').get('vectorString')
            fields["sourceoriginalseverity"] = raw_cve.get('cve').get('metrics').get(cvss_metric)[0]\
                .get('impactScore')

            for key, value in raw_cve.get('cve').get('metrics').get(cvss_metric)[0].items():
                if key == "cvssData":
                    cvss = raw_cve.get('cve').get('metrics').get(cvss_metric)[0]['cvssData']
                    for new_item in cvss:
                        metrics.append({"metrics": str(new_item), "value": cvss[new_item]})
                else:
                    metrics.append({"metrics": str(key), "value": value})

            fields["cvsstable"] = metrics

        if cpes:
            tags, relationships = parse_cpe_command([d['CPE'] for d in cpes], raw_cve.get('cve').get('id'))
            if client.feed_tags:
                tags.append(str(client.feed_tags))

        else:
            tags = []
            relationships = []

        fields["tags"] = tags
        fields["trafficlightprotocol"] = client.tlp_color
        indicator["relationships"] = relationships

        indicator["type"] = FeedIndicatorType.CVE
        indicator["rawJSON"] = raw_cve
        indicator["fields"] = fields
        indicator["score"] = 0

        indicators.append(indicator)

    return indicators


def parse_cpe_command(cpes: list[str], cve_id: str) -> tuple[list[str], list[EntityRelationship]]:
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
                                        entity_b_type="identity").
                     to_indicator() for vendor in vendors]

    relationships.extend([EntityRelationship(name="targets",
                                             entity_a=cve_id,
                                             entity_a_type="cve",
                                             entity_b=product,
                                             entity_b_type="software")
                          .to_indicator() for product in products])

    return list(vendors | products | parts), relationships


def test_module(client: Client):
    """
    Performs a simple API call to NVD for CVE-2021-44228 using the provided API key

    Args:
        client: An instance of the BaseClient connection class
        params: A dictionary containing HTTP parameters

    Returns:
        'ok' if a successful HTTP 200 message is returned

    """
    try:
        client.http_get("/rest/json/cves/2.0/?noRejected", {})
        return_results('ok')

    except Exception as e:  # pylint: disable=broad-except
        return_error("Invalid API key specified in integration instance configuration"
                     + "\nError Message: " + str(e))


def retrieve_cves(client, start_date: Any, end_date: Any, test_run: bool):
    """
    Iteratively retrieves CVEs from NVD from the specified modification date
    through the date the fetch-indicators or nvd-get-indicators command is 
    called

    Args:
        client: An instance of the BaseClient connection class

    Returns:
        Total number of CVE indicators fetched

    """
    url = "/rest/json/cves/2.0/?noRejected"
    param = {}
    start_index = 0
    results_per_page = 2000
    raw_cves = []  # type: ignore

    start_date = datetime.fromisoformat(str(start_date))
    end_date = datetime.fromisoformat(str(end_date))

    param['lastModStartDate'] = start_date.strftime(DATE_FORMAT)  # type: ignore
    param['lastModEndDate'] = end_date.strftime(DATE_FORMAT)  # type: ignore

    if client.has_kev:
        url += '&hasKev'

    param['startIndex'] = int(start_index)  # type: ignore
    param['resultsPerPage'] = results_per_page  # type: ignore

    more_to_process = True

    # Collect all the indicators together
    while more_to_process:
        try:
            if not test_run:
                res = client.http_get(url, param)
            else:
                with open('./Packs/FeedNVDv2/Integrations/FeedNVDv2/test_data/test_cve_data.json', encoding='utf-8') as f:
                    res = json.loads(f.read())
                    more_to_process = False
            if "error" in res:
                return_error(res.get('error'))
            total_results = res.get('totalResults', 0)

            if total_results:
                raw_cves += res.get('vulnerabilities')

                param['startIndex'] = str(int(param['startIndex']) + results_per_page)

            if (int(param['startIndex']) >= total_results):
                more_to_process = False

        except Exception as e:  # pylint: disable=broad-except
            demisto.debug(e)
        finally:
            time.sleep(.5)

    return raw_cves


def fetch_indicators_command(client: Client, test_run: bool):
    """
    Initiates the CVE retrieval process while tracking the total run time and indicator fetch count

    Args:
        client: An instance of the BaseClient connection class

    Returns:
        Total number of CVE indicators fetched

    """

    parsed_cves: list = []
    temp_cves: list = []
    exceeds_span = True
    iteration = 0
    command = demisto.command()

    s_date = client.start_date
    try:
        date.fromisoformat(s_date)
    except ValueError:
        return_error("Incorrect date format specified. Should be in the format of YYYY-MM-DD")
    start_date = datetime.strptime(s_date, "%Y-%m-%d")

    last_run_data = demisto.getLastRun()

    if last_run_data:
        last_run = parse(last_run_data.get("lastRun"))

    if command == 'nvd-get-indicators':
        history = demisto.getArg('history')
        demisto.debug(f'Retrieving last {history} days of CVEs using nvd-get-indicators')
        last_run = (datetime.now() - timedelta(days=int(history)))
    # First run of the integration
    elif "lastRun" not in last_run_data or test_run:
        last_run = start_date
    # last_run is present so parse last date
    else:
        last_run = parse(last_run_data.get("lastRun"))

    last_mod_start_date = last_run
    last_mod_end_date = datetime.now()  # type: ignore[attr-defined]

    while exceeds_span and last_mod_end_date and last_mod_start_date:
        delta = (last_mod_end_date - last_mod_start_date).days  # type: ignore[TypeError]
        if delta > 120:
            last_mod_end_date = last_mod_start_date + timedelta(days=120)  # type: ignore
        else:
            exceeds_span = False

        iteration += 1

        raw_cves = retrieve_cves(client, last_mod_start_date, last_mod_end_date, False)

        demisto.debug(print(f'\n\nlastModStartDate: {last_mod_start_date.strftime(DATE_FORMAT)}'  # noqa: T201
                            + f'\nlastModEndDate: {last_mod_end_date.strftime(DATE_FORMAT)}'
                            + f'\nFetch Iteration: {str(iteration)}' + '\nCurrent Total Fetched Indicator Count: '
                            + f'{str(len(parsed_cves))}\n\n'))

        if raw_cves:
            temp_cves = build_indicators(client, raw_cves)
            demisto.createIndicators(temp_cves)

            parsed_cves += temp_cves
            temp_cves.clear()

        raw_cves.clear()

        last_mod_start_date = last_mod_end_date
        last_mod_end_date = datetime.now()

    demisto.setLastRun({"lastRun": datetime.now
                        (timezone.utc).isoformat()})


def main() -> None:
    """
    Main integration function that defines the client object and initiates calls to
    the user-specified integration command

    Args:
        None

    Returns:
        None

    """

    params = demisto.params()
    base_url: str = "https://services.nvd.nist.gov"  # disable-secrets-detection
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_key = params.get('apiKey').get('password')
    tlp_color = params.get('tlp_color')
    has_kev = params.get('hasKev')
    start_date = params.get('start_date')
    feed_tags = params.get('feedTags')
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_cert,
            proxy=proxy,
            api_key=api_key,
            tlp_color=tlp_color,
            has_kev=has_kev,
            start_date=start_date,
            feed_tags=feed_tags
        )

        if command != "test-module":
            fetch_indicators_command(client, test_run=False)
        else:
            test_module(client)

    except Exception as e:  # pylint: disable=broad-except
        demisto.error(traceback.format_exc())  # demisto.info the traceback
        return_error(f'Failed to execute {command} command.\nError: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
