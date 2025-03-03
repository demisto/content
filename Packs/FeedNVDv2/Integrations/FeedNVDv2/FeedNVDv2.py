# pylint: disable=invalid-name,protected-access,unused-wildcard-import,wildcard-import,wrong-import-order
"""
NVD Feed Integration to retrieve CVEs from NIST NVD and parse them
into a normalized XSOAR CVE indicator data structure
for threat intelligence management
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
from dateparser import parse

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str,
                 proxy: bool,
                 api_key: str,
                 tlp_color: str,
                 has_kev: bool,
                 first_fetch: str,
                 feed_tags: list[str],
                 cvssv3severity: list[str],
                 keyword_search: str):
        super().__init__(base_url=base_url, proxy=proxy)
        self._base_url = base_url
        self.tlp_color = tlp_color
        self.proxy = proxy
        self.api_key = api_key
        self.has_kev = has_kev
        self.feed_tags = feed_tags
        self.first_fetch = first_fetch
        self.cvssv3severity = cvssv3severity
        self.keyword_search = keyword_search

    def get_cves(self, path: str, params: dict):  # pragma: no cover
        """
        Perform a basic HTTP call using specified headers and parameters
        """

        if self.api_key:
            headers = {'apiKey': self.api_key}

        else:
            headers = {}

        param_string = self.build_param_string(params)

        demisto.debug(f'Calling NIST NVD with the following parameters {param_string}')

        return self._http_request('GET', url_suffix=path, headers=headers, params=param_string, resp_type='json', timeout=300,
                                  retries=3)

    def build_param_string(self, params: dict) -> str:
        """Builds a string out of the URL parameters to allow duplication of Severity keys.

        Args:
            params (dict): The URL parameters.

        Returns:
            str: The parameters needed as a string.
        """

        param_string: str = '&'.join([f'{key}={value}' for key, value in params.items()])
        param_string = param_string.replace('noRejected=None', 'noRejected')
        param_string = param_string.replace('hasKev=True', 'hasKev')

        for value in self.cvssv3severity:
            param_string += f'&cvssV3Severity={value}'

        return param_string


def build_indicators(client: Client, raw_cves: List[dict]):
    """
    Iteratively processes the retrieved CVEs from retrieve_cves function
    and parses the returned JSON into the required XSOAR data structure

    Args:
        cve_list: CVEs retrieved using the retrieve_cves function

    Returns:
        None
    """

    indicators = []

    for cve in raw_cves:
        raw_cve = cve.get("cve", {})
        cvss_metric = ""
        metrics: List = []
        cpes: list[dict] = []
        refs: list[dict] = []

        indicator = {"value": raw_cve.get('id')}
        fields = {"description": raw_cve.get('descriptions')[0].get('value')}
        fields["cvemodified"] = raw_cve.get('lastModified')
        fields["published"] = raw_cve.get('published')
        fields["updateddate"] = raw_cve.get('lastModified')
        fields["vulnerabilities"] = raw_cve.get('weaknesses')

        # Process references

        for ref in raw_cve.get('references'):
            refs.append({'title': indicator['value'], 'source': ref.get('source'), 'link': ref.get('url')})

        fields["publications"] = refs

        # Process CPEs
        for conf in raw_cve.get('configurations', []):
            for node in conf['nodes']:
                if "cpeMatch" in node:
                    cpes.extend({"CPE": cpe['criteria']} for cpe in node['cpeMatch'])
        fields["vulnerableproducts"] = cpes

        # Check for which CVSS Metric scoring data is available in the CVE response
        # Use the newest CVSS standard to set the CVSS Version, vector, severity, and score
        if "cvssMetricV2" in raw_cve.get('metrics'):
            cvss_metric = 'cvssMetricV2'
            fields["cvssversion"] = "2"
        elif "cvssMetricV30" in raw_cve.get('metrics'):
            cvss_metric = 'cvssMetricV30'
            fields["cvssversion"] = "3"
        elif "cvssMetricV31" in raw_cve.get('metrics'):
            cvss_metric = 'cvssMetricV31'
            fields["cvssversion"] = "3.1"

        if cvss_metric:
            fields["cvssscore"] = raw_cve.get('metrics').get(cvss_metric)[0].get('impactScore')
            fields["cvssvector"] = raw_cve.get('metrics').get(cvss_metric)[0].get('cvssData').get('vectorString')
            fields["sourceoriginalseverity"] = raw_cve.get('metrics').get(cvss_metric)[0].get('impactScore')

            for key, value in raw_cve.get('metrics').get(cvss_metric)[0].items():
                if key == "cvssData":
                    cvss = raw_cve.get('metrics').get(cvss_metric)[0]['cvssData']
                    for new_item in cvss:
                        metrics.append({"metrics": str(new_item), "value": cvss[new_item]})
                else:
                    metrics.append({"metrics": str(key), "value": value})

            fields["cvsstable"] = metrics

        if cpes:
            tags, relationships = parse_cpe_command([d['CPE'] for d in cpes], raw_cve.get('id'))
            if client.feed_tags:
                tags.append(str(client.feed_tags))

        else:
            tags = []
            relationships = []

        fields["tags"] = tags
        fields["trafficlightprotocol"] = client.tlp_color
        indicator["relationships"] = [relationship.to_indicator() for relationship in relationships]
        indicator["type"] = FeedIndicatorType.CVE
        indicator["rawJSON"] = raw_cve
        indicator["fields"] = fields
        indicator["score"] = calculate_dbotscore(fields.get("cvssscore", -1))

        indicators.append(indicator)

    return indicators


def calculate_dbotscore(cvss) -> int:
    """Returns the correct DBot score according to the CVSS Score

    Args:
        cvss (str): The CVE cvss score

    Returns:
        int: The Dbot score of the CVE
    """

    cvss = float(cvss)

    if cvss == -1:
        return 0
    elif cvss < 4.0:
        return 1
    elif cvss < 7.0:
        return 2
    else:
        return 3


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

        try:
            parts.add(cpe_parts[cpe_split[2]])

            if (vendor := cpe_split[3].capitalize().replace("\\", "").replace("_", " ")):
                vendors.add(vendor)

            if (product := cpe_split[4].capitalize().replace("\\", "").replace("_", " ")):
                products.add(product)

        except IndexError:
            pass

    relationships = [EntityRelationship(name="targets",
                                        entity_a=cve_id,
                                        entity_a_type="cve",
                                        entity_b=vendor,
                                        entity_b_type="identity") for vendor in vendors]

    relationships.extend([EntityRelationship(name="targets",
                                             entity_a=cve_id,
                                             entity_a_type="cve",
                                             entity_b=product,
                                             entity_b_type="software") for product in products])

    demisto.debug(f'{len(relationships)} relationships found for {cve_id}')

    return list(vendors | products | parts), relationships


def cves_to_war_room(raw_cves):
    """
    Output CVEs to war room based on nvd-get-indicators

    Args:
        raw_cves: List of CVEs

    Returns:
        Outputs to war room

    ID, Description, Score, Published, Modified
    """

    fields = {}
    output_list = []

    for raw_cve in raw_cves:
        if not raw_cve:
            continue

        cve = raw_cve.get("cve")
        fields = {"description": cve.get('descriptions', [])[0].get('value')}
        fields["modified"] = cve.get('lastModified')
        fields["published"] = cve.get('published')
        fields["id"] = cve.get('id')
        fields["score"] = 0
        try:
            fields["cvssversion"], fields["score"] = get_cvss_version_and_score(cve.get("metrics"))
        except Exception:
            demisto.debug(f'Cant find CVSS score for {raw_cve}')

        output_list.append(fields)

    return CommandResults(
        outputs=output_list,
        outputs_prefix='NistNVDv2.Indicators',
        readable_output=tableToMarkdown(
            "CVEs",
            [{'ID': cve["id"], 'Score': cve["score"], 'Description': cve["description"]} for cve in output_list],
            headers=['ID', 'Score', 'Description']
        ),
        outputs_key_field='Name')


def get_cvss_version_and_score(metrics):
    cvss_metrics = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", metrics.get("cvssMetricV2", [])))

    if cvss_metrics and cvss_metrics[0]:
        return cvss_metrics[0]["cvssData"]["version"], cvss_metrics[0]["cvssData"]["baseScore"]

    return '', ''


def test_module(client: Client):
    """
    Performs a simple API call to the NVD endpoint

    Args:
        client: An instance of the BaseClient connection class
        params: A dictionary containing HTTP parameters

    Returns:
        'ok' if a successful HTTP 200 message is returned

    """
    try:
        interval = parse_date_range('1 day', DATE_FORMAT)
        parse_date_range(client.first_fetch, DATE_FORMAT)
        client.get_cves("/rest/json/cves/2.0/", params={'pubStartDate': interval[0], 'pubEndDate': interval[1]})
        return_results('ok')

    except Exception as e:  # pylint: disable=broad-except
        return_error("Invalid API key specified in integration instance configuration"
                     + "\nError Message: " + str(e))


def retrieve_cves(client, start_date: Any, end_date: Any, publish_date: bool):
    """
    Iteratively retrieves CVEs from NVD from the specified modification date
    through the date the fetch-indicators or nvd-get-indicators command is
    called

    Args:
        client: An instance of the BaseClient connection class

    Returns:
        Total number of CVE indicators fetched

    """
    url_suffix = "/rest/json/cves/2.0/"
    results_per_page = 2000
    param: dict[str, str | int] = {'startIndex': 0, 'resultsPerPage': results_per_page, 'noRejected': ''}
    raw_cves = []  # type: ignore
    more_to_process = True

    if publish_date:
        param['pubStartDate'] = start_date.strftime(DATE_FORMAT)
        param['pubEndDate'] = end_date.strftime(DATE_FORMAT)

    else:
        param['lastModStartDate'] = start_date.strftime(DATE_FORMAT)
        param['lastModEndDate'] = end_date.strftime(DATE_FORMAT)

    if client.has_kev:
        param['hasKev'] = True

    if client.keyword_search:
        param['keywordSearch'] = client.keyword_search

    # Collect all the indicators together
    while more_to_process:
        try:
            res = client.get_cves(url_suffix, param)
            total_results = res.get('totalResults', 0)

            if total_results:
                demisto.debug(f'Fetching {param["startIndex"]}-{int(param["startIndex"])+results_per_page}'
                              'out of {total_results} results.')

                raw_cves += res.get('vulnerabilities')

                param['startIndex'] += int(results_per_page)  # type: ignore

            if (param['startIndex'] >= total_results):
                more_to_process = False

        except Exception as e:  # pylint: disable=broad-except
            demisto.debug(f'{e}')

        # finally:
        #    time.sleep(.5)

    return raw_cves


def fetch_indicators_command(client: Client) -> list[dict]:
    """
    Fetch CVEs from NVD API and create indicators in XSOAR

    Args:
        client: An instance of the BaseClient connection class

    Returns:
        List of CVE indicators fetched
    """

    publish_date = False
    total_results = 0
    temp_cves: list = []
    exceeds_span = True
    iteration = 0
    command = demisto.command()
    last_run_data = demisto.getLastRun()
    end_date = datetime.now(timezone.utc)

    if command == 'nvd-get-indicators':
        history = parse_date_range(f'{demisto.getArg("history")}', DATE_FORMAT)
        client.keyword_search = f'{demisto.getArg("keyword")}'
        start_date: datetime | None = parse(history[0])  # type: ignore
        publish_date = True
        demisto.debug(f'Retrieving last {demisto.getArg("history")} days of CVEs using nvd-get-indicators')

    elif last_run_data:
        # Interval run
        start_date = parse(last_run_data.get("lastRun", ""))

    else:
        # First run for the feed
        first_fetch: tuple[Any, Any] = parse_date_range(client.first_fetch, DATE_FORMAT)
        start_date = parse(first_fetch[0])  # type: ignore
        publish_date = True
        demisto.debug(f'Running Feed NVD for the first time catching CVEs since {first_fetch}')

    start_index = start_date

    while exceeds_span and start_index:
        temp_cves = []
        raw_cves: list = []

        iteration += 1

        delta = (end_date - start_index).days

        if delta > 120:
            demisto.debug(f'Fetching CVEs over a span of {delta} days, will run in 120 days batches')
            end_date = start_index + timedelta(days=120)
        else:
            exceeds_span = False

        demisto.debug(f'Fetching CVEs from {start_index:%Y-%m-%d} to {end_date:%Y-%m-%d}, '
                      f'Using {"Publish date" if publish_date else "Updated date"}')

        raw_cves = retrieve_cves(client, start_index, end_date, publish_date=publish_date)

        if raw_cves and command != "nvd-get-indicators":
            temp_cves = build_indicators(client, raw_cves)
            demisto.debug(f'Creating {len(temp_cves)} using "createIndicators"')
            demisto.createIndicators(temp_cves)
            total_results += len(temp_cves)

        start_index = end_date

    set_feed_last_run({"lastRun": end_date.strftime(DATE_FORMAT)})

    demisto.debug(f'({start_date.strftime(DATE_FORMAT)})-({end_date.strftime(DATE_FORMAT)}), '  # type: ignore
                  f'Fetched {total_results} indicators.')
    demisto.debug(f'Setting lastRun to "{end_date.strftime(DATE_FORMAT)}"')

    return raw_cves


def main():  # pragma: no cover
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
    proxy = params.get('proxy', False)
    api_key = params.get('apiKey', {}).get('password', '')
    tlp_color = params.get('tlp_color', '')
    has_kev = params.get('hasKev', False)
    first_fetch = params.get('first_fetch', '')
    feed_tags = params.get('feedTags', [])
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            proxy=proxy,
            api_key=api_key,
            tlp_color=tlp_color,
            has_kev=has_kev,
            first_fetch=first_fetch,
            feed_tags=feed_tags,
            cvssv3severity=params.get('cvssv3severity', []),
            keyword_search=params.get('keyword_search', '')
        )

        if command == 'test-module':
            test_module(client)
        elif command == "fetch-indicators":
            fetch_indicators_command(client)
        elif command == "nvd-get-indicators":
            return_results(cves_to_war_room(fetch_indicators_command(client)))

    except Exception as e:  # pylint: disable=broad-except
        return_error(f'Failed to execute {demisto.command()} command.\nError: \n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
