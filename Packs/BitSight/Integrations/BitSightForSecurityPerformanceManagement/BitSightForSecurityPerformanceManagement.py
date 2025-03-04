import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""Main file for BitSightForSecurityPerformanceManagement Integration."""
import requests
import urllib3

'''CONSTANTS'''
BITSIGHT_DATE_TIME_FORMAT = '%Y-%m-%d'
DEFAULT_FIRST_FETCH_DAYS = 3
DEFAULT_FETCH_LIMIT = 25
MAX_FETCH_LIMIT = 200
BASE_URL = "https://api.bitsighttech.com"
MAX_LIMIT = 1000
DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0

ERROR_MESSAGES = {
    "GUID_REQUIRED": "Must provide a GUID.",
    "GUID_NOT_FETCHED": "Unable to fetch GUID.",
    "GUID_NOT_AVAILABLE": "Provided 'Company's GUID' is not available/valid."
                          " Please input a GUID retrieved using the command \"bitsight-companies-guid-get\".",
    "INVALID_SELECT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "INVALID_MAX_FETCH": f"Parameter 'Max Fetch' is not a valid number."
                         f" Please provide a number in range 1 to {MAX_FETCH_LIMIT}.",
    "NEGATIVE_FIRST_FETCH": "Parameter 'First fetch time in days' should be a number greater than or equal to 0.",
    "LIMIT_GREATER_THAN_ALLOWED": f"Argument 'limit' should be a number less than or equal to {MAX_LIMIT}."
}

SEVERITY_MAPPING = {
    'minor': 1,
    'moderate': 4,
    'material': 7,
    'severe': 9
}

ASSET_CATEGORY_MAPPING = {
    'low': 'low,medium,high,critical',
    'medium': 'medium,high,critical',
    'high': 'high,critical',
    'critical': 'critical'
}

RISK_VECTOR_MAPPING = {
    'web application headers': 'application_security',
    'botnet infections': 'botnet_infections',
    'breaches': 'data_breaches',
    'desktop software': 'desktop_software',
    'dkim': 'dkim',
    'dnssec': 'dnssec',
    'file sharing': 'file_sharing',
    'insecure systems': 'insecure_systems',
    'malware servers': 'malware_servers',
    'mobile app publications': 'mobile_app_publications',
    'mobile application security': 'mobile_application_security',
    'mobile software': 'mobile_software',
    'open ports': 'open_ports',
    'patching cadence': 'patching_cadence',
    'potentially exploited': 'potentially_exploited',
    'server software': 'server_software',
    'spam propagation': 'spam_propagation',
    'spf': 'SPF',
    'ssl certificates': 'ssl_certificates',
    'ssl configurations': 'ssl_configurations',
    'unsolicited communications': 'unsolicited_comm',
    'web application security': 'web_appsec',
    'dmarc': 'dmarc'

}
PACK_VERSION = get_pack_version(pack_name='Bitsight') or '1.1.23'
CALLING_PLATFORM_VERSION = 'XSOAR'
CONNECTOR_NAME_VERSION = f'Bitsight - {PACK_VERSION}'
# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """Client will implement the service API, should not contain Cortex XSOAR logic. \
    Should do requests and return data."""

    def get_companies_guid(self):
        """Retrieve subscribed company details."""
        uri = 'v1/companies'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def get_company_detail(self, guid):
        """
        Retrieve company details based on its Guid.

        :param guid: guid of the company whose details need to be retrieved
        """
        uri = f'v1/companies/{encode_string_results(guid)}'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def get_company_findings(self, guid, first_seen, last_seen, optional_params=None):
        """
        Retrieve company findings based on its Guid.

        :param guid: guid of the company whose findings need to be retrieved
        :param first_seen: first seen date (YYYY-MM-DD) of the findings
        :param last_seen: last seen date (YYYY-MM-DD) of the findings
        :param optional_params: params to be passed to the findings endpoint
        """
        uri = f'v1/companies/{encode_string_results(guid)}/findings'

        params = {
            'first_seen_gte': first_seen,
            'last_seen_lte': last_seen,
            'unsampled': 'true',
            'expand': 'attributed_companies'
        }
        if optional_params:
            params.update(optional_params)
        remove_nulls_from_dictionary(params)

        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )


'''HELPER FUNCTIONS'''


def trim_spaces_from_args(args):
    """
    Trim spaces from values of the args dict.

    :param args: Dict to trim spaces from
    :type args: dict
    :return:
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def camelize_strings_with_underscore(string: str):
    """
    Wrap CommonServerPython's camelize_string to also convert Pascal strings.

    :param string: string to convert to camel case
    """
    if string.find("_") == -1:
        return string[0].lower() + string[1:]
    else:
        return camelize_string(string, upper_camel=False)


def camelize_dict_recursively(src):
    """
    Camelize all the keys in a dictionary with nested dictionaries and lists.

    :param src: the dictionary to camelize
    """
    destination = {}
    for key, value in src.items():
        if isinstance(value, dict):
            destination[camelize_strings_with_underscore(key)] = camelize_dict_recursively(value)
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                destination[camelize_strings_with_underscore(key)] = [camelize_dict_recursively(list_value) for
                                                                      list_value in value]
            else:
                destination[camelize_strings_with_underscore(key)] = value
        else:
            destination[camelize_strings_with_underscore(key)] = value
    return destination


def prepare_and_validate_company_findings_get_filter_args(risk_vector_list, severity, asset_category):
    """
    Prepare and validate arguments for bitsight-company-findings-get.

    :param risk_vector_list: input from argument risk_vector_label
    :param severity: input from argument severity
    :param asset_category: input from argument asset_category
    """
    risk_vector = ''
    for vector in risk_vector_list:
        if vector.lower() in RISK_VECTOR_MAPPING:
            risk_vector += RISK_VECTOR_MAPPING[vector.lower()] + ','
        else:
            raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(vector.lower(), 'risk_vector_label',
                                                                     ", ".join(RISK_VECTOR_MAPPING.keys())))

    risk_vector = risk_vector[:-1]

    severity_gte = None
    if severity:
        if severity in SEVERITY_MAPPING:
            severity_gte = SEVERITY_MAPPING[severity]
        else:
            raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(severity, 'severity',
                                                                     ", ".join(SEVERITY_MAPPING.keys())))

    asset_category_eq = None
    if asset_category:
        if asset_category in ASSET_CATEGORY_MAPPING:
            asset_category_eq = ASSET_CATEGORY_MAPPING[asset_category]
        else:
            raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(asset_category, 'asset_category',
                                                                     ", ".join(ASSET_CATEGORY_MAPPING.keys())))
    return risk_vector, severity_gte, asset_category_eq


def prepare_and_validate_fetch_findings_args(client, args):
    """
    Prepare and validate arguments for company_findings_get_command when fetch_incidents is true.

    :param client: client to use
    :param args: arguments obtained from demisto.args()
    """
    guid = args.get('guid', None)
    if not guid:
        res = client.get_companies_guid()
        if res.status_code == 200:
            res_json = res.json()
            guid = res_json.get('my_company', {}).get('guid')
        else:
            raise DemistoException(ERROR_MESSAGES["GUID_NOT_FETCHED"])
    severity = args.get('findings_min_severity', None)
    if severity:
        severity = severity.lower()
    grade_list = args.get('findings_grade', None)
    grade = ','.join(grade_list)
    asset_category = args.get('findings_min_asset_category', None)
    if asset_category:
        asset_category = asset_category.lower()
    risk_vector_list = argToList(args.get('risk_vector'))
    if 'All' in risk_vector_list:
        risk_vector_list = []
    limit = arg_to_number(args.get('max_fetch', DEFAULT_FETCH_LIMIT), 'Max Fetch', True)
    if limit and (limit < 1 or limit > MAX_FETCH_LIMIT):  # type: ignore
        raise ValueError(ERROR_MESSAGES["INVALID_MAX_FETCH"])

    return guid, severity, grade, asset_category, risk_vector_list, limit


'''COMMAND FUNCTIONS'''


def fetch_incidents(client, last_run, params):
    """
    Fetch Bitsight Findings.

    :param client: client to use
    :param last_run: last run object obtained from demisto.getLastRun()
    :param params: arguments obtained from demisto.params()
    """
    events = []
    try:
        if "offset" in last_run:
            params["offset"] = last_run["offset"]
            last_run_date = last_run["first_fetch"]
        else:
            first_fetch = arg_to_number(params.get('first_fetch', DEFAULT_FIRST_FETCH_DAYS), 'First fetch time in days',
                                        True)
            if first_fetch < 0:  # type: ignore
                raise ValueError(ERROR_MESSAGES["NEGATIVE_FIRST_FETCH"])
            today = datetime.now()
            last_run_date = (today - timedelta(days=first_fetch)).strftime(BITSIGHT_DATE_TIME_FORMAT)  # type: ignore

        report_entries = []
        findings_res = company_findings_get_command(client, params, last_run_date, True)
        report_entries.extend(findings_res.get('results', []))

        for entry in report_entries:
            # Set the Raw JSON to the event. Mapping will be done at the classification and mapping
            event = {
                "name": "Bitsight Finding - " + entry.get('temporary_id'),
                'occurred': entry.get('first_seen') + 'T00:00:00Z',
                "rawJSON": json.dumps(entry)}
            events.append(event)

        last_run = {'first_fetch': last_run_date,
                    "offset": params["offset"] + len(report_entries) if params.get("offset") else len(report_entries)}

    except Exception as e:
        demisto.error('Failed to fetch events.')
        raise e

    return last_run, events


def test_module(client, params):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. \
    Connection to the service is successful. Anything else will fail the test.

    :param client: client to use
    :param params: parameters obtained from demisto.params()
    """
    res = client.get_companies_guid()

    if params.get("isFetch", False):
        available_guids = {c["guid"] for c in res["companies"]}
        requested_guid = params.get("guid")

        if not requested_guid:
            raise ValueError(ERROR_MESSAGES["GUID_REQUIRED"])

        if requested_guid not in available_guids:
            raise ValueError(ERROR_MESSAGES["GUID_NOT_AVAILABLE"])
        fetch_incidents(client, {}, params)
    return 'ok'


def companies_guid_get_command(client, *args):
    """
    Retrieve subscribed company details.

    :param client: client to use
    """
    res_json = client.get_companies_guid()
    outputs = camelize_dict_recursively(remove_empty_elements(res_json))
    context_output = {'BitSight.Company(val.guid == obj.guid)': outputs.get('companies', []),
                      'BitSight.MyCompany(val.guid == obj.guid)': outputs.get('myCompany', {})}
    hr = []
    companies_list = outputs.get('companies', [])
    for company in companies_list:
        hr.append({
            'Company Name': company.get('name'),
            'Company Short Name': company.get('shortname'),
            'GUID': company.get('guid'),
            'Rating': company.get('rating')
        })

    readable_output = tableToMarkdown(name='Companies:',
                                      metadata=f"My Company: {outputs.get('myCompany', {}).get('guid')}",
                                      t=hr,
                                      headers=["Company Name", "Company Short Name", "GUID", "Rating"],
                                      removeNull=True
                                      )

    return CommandResults(
        readable_output=readable_output,
        outputs=context_output,
        raw_response=outputs
    )


def company_details_get_command(client, args):
    """
    Retrieve company details based on its Guid.

    :param client: client to use
    :param args: arguments obtained from demisto.args()
    """
    guid = args.get('guid')
    res_json = client.get_company_detail(guid)

    outputs = camelize_dict_recursively(remove_empty_elements(res_json))

    outputs["ratingDetails"] = [value for _, value in outputs.get("ratingDetails", {}).items()]

    company_info = {
        'guid': res_json.get('guid'),
        'customId': res_json.get('custom_id'),
        'name': res_json.get('name'),
        'description': res_json.get('description'),
        'ipv4Count': res_json.get('ipv4_count'),
        'peopleCount': res_json.get('people_count'),
        'shortName': res_json.get('shortname'),
        'industry': res_json.get('industry'),
        'industrySlug': res_json.get('industry_slug'),
        'subIndustry': res_json.get('sub_industry'),
        'subIndustrySlug': res_json.get('sub_industry_slug'),
        'homePage': res_json.get('homepage'),
        'primaryDomain': res_json.get('primary_domain'),
        'type': res_json.get('type'),
        'displayURL': res_json.get('display_url')
    }
    ratings = []
    for rating in res_json.get('ratings', []):
        rating_dict = {
            'rating': rating.get('rating'),
            'rating_date': rating.get('rating_date'),
            'range': rating.get('range')
        }
        ratings.append(rating_dict)

    rating_details = []
    for rating_detail_key in res_json.get('rating_details', {}):
        rating_detail = res_json.get('rating_details', {}).get(rating_detail_key, {})
        rating_detail_dict = {
            'name': rating_detail.get('name'),
            'rating': rating_detail.get('rating'),
            'percentile': rating_detail.get('percentile'),
            'display_url': rating_detail.get('display_url')
        }
        rating_details.append(rating_detail_dict)

    readable = {
        'Company Info': company_info,
        'Ratings': ratings,
        'Rating Details': rating_details
    }

    readable_output = tableToMarkdown(name='Company Details:',
                                      t=readable,
                                      headers=["Company Info", "Ratings", "Rating Details"],
                                      removeNull=True
                                      )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='BitSight.Company',
        outputs=outputs,
        outputs_key_field='guid',
        raw_response=res_json
    )


def company_findings_get_command(client, args, first_seen=None, fetch_incidents=False):
    """
    Retrieve company findings based on its Guid.

    :param client: client to use
    :param args: arguments obtained from demisto.args()
    :param first_seen: first seen of the finding
    :param fetch_incidents: whether the command is called from fetch_incidents
    """
    last_seen = None
    if fetch_incidents:
        guid, severity, grade, asset_category, risk_vector_list, limit = prepare_and_validate_fetch_findings_args(
            client, args)
        offset = arg_to_number(args.get('offset', DEFAULT_OFFSET), 'offset')
    else:
        guid = args.get('guid')
        severity = args.get('severity', None)
        grade = args.get('grade', None)
        asset_category = args.get('asset_category', None)
        limit = arg_to_number(args.get('limit', DEFAULT_LIMIT), 'limit')
        if limit and limit > MAX_LIMIT:  # type: ignore
            raise ValueError(ERROR_MESSAGES["LIMIT_GREATER_THAN_ALLOWED"])
        offset = arg_to_number(args.get('offset', DEFAULT_OFFSET), 'offset')
        if severity:
            severity = severity.lower()
        if grade:
            grade = grade.upper()
        if asset_category:
            asset_category = asset_category.lower()
        risk_vector_list = argToList(args.get('risk_vector_label', []))
        first_seen = args.get('first_seen')
        last_seen = args.get('last_seen')

    risk_vector, severity_gte, asset_category_eq = prepare_and_validate_company_findings_get_filter_args(
        risk_vector_list,
        severity,
        asset_category)
    res_json = client.get_company_findings(guid, first_seen, last_seen,
                                           {"severity_gte": severity_gte, "details.grade": grade,
                                            "assets.category": asset_category_eq,
                                            "risk_vector": risk_vector, "limit": limit,
                                            "offset": offset})

    if fetch_incidents:
        return res_json
    res_json_cleaned = camelize_dict_recursively(remove_empty_elements(res_json))
    readable_list = []
    outputs = None
    if res_json_cleaned.get("results", []):
        for finding in res_json_cleaned.get("results", []):
            readable = {
                'Evidence Key': finding.get('evidenceKey'),
                'Risk Vector Label': finding.get('riskVectorLabel'),
                'First Seen': finding.get('firstSeen'),
                'Last Seen': finding.get('lastSeen'),
                'ID': finding.get('temporaryId'),
                'Risk Category': finding.get('riskCategory'),
                'Severity': finding.get('severityCategory'),
                'Asset Category': "\n".join(
                    [f"{asset.get('asset')}: {asset.get('category', '').title()}" for asset
                     in finding.get('assets', [])]),
                'Finding Grade': finding.get('details', {}).get('grade', '').title()
            }
            readable_list.append(readable)
        outputs = {
            "BitSight.Company(val.guid == obj.guid)": {
                "guid": guid.lower(),
                "CompanyFinding": res_json_cleaned.get("results", [])
            },
            "BitSight.Page(val.name == obj.name)": {
                "name": "bitsight-company-findings-get",
                "next": res_json_cleaned.get("links", {}).get("next"),
                "previous": res_json_cleaned.get("links", {}).get("previous"),
                "count": res_json_cleaned.get("count")
            }}

    readable_output = tableToMarkdown(name='Company findings:',
                                      t=readable_list,
                                      metadata=f"Total Findings: {res_json_cleaned.get('count')}",
                                      headers=["Evidence Key", "Risk Vector Label", "First Seen", "Last Seen",
                                               "ID", "Risk Category", "Severity", "Asset Category",
                                               "Finding Grade"],
                                      removeNull=True
                                      )
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=res_json
    )


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""
    command = demisto.command()
    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_key = params.get('apikey', {})

    demisto.info(f'Command being called is {command}')

    client = Client(
        base_url=BASE_URL,
        verify=verify_certificate,
        proxy=proxy,
        ok_codes=[200],
        auth=requests.auth.HTTPBasicAuth(api_key, ''),
        headers={
            "X-BITSIGHT-CALLING-PLATFORM_VERSION": CALLING_PLATFORM_VERSION,
            "X-BITSIGHT-CONNECTOR-NAME-VERSION": CONNECTOR_NAME_VERSION,
        },
    )

    try:
        '''EXECUTION CODE'''
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, params))
        elif demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()
            last_run_curr, events = fetch_incidents(client, last_run, params)

            demisto.setLastRun(last_run_curr)
            demisto.incidents(events)
        else:
            COMMAND_TO_FUNCTION = {
                'bitsight-company-details-get': company_details_get_command,
                "bitsight-company-findings-get": company_findings_get_command,
                "bitsight-companies-guid-get": companies_guid_get_command,
            }
            if COMMAND_TO_FUNCTION.get(demisto.command()):
                args = demisto.args()
                remove_nulls_from_dictionary(trim_spaces_from_args(args))

                return_results(COMMAND_TO_FUNCTION[demisto.command()](client, args))  # type: ignore
            else:
                raise NotImplementedError(f'Command {demisto.command()} is not implemented')

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{e}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
