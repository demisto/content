import traceback

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

register_module_line('BitSight for Security Performance Management', 'start', __line__())


''' IMPORTS '''


'''CONSTANTS'''
BitSight_date_time_format = '%Y-%m-%d'

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def get_companies_guid(self):
        uri = 'v1/companies'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def get_company_detail(self, guid):
        uri = f'v1/companies/{encode_string_results(guid)}'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def get_company_findings(self, guid, first_seen, last_seen, severity_gte, grade_gt, asset_category, risk_vector):
        uri = f'v1/companies/{encode_string_results(guid)}/findings'

        params = {
            'first_seen_gte': first_seen,
            'last_seen_lte': last_seen,
            'unsampled': 'true',
            'expand': 'attributed_companies'
        }

        if severity_gte:
            params['severity_gte'] = severity_gte

        if grade_gt:
            params['details.grade'] = grade_gt

        if asset_category:
            params['assets.category'] = asset_category

        if risk_vector:
            params['risk_vector'] = risk_vector

        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )


'''HELPER FUNCTIONS'''


def get_time_elapsed(fetch_time, last_run, first_fetch):
    today = datetime.today()
    now = datetime.now()
    if 'time' in last_run:
        # Get Last run and parse to date format. Bitsight report will be pulled from last run date to Yesterday's date
        last_run_time = last_run['time']
        last_run = datetime.strptime(last_run_time, '%Y-%m-%dT%H:%M:%SZ')
        last_run_time = last_run.strftime(BitSight_date_time_format)
        time_elapsed_in_minutes = (now - last_run).total_seconds() / 60
    else:
        # If last run time is not set, data will be pulled using fetch_time
        # i.e. last 10min if fetch events is set to 10min
        last_run_time = (today - timedelta(days=first_fetch)).strftime(
            BitSight_date_time_format)
        time_elapsed_in_minutes = fetch_time

    return time_elapsed_in_minutes, last_run_time


'''COMMAND FUNCTIONS'''


def fetch_incidents(client, last_run, params):
    events = []
    minuets_in_day = 1440

    try:
        # If there is no fetch time configured, it will be set to 0 and no events will be pulled
        first_fetch = int(params.get('first_fetch', 1))
        fetch_time = params.get('fetch_time', '00:01')
        current_time = datetime.now().strftime('%H:%M')
        time_elapsed_in_minutes, last_run_date = get_time_elapsed(minuets_in_day, last_run, first_fetch)

        if (time_elapsed_in_minutes >= minuets_in_day) and (current_time >= fetch_time):
            report_entries = []
            findings_res = get_company_findings_command(client, params, last_run_date, True)
            report_entries.extend(findings_res.get('results', []))

            for entry in report_entries:
                # Set the Raw JSON to the event. Mapping will be done at the classification and mapping
                event = {
                    "name": "BitSight Finding - " + entry.get('temporary_id'),
                    'occurred': entry.get('first_seen') + 'T00:00:00Z',
                    "rawJSON": json.dumps(entry)}
                events.append(event)
            last_run_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

            last_run = {'time': last_run_time}
    except Exception as e:
        demisto.error('Failed to fetch events.')
        raise e

    return last_run, events


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Anything else will fail the test.
    """
    res = client.get_companies_guid()

    available_guids = {c["guid"] for c in res["companies"]}
    requested_guid = demisto.params().get("guid", None)

    if requested_guid is None:
        raise Exception("Must provide a GUID ")

    if requested_guid in available_guids:
        return 'ok', None, None
    else:
        raise Exception(f"Failed to execute test_module "
                        f"Response: {res}")


def get_companies_guid_command(client):
    generic_iam_context_data_list = []
    res_json = client.get_companies_guid()

    generic_iam_context = {
        'companyName': 'my_company',
        'shortName': 'my_company',
        'guid': res_json.get('my_company', {}).get('guid')
    }
    generic_iam_context_data_list.append(generic_iam_context)
    companies_list = res_json.get('companies', [])
    for company in companies_list:
        generic_iam_context = {
            'companyName': company.get('name'),
            'shortName': company.get('shortname'),
            'guid': company.get('guid')
        }
        generic_iam_context_data_list.append(generic_iam_context)

    readable_output = tableToMarkdown(name='Get Companies GUID:',
                                      t=generic_iam_context_data_list,
                                      headers=["companyName", "shortName", "guid"],
                                      removeNull=True
                                      )

    return readable_output, generic_iam_context_data_list, res_json


def get_company_details_command(client, args):
    guid = args.get('guid')
    res_json = client.get_company_detail(guid)

    generic_iam_context = {
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
        'displayURL': res_json.get('display_url'),
        'ratingDetails': res_json.get('rating_details'),
        'ratings': res_json.get('ratings'),
        'searchCount': res_json.get('search_count'),
        'subscriptionType': res_json.get('subscription_type'),
        'sparkline': res_json.get('sparkline'),
        'subscriptionTypeKey': res_json.get('subscription_type_key'),
        'subscriptionEndDate': res_json.get('subscription_end_date'),
        'bulkEmailSenderStatus': res_json.get('bulk_email_sender_status'),
        'serviceProvider': res_json.get('service_provider'),
        'customerMonitoringCount': res_json.get('customer_monitoring_count'),
        'availableUpgradeTypes': res_json.get('available_upgrade_types'),
        'hasCompanyTree': res_json.get('has_company_tree'),
        'hasPreferredContact': res_json.get('has_preferred_contact'),
        'isBundle': res_json.get('is_bundle'),
        'ratingIndustryMedian': res_json.get('rating_industry_median'),
        'primaryCompany': res_json.get('primary_company'),
        'permissions': res_json.get('permissions'),
        'isPrimary': res_json.get('is_primary'),
        'securityGrade': res_json.get('security_grade'),
        'inSpmPortfolio': res_json.get('in_spm_portfolio'),
        'isMycompMysubsBundle': res_json.get('is_mycomp_mysubs_bundle'),
        'companyFeatures': res_json.get('company_features')
    }
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

    readable_output = tableToMarkdown(name='Get Company Details:',
                                      t=readable,
                                      headers=["Company Info", "Ratings", "Rating Details"],
                                      removeNull=True
                                      )
    return readable_output, generic_iam_context, res_json


def get_company_findings_command(client, args, first_seen=None, fetch_incidents=False):
    if fetch_incidents:
        guid = args.get('guid', None)
        if not guid:
            res = client.get_companies_guid()
            if res.status_code == 200:
                res_json = res.json()
                guid = res_json.get('my_company', {}).get('guid')
            else:
                raise Exception('Unable to fetch GUID')
        severity = args.get('findings_min_severity', None)
        if severity:
            severity = severity.lower()
        grade = args.get('findings_grade', None)
        if type(grade) is list:
            grade = ','.join(grade)
        asset_category = args.get('findings_asset_category', None)
        if asset_category:
            asset_category = asset_category.lower()
        risk_vector_list = args.get('risk_vector')
        if not isinstance(risk_vector_list, list):
            risk_vector_list = risk_vector_list.split(',')
        if 'All' in risk_vector_list:
            risk_vector_list = []
        first_seen = first_seen
        last_seen = (datetime.today() - timedelta(days=1)).strftime(BitSight_date_time_format)
    else:
        guid = args.get('guid')
        severity = args.get('severity', None)
        grade = args.get('grade', None)
        asset_category = args.get('asset_category', None)
        if severity:
            severity = severity.lower()
        if grade:
            grade = grade.lower()
        if asset_category:
            asset_category = asset_category.lower()
        risk_vector_list = args.get('risk_vector_label', None)
        if risk_vector_list:
            risk_vector_list = risk_vector_list.split(',')
        else:
            risk_vector_list = []
        first_seen = args.get('first_seen')
        last_seen = args.get('last_seen')

    severity_mapping = {
        'minor': 1,
        'moderate': 2,
        'material': 3,
        'severe': 4
    }

    asset_category_mapping = {
        'low': 'low,medium,high,critical',
        'medium': 'medium,high,critical',
        'high': 'high,critical',
        'critical': 'critical'
    }

    risk_vector_mapping = {
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
        'unsolicited communications': 'unsolicited_comm'
    }

    risk_vector = ''
    for vector in risk_vector_list:
        risk_vector += risk_vector_mapping[vector.lower()] + ','

    risk_vector = risk_vector[:-1]

    severity_gte = None
    if severity:
        severity_gte = severity_mapping[severity]

    asset_category_eq = None
    if asset_category:
        asset_category_eq = asset_category_mapping[asset_category]

    res_json = client.get_company_findings(guid, first_seen, last_seen, severity_gte, grade, asset_category_eq,
                                           risk_vector)

    return_results(res_json)
    return

    if not fetch_incidents:
        generic_iam_context_data_list = []
        readable_list = []
        results = res_json.get('results')
        if results:
            for result in results:
                generic_iam_context = {
                    'temporaryId': result.get('temporary_id'),
                    'affectsRating': result.get('affects_rating'),
                    'assets': result.get('assets'),
                    'details': result.get('details'),
                    'evidenceKey': result.get('evidence_key'),
                    'firstSeen': result.get('first_seen'),
                    'lastSeen': result.get('last_seen'),
                    'relatedFindings': result.get('related_findings'),
                    'riskCategory': result.get('risk_category'),
                    'riskVector': result.get('risk_vector'),
                    'riskVectorLabel': result.get('risk_vector_label'),
                    'rolledupObservationId': result.get('rolledup_observation_id'),
                    'severity': result.get('severity'),
                    'severityCategory': result.get('severity_category'),
                    'tags': result.get('tags'),
                    'duration': result.get('duration'),
                    'comments': result.get('comments'),
                    'remainingDecay': result.get('remaining_decay')
                }

                generic_iam_context_data_list.append(generic_iam_context)
                readable = {
                    'Evidence Key': result.get('evidence_key'),
                    'Risk Vector Label': result.get('risk_vector_label'),
                    'First Seen': result.get('first_seen'),
                    'Last Seen': result.get('last_seen'),
                    'ID': result.get('temporary_id'),
                    'Risk Category': result.get('risk_category'),
                    'Severity': result.get('severity_category'),
                }
                readable_list.append(readable)
        else:
            generic_iam_context_data_list.append({})
            readable_list.append({})

        readable_output = tableToMarkdown(name='Get Company findings:',
                                          t=readable_list,
                                          headers=["Evidence Key", "Risk Vector Label", "First Seen", "Last Seen",
                                                   "ID", "Risk Category", "Severity"],
                                          removeNull=True
                                          )
        return readable_output, generic_iam_context_data_list, res_json
    else:
        return res_json


def main():
    command = demisto.command()
    params = demisto.params()
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_key = params.get('apikey', {})

    demisto.info(f'Command being called is {command}')

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        ok_codes=[200],
        auth=requests.auth.HTTPBasicAuth(api_key, '')
    )

    try:
        '''EXECUTION CODE'''
        if command == 'bitsight-get-company-details':
            readable_output, context, res_json = get_company_details_command(client, demisto.args())
            results = CommandResults(
                readable_output=readable_output,
                outputs_prefix='BitSight.Company',
                outputs=context,
                outputs_key_field='guid',
                raw_response=res_json
            )
            return_results(results)
        elif command == 'bitsight-get-company-findings':
            readable_output, context, res_json = get_company_findings_command(client, demisto.args())
            results = CommandResults(
                readable_output=readable_output,
                outputs_prefix='BitSight.Finding',
                outputs=context,
                outputs_key_field='guid',
                raw_response=res_json
            )
            return_results(results)
        elif command == 'test-module':
            human_readable, outputs, raw_response = test_module(client)
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
        elif command == 'bitsight-get-companies-guid':
            readable_output, context, res_json = get_companies_guid_command(client)
            results = CommandResults(
                readable_output=readable_output,
                outputs_prefix='BitSight.GUID',
                outputs=context,
                outputs_key_field='temporary_id',
                raw_response=res_json
            )
            return_results(results)
        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()

            last_run_curr, events = fetch_incidents(client, last_run, params)

            if last_run != last_run_curr:
                demisto.setLastRun({'time': last_run_curr['time']})
                demisto.incidents(events)
            else:
                demisto.incidents([])

    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

register_module_line('BitSight for Security Performance Management', 'end', __line__())
