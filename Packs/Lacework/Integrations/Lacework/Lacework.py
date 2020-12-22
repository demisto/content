import json

from datetime import datetime, timedelta, timezone

from laceworksdk import LaceworkClient
import demistomock as demisto
from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

handle_proxy()

''' GLOBAL VARS '''
LACEWORK_ACCOUNT = demisto.params().get('lacework_account')
LACEWORK_API_KEY = demisto.params()['lacework_api_key']
LACEWORK_API_SECRET = demisto.params()['lacework_api_secret']
LACEWORK_EVENT_SEVERITY = demisto.params()['lacework_event_severity']
LACEWORK_EVENT_HISTORY_DAYS = demisto.params()['lacework_event_history']

try:
    lacework_client = LaceworkClient(instance=LACEWORK_ACCOUNT,
                                     api_key=LACEWORK_API_KEY,
                                     api_secret=LACEWORK_API_SECRET)
except Exception:
    demisto.results("Lacework API authentication failed. Please validate Instance Name, API Key, and API Secret.")

''' HELPER FUNCTIONS '''


def get_event_severity_threshold():
    """
    Convert the Event Severity string to the appropriate integer
    """

    if LACEWORK_EVENT_SEVERITY == 'critical':
        return 1
    elif LACEWORK_EVENT_SEVERITY == 'high':
        return 2
    elif LACEWORK_EVENT_SEVERITY == 'medium':
        return 3
    elif LACEWORK_EVENT_SEVERITY == 'low':
        return 4
    elif LACEWORK_EVENT_SEVERITY == 'informational':
        return 5
    else:
        raise Exception('Invalid Event Severity Threshold was defined.')


def create_entry(title, data, ec, human_readable=None):
    """
    Simplify the output/contents
    """

    if human_readable is None:
        human_readable = data

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, human_readable) if data else 'No result were found',
        'EntryContext': ec
    }


def format_compliance_data(compliance_data, rec_id):
    """
    Simplify the output/contents for Compliance reports
    """

    if len(compliance_data['data']) > 0:

        compliance_data = compliance_data['data'][0]

        # If the user wants to filter on a recommendation ID
        if rec_id:
            # Iterate through all recommendations, removing irrelevant ones
            for recommendation in compliance_data["recommendations"][:]:
                if recommendation["REC_ID"] not in rec_id:
                    compliance_data["recommendations"].remove(recommendation)

        # Build Human Readable Output
        readable_output = tableToMarkdown("Compliance Summary",
                                          compliance_data['summary'])

        ec = {"Lacework.Compliance(val.reportTime === obj.reportTime)": compliance_data}
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': compliance_data,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': readable_output,
            'EntryContext': ec
        }
    else:
        return {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": 'No compliance data was returned.'
        }


''' COMMANDS FUNCTIONS '''


def get_aws_compliance_assessment():
    """
    Get the latest AWS compliance assessment
    """

    account_id = demisto.args().get('account_id')
    rec_id = argToList(demisto.args().get('rec_id'))
    report_type = demisto.args().get('report_type', 'AWS_CIS_S3')

    response = lacework_client.compliance.get_latest_aws_report(account_id,
                                                                file_format="json",
                                                                report_type=report_type)

    results = format_compliance_data(response, rec_id)
    return_results(results)


def get_azure_compliance_assessment():
    """
    Get the latest Azure compliance assessment
    """

    tenant_id = demisto.args().get('tenant_id')
    subscription_id = demisto.args().get('subscription_id')
    rec_id = argToList(demisto.args().get('rec_id'))
    report_type = demisto.args().get('report_type', 'AZURE_CIS')

    response = lacework_client.compliance.get_latest_azure_report(tenant_id,
                                                                  subscription_id,
                                                                  file_format="json",
                                                                  report_type=report_type)

    results = format_compliance_data(response, rec_id)
    return_results(results)


def get_gcp_compliance_assessment():
    """
    Get the latest GCP compliance assessment
    """

    organization_id = demisto.args().get('organization_id')
    project_id = demisto.args().get('project_id')
    rec_id = argToList(demisto.args().get('rec_id'))
    report_type = demisto.args().get('report_type', 'GCP_CIS')

    response = lacework_client.compliance.get_latest_gcp_report(organization_id,
                                                                project_id,
                                                                file_format="json",
                                                                report_type=report_type)

    results = format_compliance_data(response, rec_id)
    return_results(results)


def get_gcp_projects_by_organization():
    """
    Get a list of GCP Projects that reside in an Organization
    """

    organization_id = demisto.args().get('organization_id')

    response = lacework_client.compliance.list_gcp_projects(organization_id)

    ec = {"Lacework.GCP(val.organization === obj.organization)": response['data']}
    create_entry('Google Cloud Platform Projects for Organization ' + str(organization_id),
                 response['data'],
                 ec)


def run_aws_compliance_assessment():
    """
    Run an AWS compliance assessment
    """

    account_id = demisto.args().get('account_id')

    run_report_response = lacework_client.run_reports.aws(account_id)

    if run_report_response:
        return {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": 'Compliance assessment running on AWS Account ID ' + str(account_id)
        }
    else:
        return {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": 'Failed to trigger AWS compliance assessment.'
        }


def run_azure_compliance_assessment():
    """
    Run an Azure compliance assessment
    """

    tenant_id = demisto.args().get('tenant_id')

    run_report_response = lacework_client.run_reports.azure(tenant_id)

    if run_report_response:
        return {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": 'Compliance assessment running on Azure Tenant ID ' + str(tenant_id)
        }
    else:
        return {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": 'Failed to trigger Azure compliance assessment.'
        }


def run_gcp_compliance_assessment():
    """
    Run a GCP compliance assessment
    """

    project_id = demisto.args().get('project_id')

    run_report_response = lacework_client.run_reports.gcp(project_id)

    if run_report_response:
        return {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": 'Compliance assessment running on GCP Project ID ' + str(project_id)
        }
    else:
        return {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": 'Failed to trigger GCP compliance assessment.'
        }


def get_container_vulnerabilities():
    """
    Get Container Vulnerabilities
    """

    id_type = demisto.args().get('id_type', 'image_digest')
    image_id = demisto.args().get('image_id', None)
    image_digest = demisto.args().get('image_digest', None)
    severity = demisto.args().get('severity', None)
    fixable = demisto.args().get('fixable', None)
    start_time = demisto.args().get('start_time', None)
    end_time = demisto.args().get('end_time', None)

    if id_type == 'image_digest':
        response = lacework_client.vulnerabilities.get_container_vulnerabilities(image_digest=image_digest,
                                                                                 severity=severity,
                                                                                 fixable=fixable,
                                                                                 start_time=start_time,
                                                                                 end_time=end_time)
    elif id_type == 'image_id':
        response = lacework_client.vulnerabilities.get_container_vulnerabilities(image_id=image_id,
                                                                                 severity=severity,
                                                                                 fixable=fixable,
                                                                                 start_time=start_time,
                                                                                 end_time=end_time)
    else:
        raise Exception('Invalid Container Image ID Type.')

    full_data = response
    if response['data'].get('image', ''):
        response['data'].pop('image')
    human_readable = response

    ec = {"Lacework.Vulnerability.Container(val.last_evaluation_time === obj.last_evaluation_time)": response['data']}
    return create_entry("Lacework Vulnerability Data for Container",
                        full_data['data'],
                        ec,
                        human_readable=human_readable['data'])


def get_host_vulnerabilities():
    """
    Get Host Vulnerabilities
    """

    fixable = demisto.args().get('fixable', None)
    namespace = demisto.args().get('namespace', None)
    severity = demisto.args().get('severity', None)
    start_time = demisto.args().get('start_time', None)
    end_time = demisto.args().get('end_time', None)
    cve = demisto.args().get('cve', None)
    limit = demisto.args().get('limit', None)

    response = lacework_client.vulnerabilities.get_host_vulnerabilities(fixable=fixable,
                                                                        namespace=namespace,
                                                                        severity=severity,
                                                                        start_time=start_time,
                                                                        end_time=end_time,
                                                                        cve=cve)

    # If a limit is set, then use it
    if limit:
        try:
            limit = int(limit)
            response['data'] = response['data'][0:limit]
        except Exception:
            return {
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": "The provided limit parameter was invalid."
            }

    ec = {"Lacework.Vulnerability.Host(val.cve_id === obj.cve_id)": response['data']}
    return create_entry("Lacework Host Vulnerability Data",
                        response['data'],
                        ec)


def get_event_details():
    """
    Get Event Details
    """

    event_id = demisto.args().get('event_id')

    response = lacework_client.events.get_details(event_id)

    ec = {"Lacework.Event(val.EVENT_ID === obj.EVENT_ID)": response['data']}
    return create_entry("Lacework Event " + str(event_id),
                        response['data'],
                        ec)


def fetch_incidents():
    """
    Function to fetch incidents (events) from Lacework
    """

    date_format = "%Y-%m-%dT%H:%M:%SZ"

    # Make a placeholder for events
    new_incidents = []

    # Get data from the last run
    max_event_id = demisto.getLastRun().get('max_event_id', 0)

    now = datetime.now(timezone.utc)

    # Generate ISO8601 Timestamps
    end_time = now.strftime(date_format)
    start_time = now - timedelta(days=int(LACEWORK_EVENT_HISTORY_DAYS))
    start_time = start_time.strftime(date_format)

    # Get the event severity threshold
    event_severity_threshold = get_event_severity_threshold()

    # Get events from Lacework
    events_response = lacework_client.events.get_for_date_range(start_time, end_time)
    events_data = events_response.get('data', [])

    temp_max_event_id = max_event_id

    # Iterate through all events
    for event in events_data:

        # Convert the current Event ID to an integer
        event_id = int(event['EVENT_ID'])
        event_severity = int(event['SEVERITY'])

        # If the event is severe enough, continue
        if event_severity <= event_severity_threshold:

            # If the Event ID is newer than we've imported, then add it
            if event_id > max_event_id:

                # Store our new max Event ID
                if event_id > temp_max_event_id:
                    temp_max_event_id = event_id

                # Get the event details from Lacework
                event_details = lacework_client.events.get_details(event['EVENT_ID'])
                event_details['data'][0]['SEVERITY'] = event['SEVERITY']

                incident = {
                    'name': 'Lacework Event: ' + event['EVENT_TYPE'],
                    'occurred': event['START_TIME'],
                    'rawJSON': json.dumps(event_details['data'][0])
                }

                new_incidents.append(incident)

    max_event_id = temp_max_event_id

    demisto.setLastRun({
        'max_event_id': max_event_id
    })
    demisto.incidents(new_incidents)


''' EXECUTION CODE '''


try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        try:
            response = lacework_client.integrations.get_all()
            if response['ok']:
                demisto.results('ok')
        except Exception as error:
            demisto.results(error)
    elif demisto.command() == 'lw-get-aws-compliance-assessment':
        demisto.results(get_aws_compliance_assessment())
    elif demisto.command() == 'lw-get-azure-compliance-assessment':
        demisto.results(get_azure_compliance_assessment())
    elif demisto.command() == 'lw-get-gcp-compliance-assessment':
        demisto.results(get_gcp_compliance_assessment())
    elif demisto.command() == 'lw-get-gcp-projects-by-organization':
        demisto.results(get_gcp_projects_by_organization())
    elif demisto.command() == 'lw-run-aws-compliance-assessment':
        demisto.results(run_aws_compliance_assessment())
    elif demisto.command() == 'lw-run-azure-compliance-assessment':
        demisto.results(run_azure_compliance_assessment())
    elif demisto.command() == 'lw-run-gcp-compliance-assessment':
        demisto.results(run_gcp_compliance_assessment())
    elif demisto.command() == 'lw-get-container-vulnerabilities':
        demisto.results(get_container_vulnerabilities())
    elif demisto.command() == 'lw-get-host-vulnerabilities':
        demisto.results(get_host_vulnerabilities())
    elif demisto.command() == 'lw-get-event-details':
        demisto.results(get_event_details())
    elif demisto.command() == 'fetch-incidents':
        demisto.results(fetch_incidents())
except Exception as e:
    LOG(e)
    LOG.print_log()
    raise
