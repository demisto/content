import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

'''
Script Description:
    This script runs the "prisma-cloud-compute-hosts-scan-list" command for a specific container ID and returns details about its
compliance issues, if found.
    If any compliance issues found, it will create a new tab in the layout called "Detailed Compliance Issues" showing the issues
details.
    Returns the following fields for each compliance ID:
    - Compliance ID
    - Cause
    - Severity
    - Title
    - Description
'''


# Script Name: PCC_ContainerComplianceIssues Script Description: This script runs the
# "prisma-cloud-compute-container-scan-results-list" command and returns specific details.

# Command Function
def run_prisma_cloud_compute_containers_scan_list(container_id: str) -> list:
    """
    Runs the "prisma-cloud-compute-container-scan-results-list" command with specified arguments and returns compliance issues.

    Args:
        container_id: The ID of the container.

    Returns:
        list
    """

    args = {'container_ids': container_id}

    # Run the prisma-cloud-compute-container-scan-results-list command
    result = demisto.executeCommand("prisma-cloud-compute-container-scan-results-list", args)
    if isError(result):
        return_error(f"Failed to run 'prisma-cloud-compute-container-scan-results-list': {get_error(result)}")

    # Check if the result is a list and contains 'Contents'
    if not result or not isinstance(result, list) or not result[0].get('Contents'):
        return_error("No valid results found in the command output.")

    # Extract specific details from the command results
    contents_info = result[0]['Contents'][0]['info']
    compliance_issues = contents_info.get('complianceIssues')

    # Check if compliance_issues is empty
    if not compliance_issues:
        return_results(f"No compliance issues found for container {container_id}")
        sys.exit(0)

    return compliance_issues


# Function to filter compliance issues based on provided IDs
def filter_compliance_issues(compliance_issues: list, compliance_ids: str) -> list:
    """
    Filter compliance issues based on provided IDs.

    Args:
        compliance_issues: List of compliance issues.
        compliance_ids: Comma-separated list of compliance IDs to filter the issues.

    Returns:
        List of filtered compliance issues.
    """
    if not compliance_ids:
        return compliance_issues  # Return all issues if no IDs provided

    # Split comma-separated IDs into a list
    ids_to_filter = [id.strip() for id in compliance_ids.split(',')]

    # Filter issues based on provided IDs
    filtered_compliance_issues = [issue for issue in compliance_issues if str(issue.get('id', '')) in ids_to_filter]

    return filtered_compliance_issues


# Function to process and output compliance issues
def process_and_output_compliance_issues(compliance_issues: list, container_id: str) -> CommandResults:
    """
    Process the compliance issues and returnes the expected output to be displayed in the war room.

    Args:
        compliance_issues: List of compliance issues.
        container_id: The ID of the container.

    Returns:
        CommandResults
    """
    # Iterate over each compliance issue and extract selected keys
    rows = []

    for issue in compliance_issues:
        row = {
            'ComplianceID': str(issue.get('id', '')),
            'Cause': issue.get('cause', ''),
            'Severity': issue.get('severity', ''),
            'Title': issue.get('title', ''),
            'Description': issue.get('description', '')
        }
        rows.append(row)

    # Build CommandResults object
    command_results = CommandResults(
        outputs_prefix='PrismaCloudCompute.PCC_ContainerComplianceIssues',
        outputs={
            'container_id': container_id,
            'compliance_issues': rows
        },
        tags=['ComplianceIssuesResults'],
        readable_output=tableToMarkdown(
            f'Compliance Issues of container {container_id}',
            rows,
            headers=['ComplianceID', 'Cause', 'Severity', 'Title', 'Description']
        )
    )
    incident_id = demisto.incidents()[0]['id']
    demisto.executeCommand('setIncident', {'id': incident_id, 'prismacloudcomputeshowcompliancetab': 'container-detailed'})

    return command_results


# Main function
def main() -> None:
    """
    Main function of the script.

    Args:
        None

    Returns:
        None
    """
    try:
        # Get user-provided arguments
        container_id = demisto.getArg('container_id')
        compliance_ids = demisto.getArg('compliance_ids')

        # Validate container_id length
        if len(container_id) != 64:
            return_error("Invalid container_id. Please verify that you entered a valid 64-character container ID.")

        # Run the command with the provided arguments
        compliance_issues = run_prisma_cloud_compute_containers_scan_list(container_id)

        # Filter compliance issues based on provided compliance issues IDs
        filtered_compliance_issues = filter_compliance_issues(compliance_issues, compliance_ids)

        # Process the filtered compliance_issues
        command_results = process_and_output_compliance_issues(filtered_compliance_issues, container_id)

        # Output to War Room
        return_results(command_results)
    except Exception as e:
        return_error(f"Error in script: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
