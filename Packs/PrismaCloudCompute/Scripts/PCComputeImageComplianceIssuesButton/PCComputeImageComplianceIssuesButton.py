import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

'''
Script Description:
    This script runs the 'prisma-cloud-compute-images-scan-list' command for a specific image id and returns details about its
compliance issues, if found.
    If any compliance issues found, it will create a new tab in the layout called "Detailed Compliance Issues" showing the
issues details.
    Returns the following fields for each compliance ID:
    - Compliance ID
    - Cause
    - Severity
    - Title
    - Description
'''


# Command Function
def run_prisma_cloud_compute_images_scan_list(image_id: str) -> list:
    """
    Runs the 'prisma-cloud-compute-images-scan-list' command with specified arguments and returns specific details about its
    compliance issues, if found.

    Args:
        image_id: ID of the image to scan.

    Returns:
        list
    """
    preconfigured_args = {
        'compact': 'false',
        'all_results': 'true'
    }

    args = {'id': image_id}
    args.update(preconfigured_args)

    # Run the 'prisma-cloud-compute-images-scan-list' command
    result = demisto.executeCommand("prisma-cloud-compute-images-scan-list", args)
    if isError(result):
        return_error(f"Failed to run 'prisma-cloud-compute-images-scan-list': {get_error(result)}")

    # Check if the result is a list and contains 'Contents'
    if not result or not isinstance(result, list) or not result[0].get('Contents'):
        return_error("No valid results found in the command output.")

    # Extract specific details from the command results
    contents_list = result[0]['Contents'][0]
    compliance_issues = contents_list.get('complianceIssues')

    return compliance_issues


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
    ids_to_filter = [compliance_id.strip() for compliance_id in compliance_ids.split(',')]

    # Filter issues based on provided IDs
    filtered_compliance_issues = [issue for issue in compliance_issues if str(issue.get('id', '')) in ids_to_filter]

    return filtered_compliance_issues


def process_and_output_compliance_issues(compliance_issues: list, image_id: str) -> CommandResults:
    """
    Process the compliance issues and output specific details to the War Room.

    Args:
        compliance_issues: List of compliance issues.
        image_id: ID of the image.

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
        outputs_prefix='PrismaCloudCompute.PCC_ImageComplianceIssues',
        outputs={
            'image_id': image_id,
            'compliance_issues': rows
        },
        tags=['ComplianceIssuesResults'],
        readable_output=tableToMarkdown(
            f'Compliance Issues of image {image_id}',
            rows,
            headers=['ComplianceID', 'Cause', 'Severity', 'Title', 'Description']
        )
    )
    incident_id = demisto.incidents()[0]['id']
    demisto.executeCommand('setIncident', {'id': incident_id, 'prismacloudcomputeshowcompliancetab': 'image-detailed'})

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
        image_id = demisto.getArg('image_id')
        compliance_ids = demisto.getArg('compliance_ids')

        # Verify and normalize image_id
        if not image_id.startswith('sha256:'):
            if len(image_id) == 64:
                image_id = f'sha256:{image_id}'
            else:
                return_error("Invalid image_id. It should be in the format 'sha256:{64 characters}'.")
        elif len(image_id) != 71:
            return_error("Invalid image_id length. It should be in the format 'sha256:{64 characters}'.")

        # Run the command with the provided arguments
        compliance_issues = run_prisma_cloud_compute_images_scan_list(image_id)

        # Filter compliance issues based on provided compliance issues IDs
        filtered_compliance_issues = filter_compliance_issues(compliance_issues, compliance_ids)

        # Process the filtered compliance_issues
        command_results = process_and_output_compliance_issues(filtered_compliance_issues, image_id)

        # Output to War Room
        return_results(command_results)

    except Exception as e:
        return_error(f"Error in script: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
