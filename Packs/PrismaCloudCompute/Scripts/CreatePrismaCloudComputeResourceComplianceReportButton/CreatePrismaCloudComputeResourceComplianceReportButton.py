import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def filter_severities(data: List[Dict[str, Any]], desired_severities: List[str]) -> List[Dict[str, Any]]:
    """
    Filters the data based on desired severities.

    Args:
        data (list): The input data containing compliance issues.
        desired_severities (list): A list of desired severities to filter the data.

    Returns:
        list: The filtered data based on the desired severities.
    """
    if not desired_severities or set(desired_severities) == {"critical", "high", "medium", "low"}:
        return data

    filtered_data = []

    for entry in data:
        entry_severities = entry.get('complianceissues', '').split('\n\n')
        filtered_issues = []

        for issue in entry_severities:
            for severity in map(str.strip, desired_severities):
                if severity.lower() in issue.lower():
                    filtered_issues.append(issue)
                    break

        if filtered_issues:
            entry['complianceissues'] = '\n\n'.join(filtered_issues)
            filtered_data.append(entry)

    return filtered_data


def filter_resources(data: List[Dict[str, Any]], resource_type: str, desired_resources: List[str]) -> List[Dict[str, Any]]:
    """
    Filters the data based on desired resources and resource type.

    Args:
        data (list): The input data containing resource information.
        resource_type (str): The type of resource to filter (e.g., 'host', 'container', 'image').
        desired_resources (list): A list of desired resource values.

    Returns:
        list: The filtered data based on the desired resources and resource type.
    """
    if not desired_resources:
        return data

    filtered_data = []
    key_mapping = {
        'host': 'hostname',
        'container': 'containerid',
        'image': 'imageid'
    }

    key = key_mapping.get(resource_type, None)
    if not key:
        raise DemistoException("Invalid resource_type. Supported types: 'host', 'container', 'image'.")

    for entry in data:
        resource_value = entry.get(key, '')
        if resource_value in desired_resources:
            filtered_data.append(entry)

    return filtered_data


def transform_html_for_resource(html: str, resource_type: str) -> str:
    """
    Transforms the HTML table based on the resource type.

    Args:
        html (str): The HTML table to transform.
        resource_type (str): The type of resource to determine the transformation.

    Returns:
        str: The transformed HTML table.
    """
    if resource_type == "host":
        html = html.replace('cellpadding="3">', 'cellpadding="3" width="100%" style="word-break: break-all;">')
        html = html.replace("<th>complianceissues", '<th width="40%">Compliance Issues')
        html = html.replace("<th>cloudmetadata", '<th width="25%">Cloud MetaData')
        html = html.replace("<th>compliancedistribution", '<th width="15%">Compliance Distribution')
        html = html.replace("<th>hostname", '<th width="20%">Hostname')

    elif resource_type == "container":
        html = html.replace('cellpadding="3">', 'cellpadding="3" width="120%" style="word-break: break-all;">')
        html = html.replace("<th>complianceissues", '<th width="23%">Compliance Issues')
        html = html.replace("<th>cloudmetadata", '<th width="15%">Cloud MetaData')
        html = html.replace("<th>compliancedistribution", '<th width="8%">Compliance Distribution')
        html = html.replace("<th>containerid", '<th width="15%">Container ID')
        html = html.replace("<th>hostname", '<th width="15%">Hostname')
        html = html.replace("<th>imagename", '<th width="15%">Image Name')

    elif resource_type == "image":
        html = html.replace('cellpadding="3">', 'cellpadding="3" width="120%" style="word-break: break-all;">')
        html = html.replace("<th>complianceissues", '<th width="23%">Compliance Issues')
        html = html.replace("<th>cloudmetadata", '<th width="15%">Cloud MetaData')
        html = html.replace("<th>compliancedistribution", '<th width="8%">Compliance Distribution')
        html = html.replace("<th>imageid", '<th width="15%">Image ID')
        html = html.replace("<th>hosts", '<th width="15%">Hosts')
        html = html.replace("<th>imageinstances", '<th width="15%">Image Instances')

    return html


def send_html_email(html: str, resource_type: str, to_email: str) -> None:
    """
    Sends an HTML email with the compliance report attached.

    Args:
        html (str): The HTML content of the compliance report.
        resource_type (str): The type of resource for the report.
        to_email (str): The email address to send the report to.

    Returns:
        None
    """
    body = f"""
    Hello,

    Please see below the details for the compliance report from Prisma Cloud Compute

    {html}
    """

    res = demisto.executeCommand("send-mail", {
        "to": to_email,
        "subject": f"IMPORTANT: Prisma Cloud Compute {resource_type.capitalize()} Compliance",
        "htmlBody": body
    })

    if is_error(res):
        raise DemistoException(f'Failed to create compliance report: {str(get_error(res))}')

    demisto.results(res)
    return_results(CommandResults(
        readable_output=res[0]['Contents']
    ))


def send_xlsx_email(file_id: str, file_name: str, to_email: str, resource_type: str) -> None:
    """
    Sends an email with an XLSX attachment containing the compliance report.

    Args:
        file_id (str): The ID of the XLSX file attachment.
        file_name (str): The name of the XLSX file.
        to_email (str): The email address to send the report to.
        resource_type (str): The type of resource for the report.

    Returns:
        None
    """
    res = demisto.executeCommand("send-mail", {
        "to": to_email,
        "subject": f"IMPORTANT: Prisma Cloud Compute {resource_type.capitalize()} Compliance",
        "attachIDs": file_id,
        "attachNames": file_name,
        "body": "Please find attached file for the compliance report from Prisma Cloud Compute."
    })

    if is_error(res):
        raise DemistoException(f'Failed to send email with XLSX attachment: {str(get_error(res))}')

    demisto.results(res)
    return_results(CommandResults(
        readable_output=res[0]['Contents']
    ))


def main() -> None:
    """
    Main function to create and send compliance reports based on input parameters.

    Args:
        None

    Returns:
        None
    """
    args = demisto.args()

    try:
        output_type = args.get("output_type", "html")  # New argument for output type, default is HTML
        desired_severities = argToList(args.get("desired_severities", ""))
        desired_resources = argToList(args.get("desired_resources", ""))

        # Fetching the table data
        table_data = argToList(args.get("table", []))
        filtered_data = filter_resources(table_data, args.get("resource_type"), desired_resources)
        filtered_data = filter_severities(filtered_data, desired_severities)

        if not filtered_data:
            demisto.results("No data matching the specified criteria. Email not sent.")
            return

        if output_type.lower() == "html":
            res = demisto.executeCommand("ConvertTableToHTML", {"table": filtered_data, "title": args.get("title"),
                                                                "headers": args.get("headers")})

            if is_error(res):
                raise DemistoException(f'Failed to create compliance report: {str(get_error(res))}')

            html = res[0]["EntryContext"]["HTMLTable"]
            html = html.replace("\n", "<br />")  # Add line break replacement

            resource_type = args.get("resource_type")
            html = transform_html_for_resource(html, resource_type)

            send_html_email(html, resource_type, args.get("to"))

        elif output_type.lower() == "xlsx":
            # New logic for XLSX output
            res = demisto.executeCommand("ExportToXLSX", {"data": filtered_data, "file_name": "compliance_report.xlsx",
                                                          "sheet_name": "Compliance Report"})

            if is_error(res):
                raise DemistoException(f'Failed to create XLSX file: {str(get_error(res))}')

            file_id = res[0]["FileID"]
            file_name = res[0]["File"]

            send_xlsx_email(file_id, file_name, args.get("to"), args.get("resource_type"))

        else:
            return_error("Invalid output type. Supported types: 'html', 'xlsx'.")

    except Exception as e:
        return_error(e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
