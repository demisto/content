import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from datetime import datetime, timedelta
import json
import base64
import re
import mimetypes

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
REPORT_STATUS = {
    "open": "open",
    "in_progress": "in_progress",
    "resolved": "resolved",
    "discarded": "discarded"
}

""" CLIENT CLASS """


class CaClient(BaseClient):
    """
    CybelAngel client enables access to CybelAngel API
    """

    def __init__(self, base_url, client_id, secret_client, auth_token, tenant_id):
        super().__init__(base_url=base_url)
        if not auth_token:
            auth_token = self.get_auth_token(client_id, secret_client)
        else:
            try:
                self._headers = self.set_headers(auth_token)
                self.get_domain_watchlist()
            except Exception as e:
                if 'Authentication failed: Signature has expired' in str(e):
                    auth_token = self.get_auth_token(client_id, secret_client)
        self.auth_token = auth_token
        self._headers = self.set_headers(self.auth_token)
        self.tenant_id = tenant_id

    def set_headers(self, auth_token):
        """Sets headers for requests to the CybelAngel API

        Args:
            auth_token (str): Token provided for http requests

        Returns:
            str: A token valid for one hour
        """
        return {'Authorization': f"Bearer {auth_token}", 'Content-Type': 'application/json'}

    def get_auth_token(self, client_id, client_secret):
        """ Gets the authorization token from the CybelAngel API

        Args:
            client_id (str): Client ID provided by the CybelAngel platform
            client_secret (str): Secret provided by the CybelAngel platform

        Returns:
            str: A token valid for one hour
        """
        old_base_url = self._base_url
        self._base_url = "https://auth.cybelangel.com/oauth/token"
        data = self._http_request(
            method="POST",
            headers={
                "content-type": "application/json"},
            json_data={
                "client_id": f"{client_id}",
                "client_secret": f"{client_secret}",
                "grant_type": "client_credentials",
                "audience": "https://platform.cybelangel.com/"})
        self._base_url = old_base_url
        return data["access_token"]

    def get_reports_by_date(self, start_date, end_date=None):
        """ Gets reports from start_date to end_date

        Args:
            start_date (str): Date from reports are going to be pulled
            end_date (str): Date where the pull is going to stop, if end_date is not
                            provided, this date will be the current date.

        Returns:
            list: list containing all the reports contained between the dated
        """
        if not end_date:
            end_date = datetime.now().strftime(DATE_FORMAT)
        params = {"start-date": start_date, "end-date": end_date}
        return self._http_request(
            method="GET",
            url_suffix="v2/reports",
            params=params)

    def get_report_by_id(self, report_id):
        """ Retrieves a report from the CybelAngel API

        Args:
            report_id (str): Report ID

        Returns:
            dict: dict containing the report as returned from the API
        """
        return self._http_request(
            method="GET",
            url_suffix=f"v2/reports/{report_id}")

    def get_single_attachment(self, report_id, attachment_id):
        """ Retrieves an attachment from a report from the CybelAngel API

        Args:
            report_id (str): Report ID
            attachment_id (str): Attachment ID

        Returns:
            str: returns a file encoded in base64 string
        """
        url_suffix = f"v1/reports/{report_id}/attachments/{attachment_id}"
        return self.file_request_handler("GET", url_suffix)

    def get_domain_watchlist(self, limit=1):
        """Gets the list of domains being watched

        Args:
            limit (int): limit of results

        Returns:
            list: Returns the list of domains being watched
        """
        params = {"limit": limit}
        return self._http_request(
            method="GET",
            url_suffix="v1/domains",
            params=params)

    def get_asset(self, url_suffix):
        """Gets an asset from absolute url

        Args:
            url_suffix (str): Full API Path from asset

        Returns:
            str: returns a file encoded in base64 string
        """
        return self.file_request_handler("GET", url_suffix)

    def file_request_handler(self, method, url_suffix):
        """Auxiliary function to handle binary files to pass it as strings for further treatment

        Args:
            url_suffix (str): Full API Path from asset

        Returns:
            str: returns a file encoded in base64 string
        """
        with self._http_request(method, url_suffix=url_suffix, stream=True, resp_type="response") as req:
            req.raise_for_status()
            encoded_file = base64.b64encode(req.content)
        return encoded_file.decode()

    def get_pdf_report(self, report_id):
        """Gets a PDF file of the report

        Args:
            report_id (str): Report ID

        Returns:
            str: returns a file encoded in base64 string
        """
        url_suffix = f"v1/reports/{report_id}/pdf"
        return self.file_request_handler("GET", url_suffix=url_suffix)

    def update_report_status(self, report_id, status):
        """Updates the state of a report

        Args:
            report_id (str): Report ID
            status (str): The status to be set [open, resolved]

        Returns:
            dict: dict containing the result of the change and the id of report
        """
        url_suffix = f"v1/reports/{report_id}/status"
        data = {"status": status}
        return self._http_request("PUT", url_suffix=url_suffix, json_data=data)

    def get_comments(self, report_id):
        """Get the list of comments on a specific report

        Args:
            report_id (str): Report ID

        Returns:
            dict: dict containing a list of comments from report
        """
        url_suffix = f"v1/reports/{report_id}/comments"
        return self._http_request("GET", url_suffix=url_suffix)

    def create_comment(self, comment, report_id):
        """Create a new comments attached to a specific report

        Args:
            report_id (str): Report ID
            comment (str): Comment content to be displayed in report

        Returns:
            dict: dict containing the comment being posted
        """
        url_suffix = f"v1/reports/{report_id}/comments"
        discussion_id = f"{report_id}:{self.tenant_id}"
        data = {
            "content": comment,
            "discussion_id": discussion_id,
        }
        return self._http_request("POST", url_suffix=url_suffix, json_data=data)


""" HELPER FUNCTIONS """


def get_file_size(b64string):
    """Gets the file size from a file encoded in a base64 format
        https://stackoverflow.com/questions/11761889/get-image-file-size-from-base64-string

    Args:
        b64string (str): File encoded in base64 format

    Returns:
        string: Returns a str with the size of the file
    """
    size = int((len(b64string) * 3) / 4 - b64string.count("=", - 2)) / 1024
    return "{:.1f} Kb".format(size)


def get_file_structure(file, filename):
    """Returns a normalized file structure

    Args:
        file (str): File encoded in base64 format
        filename (str): name of the file passed as arg

    Returns:
        dict: Returns a normalized structure of a file
    """
    file_type = mimetypes.guess_type(filename)[0]
    file_size = get_file_size(file)
    file_structure = {
        "file": file,
        "filename": filename,
        "file_type": file_type,
        "file_size": file_size
    }
    return file_structure


def get_extracted_field(field, dictionaries):
    """Returns a value from dict if field present as value

    Args:
        field (str): field to be searched
        dictionaries (str): array of dict containing parameter values

    Returns:
        dict: Returns a normalized structure of a file
    """
    for dictionary in dictionaries:
        for item in dictionary:
            if dictionary[item] == field:
                return dictionary["value"]
    return None


def extract_values(ressource, counter, fields_to_extract, filename, filename_params):
    """Auxliary function destined to extract data from ressource and assign filename

    Args:
        ressource (dict): structure containing data
        counter (int): counter of ressources
        fields_to_extract (list[dict]): data to be extracted from the ressource
        filename (str): format of the filename
        filename_params (list): params to be retrieved from source to filename format

    Returns:
        fields_to_extract: array of dictionaries containing extracted values from the ressource
        filename: absolute filename
    """
    if fields_to_extract:
        for dictionary in fields_to_extract:
            dictionary["value"] = ressource[dictionary["ressource_name"]]
        aux_filename = get_extracted_field("filename", fields_to_extract)
        if aux_filename:
            filename = aux_filename
    if filename_params:
        format_values = list()
        for param in filename_params:
            if type(param) == list:
                format_values.append(param[counter])
            else:
                format_values.append(param)
        filename = filename.format(*format_values)
    return fields_to_extract, filename


def get_func_params(mapped_params, file_function_params):
    """ Gets the value of params to be used in a function

    Args:
        mapped_params (dict): dict containing values of parameters
        file_function_params (list): list of params

    Returns: returns the values of the parameters passed from file_function_params
    """
    function_args = dict()
    for param in file_function_params:
        if "extract" in param["value"] and param["value"]["extract"]:
            function_args[param["name"]] = get_extracted_field(param["name"], mapped_params)
        else:
            function_args[param["name"]] = param["value"]["content"]
    return function_args


def get_ressources(ressources, file_function, file_function_params,
                   fields_to_extract=None, filename_format=None, filename_params=None):
    """Gets an array of structured files

    Args:
        ressources: raw data to be used to parse other args
        file_function: function that takes as a parameter file_function_params
        file_function_params (list[dict]): list of dictionaries containing parameters and their match on the ressource
            Ex
            [{"name": <functions_parameter_name>, "value": {"content": <absolute_value>}},
             {"name": <functions_parameters_name>, "value": {"extract": True}}])
             if extract, the value has to be present in the ressource,
                the mapping will be set on the param fields_to_extract
                fields_to_extract (list[dict]): List of dictionaries that associates value present in
                the ressource (ressource_name) and the name of the
            function parameter, this values will be extracted from the ressource
            Ex
            [{"ressource_name": "name"}, {"ressource_name": "id", "parameter_name": "attachment_id"}]
    """
    files = list()
    for counter, ressource in enumerate(ressources):
        if fields_to_extract or filename_params:
            fields_to_extract, filename = extract_values(ressource, counter, fields_to_extract, filename_format, filename_params)
        if file_function_params:
            function_args = get_func_params(fields_to_extract, file_function_params)
        if not file_function_params:
            file = file_function(ressource)
        else:
            file = file_function(**function_args)
        file_structure = get_file_structure(file, filename)
        files.append(file_structure)
    return files


def get_filtered_reports(report_filter, report_list):
    """ Filters reports by status

    Args:
        report_filter (str): filter to be applied
        report_list (list): list of reports to be filtered

    Returns:
        list: list of reports with the status <report_filter>
    """
    reports = []
    for item in report_list:
        if item["status"] in report_filter:
            item["report_content"] = get_formatted_report(item["report_content"])
            reports.append(item)
    return reports


def get_last_fetch(report_list):
    """ Gets the next date to fetch

    Args:
        report_list (list): List of reports to determinate oldest result

    Returns:
        date: Next date to fetch
    """
    last_fetch = datetime.strptime(report_list[0]["sent_at"][:report_list[0]["sent_at"].find("+")], DATE_FORMAT)
    for item in report_list:
        current_fetch = item["sent_at"]
        current_fetch = datetime.strptime(current_fetch[:current_fetch.find("+")], DATE_FORMAT)
        if not last_fetch or last_fetch < current_fetch:
            last_fetch = current_fetch
    last_fetch = last_fetch + timedelta(seconds=1)
    return last_fetch.strftime(DATE_FORMAT)


def get_report_data(report_content):
    """ Auxiliary function to extract all data from report content

    Args:
        report_content (str): raw report

    Returns:
        report (dict): this will contain all data related to a category
        category_index (dict): template for information extracted per category
        index_categories (list): list of tuples of the occurences of categories in
            raw report to conservate original order
    """
    categories = ["Executive summary", "Abstract", "Technical details", "Risk overview",
                  "Detected data sample", "Analysis", "Risk assessment", "Suggestions", "Screenshot", "Whois"]
    # Categories taken into account for the format

    index_categories = list()
    """
    Each category will have to fields
    - regex: This will extract the data corresponding to the field
    - text_format: the markdown format that will be added
    """
    category_index = {
        "Titles": {"regex": "#{3,}(?:\s\n\s+)?\s?(.*?)\n", "text_format": "#### **{}**\n"},
        "Abstract": {"regex": "\n{3}(.*?)\n{2}?\s?", "text_format": "{}"},
        "Executive summary": {"regex": "\n{3}(.*?)\n(.*?)(?=\n{3})", "text_format": "# **{}**: {}\n"},
        "Technical details": {"regex": "\n{3}(.*?)\n(.*?)(?:(?=\n{3})|$)", "text_format": "|{}|{}|\n"},
        "Risk overview": {"regex": "\n{2,}\\s(.*?)\n", "text_format": "*{}*\n"},
        "Detected data sample": {"regex": "\n{2,}(.*?)(?:(?=\n{2})|$)", "text_format": "* *{}*\n"},
        "Risk assessment": {"regex": "\n{3}\s(.*?)\n\s+\n{2}\s(.*?)\n", "text_format": "### {}\n * *{}*"},
        "Suggestions": {"regex": "\\*\\s(.*?)(?=\\.)", "text_format": "* {}\n"},
        "Screenshot": {"regex": "\[cba-image\]\((.*?)\)", "text_format": "* See attachment *CybelAngel_screenshot_{}.jpg*"},
        "Whois": {"regex": "\n(.*?):[\s+\W](.*?)(?:(?=\n)|$)", "text_format": "{}: {}\n"}
    }
    # Creates an index for the apparition of the categories in the report
    for i in categories:
        category_pos = report_content.find(i)
        if category_pos > 0:
            index_categories.append((i, category_pos))
    # sort it in order or apparition
    index_categories.sort(key=lambda a: a[1])
    report = {}
    report["Titles"] = re.findall(category_index["Titles"]["regex"], report_content)
    for count, category in enumerate(index_categories):
        category_key = category[0]
        index_category = category[1]
        final_loop = True if count + 1 == len(index_categories) else False
        # Here the regex will be applied between categories or EOF for the final loop
        if final_loop:
            report[category_key] = re.findall(
                category_index[category_key]["regex"],
                report_content[index_category:])
        else:
            report[category_key] = re.findall(
                category_index[category_key]["regex"],
                report_content[index_category:index_categories[count + 1][1]])
    return report, category_index, index_categories


def get_formatted_report(report_content):
    """ Formats the content of a CybelAngel report to be styled in a markdown format

    Args:
        report_content (str): Report content

    Returns:
        str: report styled in markdown format
    """
    report, category_index, index_categories = get_report_data(report_content)
    new_report = ""
    for title in report["Titles"]:
        new_report += category_index["Titles"]["text_format"].format(title)

    """ Here more customization could be done for each section
    Ex:
    - Table headers
    - Code block format
    """
    for item in index_categories:
        new_report += f"\n## {item[0]}\n"  # Category title
        content = "{}"  # Common content block
        if item[0] == "Technical details":
            new_report += "|Technical key| Technical value|\n|--------------|------------|\n"
        if item[0] == "Executive summary":
            content = "***\n{}\n***"
        if item[0] == "Whois":
            content = "```\n{}```"
        block = ""
        for counter, elem in enumerate(report[item[0]]):
            if not elem:
                continue  # Check if section is present in original report
            if item[0] == "Screenshot":
                block += category_index[item[0]]["text_format"].format(counter + 1)  # Special format for screenshot attachments
                continue
            if type(elem) == tuple:
                block += category_index[item[0]]["text_format"].format(*elem)  # Multiple fields to unpack
            else:
                block += category_index[item[0]]["text_format"].format(elem)
        new_report += content.format(block)
        new_report += "\n"
    return new_report


def get_module(incident_type):
    """Auxiliary function to find CybelAngel module given an incident type

    Args:
        incident_type (str): Incident to be categorized

    Returns:
        category (str): CybelAngel module
    """
    mapping = {
        "data_breach_prevention": ["sensitive_documents", "sensitive_code", "unsecured_database"],
        "domain_protection": ["malicious_website"],
        "dark_web_monitoring": ["banking_information", "fraud_scheme", "targeting", "vulnerability"]
    }
    for category in mapping:
        if incident_type in mapping[category]:
            return category
    return None


def get_report_title(incident_type, incident_id):
    """ Returns a well formated CybelAngel report title

    Args:
        incident_type (str): incident type
        incident_id (str): Incident ID

    Returns:
        CybelAngel report title
    """
    category = " ".join(incident_type.split("_"))
    incident_type = "".join([x.capitalize() for x in get_module(incident_type).split("_")])
    return f"[CybelAngel-{incident_type}] {incident_id} - new {category} has/have been discovered"


"""
################### BEGIN FETCH ######################
"""


def fetch_incidents(client: CaClient, last_run, first_fetch_time):
    last_fetch = last_run.get("last_fetch")
    if not last_fetch:
        if not first_fetch_time:
            last_fetch = datetime.now().strftime(DATE_FORMAT)
        else:
            last_fetch = first_fetch_time

    incidents = []
    reports = client.get_reports_by_date(start_date=last_fetch)
    reports["reports"] = get_filtered_reports(REPORT_STATUS["open"], reports["reports"])
    # [CybelAngel-DomainProtection] ABC6S6 - A malicious website has been discovered
    for item in reports["reports"]:
        incident = {
            "name": get_report_title(item['incident_type'], item['incident_id']),
            "occurred": item["detected_at"],
            "rawJSON": json.dumps(item)
        }
        incidents.append(incident)
    if len(reports["reports"]) > 0:
        last_fetch = get_last_fetch(reports["reports"])
    next_run = {
        "last_fetch": last_fetch,
        "auth_token": client.auth_token
    }
    return next_run, incidents


"""
################### BEGIN COMMANDS ######################
"""


def test_module(client: CaClient):
    """
    Tests API connectivity and authentication
    When "ok" is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (CaClient): CybelAngel client to use.

    Returns:
        str: "ok" if test passed, anything else will raise an exception and will fail the test.
    """

    res = client.get_domain_watchlist()
    if res["total"]:
        return "ok"
    else:
        return res.text


def create_comment_command(client: CaClient, args: dict):
    """
    cybelangel-create-comment command: Creates a comment on a report
    Args:
        client (CaClient): CybelAngel client to use.
        args (dict): all command arguments
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that created a comment.
    """
    report_id = args.get("report_id")
    comment = args.get("comment")
    res = client.create_comment(comment=comment, report_id=report_id)

    readable_output = tableToMarkdown("CybelAngel comment added", res,
                                      headers=["created_at", "content", "discussion_id"],
                                      date_fields=["created_at"])

    return CommandResults(
        outputs_prefix="CybelAngel.Reports.comment",
        outputs=res,
        readable_output=readable_output)


def get_comments_command(client: CaClient, args: dict):
    """
    cybelangel-get-comments command: Creates a comment on a report
    Args:
        client (CaClient): CybelAngel client to use.
        args (dict): all command arguments
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that will retrieve the comments in a report
    """
    report_id = args.get("report_id")
    res = client.get_comments(report_id)

    readable_output = tableToMarkdown("CybelAngel Report comments", res,
                                      headers=["total", "comments"], date_fields=["created_at"],
                                      json_transform_mapping={"comments": JsonTransformer(keys=("content", "created_at"))})

    return CommandResults(
        outputs_prefix="CybelAngel.Reports.comments",
        outputs=res,
        readable_output=readable_output)


def update_report_status_command(client: CaClient, args: dict):
    """
    cybelangel-update-report-status command: Creates a comment on a report
    Args:
        client (CaClient): CybelAngel client to use.
        args (dict): all command arguments
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that will retrieve the update results
    """
    report_id = args.get("report_id")
    status = args.get("status")
    res = client.update_report_status(report_id, status)

    readable_output = tableToMarkdown("CybelAngel status report", res, headers=["result", "status", "id"])

    return CommandResults(
        outputs_prefix="CybelAngel.Reports.status",
        outputs=res,
        readable_output=readable_output)


def get_single_attachment_command(client: CaClient, args: dict):
    """
    cybelangel-get-single-attachment command: Gets an attachment from report
    Args:
        client (CaClient): CybelAngel client to use.
        args (dict): all command arguments
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that will retrieve a file in base64 format
    """
    report_id = args.get("report_id")
    attachment_id = args.get("attachment_id")
    res = client.get_single_attachment(report_id=report_id, attachment_id=attachment_id)

    readable = get_file_structure(res, "attachment")
    readable["attachment_id"] = attachment_id
    readable["report_id"] = report_id
    readable_output = tableToMarkdown("CybelAngel attachment", readable)

    return CommandResults(
        outputs_prefix="CybelAngel.Report.attachment",
        outputs_key_field="report_id",
        raw_response=res,
        readable_output=readable_output)


def get_single_report_command(client: CaClient, args: dict):
    """
    cybelangel-get-single-report command: Gets a report
    Args:
        client (CaClient): CybelAngel client to use.
        args (dict): all command arguments
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that will retrieve a CybelAngel report
    """
    report_id = args.get("report_id")
    res = client.get_report_by_id(report_id)
    res["old_report"] = res["report_content"]
    res["report_content"] = get_formatted_report(res["report_content"])

    readable_output = tableToMarkdown("CybelAngel report", res,
                                      headers=["category", "report_type", "severity", "abstract", "incident_type",
                                               "created_at", "detected_at", "updated_at", "risks", "attachments", "keywords"],
                                      date_fields=["created_at", "detected_at", "updated_at"])
    return CommandResults(
        outputs_prefix="CybelAngel.Report",
        outputs_key_field="report_id",
        raw_response=res,
        readable_output=readable_output)


def get_reports_command(client: CaClient, args: dict):
    """
    cybelangel-get-reports command: Gets a list of reports between dates
    Args:
        client (CaClient): CybelAngel client to use.
        args (dict): all command arguments
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that will retrieve a list of CybelAngel reports
    """
    start_date = args.get("start_date")
    end_date = args.get("end_date")
    if not end_date:
        end_date = datetime.now().strftime(DATE_FORMAT)
    try:
        start_date = datetime.strptime(str(start_date), DATE_FORMAT)
        end_date = datetime.strptime(str(end_date), DATE_FORMAT)
    except ValueError:
        raise DemistoException("Date does not match yyyy-mm-ddTHH:MM:SS date format")

    if end_date < start_date:
        raise DemistoException("Start date is older than the end date")

    res = client.get_reports_by_date(start_date, end_date)
    report_filter = args.get("status")
    if report_filter:
        res["reports"] = get_filtered_reports(report_filter, res["reports"])

    readable_output = tableToMarkdown("CybelAngel reports", res["reports"],
                                      headers=["url", "category", "updated_at", "severity"],
                                      json_transform_mapping={
                                      "reports": JsonTransformer(keys=("url", "category", "updated_at", "severity"))})

    return CommandResults(
        outputs_prefix="CybelAngel.Reports",
        outputs_key_field="id",
        raw_response=res,
        readable_output=readable_output)


def get_attachments_from_report_command(client: CaClient, args: dict):
    """
    cybelangel-get-attachments-from-report command: Gets a list of attachments
    Args:
        client (CaClient): CybelAngel client to use.
        args (dict): all command arguments
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that will retrieve a list of attachment from report
    """
    report_id = args.get("report_id")
    res = client.get_report_by_id(report_id)
    attachments_list = list()
    report = res["report_content"]
    report_attachments = res["attachments"]
    screenshot_paths = re.findall("\[cba-image\]\(/api/(\S+)\)", report)
    incident_id = res["incident_id"]

    screenshots_attachments = get_ressources(
        ressources=screenshot_paths,
        fields_to_extract=None,
        file_function=client.get_asset,
        file_function_params=None,
        filename_format="CybelAngel_{}_screenshot_{}.jpg",
        filename_params=[incident_id, list(range(1, len(screenshot_paths) + 1))])
    attachments_list.extend(screenshots_attachments)

    cybelangel_attachments = get_ressources(
        ressources=report_attachments,
        fields_to_extract=[{"ressource_name": "name"},
                           {"ressource_name": "id", "parameter_name": "attachment_id"}],
        file_function=client.get_single_attachment,
        file_function_params=[{"name": "report_id", "value": {"content": report_id}},
                              {"name": "attachment_id", "value": {"extract": True}}])
    attachments_list.extend(cybelangel_attachments)

    pdf_attachment = get_file_structure(client.get_pdf_report(report_id), f"CybelAngel_{incident_id}.pdf")
    attachments_list.append(pdf_attachment)

    readable_output = tableToMarkdown("CybelAngel Attachments", attachments_list, headers=["filename", "file_type", "file_size"])

    return CommandResults(
        outputs_prefix="CybelAngel.Report.attachments",
        outputs=attachments_list,
        raw_response=attachments_list,
        readable_output=readable_output)


""" MAIN FUNCTION """


def main():
    params = demisto.params()
    args = demisto.args()
    base_url = params.get("url")
    tenant_id = params.get("tenant_id")
    last_run = demisto.getLastRun()
    auth_token = None
    if last_run:
        auth_token = last_run.get("auth_token")

    client = CaClient(
        base_url=base_url,
        client_id=params.get("client_id"),
        secret_client=params.get("secret_client"),
        auth_token=auth_token,
        tenant_id=tenant_id)
    command = demisto.command()
    command_map = {
        "cybelangel-get-reports": get_reports_command,
        "cybelangel-get-single-report": get_single_report_command,
        "cybelangel-get-single-attachment": get_single_attachment_command,
        "cybelangel-get-attachments-from-report": get_attachments_from_report_command,
        "cybelangel-update-report-status": update_report_status_command,
        "cybelangel-get-comments": get_comments_command,
        "cybelangel-create-comment": create_comment_command
    }
    try:
        if command == "test-module":
            result = test_module(client)
            return_results(result)
        if command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=last_run,
                first_fetch_time=params.get("first_fetch")
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        if command in command_map:
            return_results(command_map[command](client, args))
    except Exception as e:
        return_error(f"Failed to excecute command {command} {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
