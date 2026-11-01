import demistomock as demisto  # noqa: F401

# IMPORTS
# Disable insecure warnings
import urllib3
from CommonServerPython import *  # noqa: F401

urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_API_VERSION = "v47.0"
API_VERSION_PATTERN = re.compile(r"^v\d+\.\d+$")
HEADERS = [
    "Worker_ID",
    "User_ID",
    "Country",
    "Preferred_First_Name",
    "Preferred_Last_Name",
    "Active",
    "Position_Title",
    "Start_Date",
    "End_Date",
    "Terminated",
    "Termination_Date",
]

GET_EMPLOYEES_REQ = """
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:bsvc="urn:com.workday/bsvc">
    <soapenv:Header>
        <wsse:Security soapenv:mustUnderstand="1"
        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsse:UsernameToken wsu:Id="UsernameToken-{token}">
                <wsse:Username>{username}</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0
                #PasswordText">{password}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </soapenv:Header>
    <soapenv:Body>
        <bsvc:Get_Workers_Request bsvc:version="{api_version}">
            <bsvc:Response_Filter>
                <bsvc:Page>{page}</bsvc:Page>
                <bsvc:Count>{count}</bsvc:Count>
            </bsvc:Response_Filter>
            <bsvc:Response_Group>
                <bsvc:Include_Reference>1</bsvc:Include_Reference>
                <bsvc:Include_Personal_Information>1</bsvc:Include_Personal_Information>
                <bsvc:Include_Employment_Information>1</bsvc:Include_Employment_Information>
                <bsvc:Include_Management_Chain_Data>1</bsvc:Include_Management_Chain_Data>
                <bsvc:Include_Photo>1</bsvc:Include_Photo>
            </bsvc:Response_Group>
        </bsvc:Get_Workers_Request>
    </soapenv:Body>
</soapenv:Envelope>
"""

GET_EMPLOYEE_BY_ID = """
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:bsvc="urn:com.workday/bsvc">
    <soapenv:Header>
        <wsse:Security soapenv:mustUnderstand="1"
        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsse:UsernameToken wsu:Id="UsernameToken-{token}">
                <wsse:Username>{username}</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0
                #PasswordText">{password}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </soapenv:Header>
    <soapenv:Body>
        <bsvc:Get_Workers_Request bsvc:version="{api_version}">
            <bsvc:Request_References bsvc:Skip_Non_Existing_Instances="false">
                <bsvc:Worker_Reference>
                    <bsvc:ID bsvc:type="Employee_ID">{employee_id}</bsvc:ID>
                </bsvc:Worker_Reference>
            </bsvc:Request_References>
            <bsvc:Response_Group>
                <bsvc:Include_Reference>1</bsvc:Include_Reference>
                <bsvc:Include_Personal_Information>1</bsvc:Include_Personal_Information>
                <bsvc:Include_Employment_Information>1</bsvc:Include_Employment_Information>
                <bsvc:Include_Management_Chain_Data>1</bsvc:Include_Management_Chain_Data>
                <bsvc:Include_Photo>1</bsvc:Include_Photo>
            </bsvc:Response_Group>
        </bsvc:Get_Workers_Request>
    </soapenv:Body>
</soapenv:Envelope>
"""


def convert_to_json(response):
    raw_json_response = json.loads(xml2json(response))
    workers_data = (
        raw_json_response.get("Envelope", {})
        .get("Body", {})
        .get("Get_Workers_Response", {})
        .get("Response_Data", {})
        .get("Worker")
    )
    return raw_json_response, workers_data


def _as_dict(value) -> dict:
    """Returns the value if it is a dict, otherwise an empty dict (xml2json renders empty elements as None)."""
    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:
    """Returns the value as a list (xml2json renders a single element as a dict and a missing one as None)."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _primary_or_first(value) -> dict:
    """Returns the element marked as primary (or the first one) when Workday returns a list, e.g. multiple jobs."""
    items = [_as_dict(item) for item in _as_list(value)]
    for item in items:
        if item.get("@{urn:com.workday/bsvc}Primary_Job") == "1":
            return item
    return items[0] if items else {}


def get_reference_id(reference, index: int) -> str | None:
    """Returns the text of the ID at the given position of a Workday reference, or None if it does not exist.

    Workday references hold a list of IDs of different types (e.g. WID first, then a readable ID).
    Not every tenant returns every reference or every ID type, so missing values must not raise.
    """
    ids = _as_list(_as_dict(reference).get("ID"))
    if index >= len(ids):
        return None
    return _as_dict(ids[index]).get("#text")


def _to_bool(value) -> bool | None:
    return bool(int(value)) if value not in (None, "") else None


def _position_context(position: dict) -> dict:
    job_profile = _as_dict(position.get("Job_Profile_Summary_Data"))
    business_site = _as_dict(position.get("Business_Site_Summary_Data"))
    site_address = business_site.get("Address_Data")
    site_address = _as_dict(site_address[-1] if isinstance(site_address, list) and site_address else site_address)
    return {
        "Position_ID": position.get("Position_ID"),
        "Position_Title": position.get("Position_Title"),
        "Business_Title": position.get("Business_Title"),
        "Start_Date": position.get("Start_Date"),
        "End_Employment_Reason_Reference": get_reference_id(position.get("End_Employment_Reason_Reference"), 1) or "",
        "Worker_Type": get_reference_id(position.get("Worker_Type_Reference"), 1),
        "Position_Time_Type": get_reference_id(position.get("Position_Time_Type_Reference"), 1),
        "Scheduled_Weekly_Hours": position.get("Scheduled_Weekly_Hours"),
        "Default_Weekly_Hours": position.get("Default_Weekly_Hours"),
        "Full_Time_Equivalent_Percentage": position.get("Full_Time_Equivalent_Percentage"),
        "Exclude_from_Headcount": position.get("Exclude_from_Headcount"),
        "Pay_Rate_Type": get_reference_id(position.get("Pay_Rate_Type_Reference"), 1) or "",
        "Job_Profile_Name": job_profile.get("Job_Profile_Name"),
        "Work_Shift_Required": job_profile.get("Work_Shift_Required"),
        "Critical_Job": job_profile.get("Critical_Job"),
        "Business_Site_id": get_reference_id(business_site.get("Location_Reference"), 1),
        "Business_Site_Name": business_site.get("Name"),
        "Business_Site_Type": get_reference_id(business_site.get("Location_Type_Reference"), 1),
        "Business_Site_Address": {
            "Address_ID": site_address.get("Address_ID"),
            "Formatted_Address": site_address.get("@{urn:com.workday/bsvc}Formatted_Address"),
            "Country": get_reference_id(site_address.get("Country_Reference"), 1),
            "Postal_Code": site_address.get("Postal_Code"),
        },
        "End_Date": position.get("End_Date"),
        "Pay_Through_Date": position.get("Pay_Through_Date"),
    }


def _status_context(worker_status: dict) -> dict:
    return {
        "Active": _to_bool(worker_status.get("Active")),
        "Hire_Date": worker_status.get("Hire_Date"),
        "Hire_Reason": get_reference_id(worker_status.get("Hire_Reason_Reference"), 2),
        "First_Day_of_Work": worker_status.get("First_Day_of_Work"),
        "Retired": worker_status.get("Retired"),
        # Number of days unemployed since the employee first joined the work force. Used only for China:
        "Days_Unemployed": worker_status.get("Days_Unemployed"),
        "Terminated": _to_bool(worker_status.get("Terminated")),
        "Rehire": worker_status.get("Rehire"),
        "Resignation_Date": worker_status.get("Resignation_Date"),
    }


def _termination_context(worker_status: dict) -> dict:
    return {
        "Termination_Date": worker_status.get("Termination_Date"),
        "Primary_Termination_Reason": get_reference_id(worker_status.get("Primary_Termination_Reason_Reference"), 2),
        "Primary_Termination_Category": get_reference_id(worker_status.get("Primary_Termination_Category_Reference"), 1),
        "Termination_Involuntary": worker_status.get("Termination_Involuntary"),
        "Termination_Last_Day_of_Work": worker_status.get("Termination_Last_Day_of_Work"),
    }


def _addresses_context(addresses) -> list:
    addresses_context = []
    for address in map(_as_dict, _as_list(addresses)):
        type_data = _as_dict(_as_dict(address.get("Usage_Data")).get("Type_Data"))
        addresses_context.append(
            {
                "Address_ID": address.get("Address_ID"),
                "Formatted_Address": address.get("@{urn:com.workday/bsvc}Formatted_Address"),
                "Country": get_reference_id(address.get("Country_Reference"), 1) or "",
                "Region": get_reference_id(address.get("Country_Region_Reference"), 2) or "",
                "Region_Descriptor": address.get("Country_Region_Descriptor", ""),
                "Postal_Code": address.get("Postal_Code"),
                "Type": get_reference_id(type_data.get("Type_Reference"), 1) or "",
            }
        )
    return addresses_context


def _emails_context(emails) -> list:
    emails_context = []
    for email in map(_as_dict, _as_list(emails)):
        usage_data = _as_dict(email.get("Usage_Data"))
        type_data = _as_dict(usage_data.get("Type_Data"))
        emails_context.append(
            {
                "Email_Address": email.get("Email_Address"),
                "Type": get_reference_id(type_data.get("Type_Reference"), 1) or "",
                "Primary": _to_bool(type_data.get("@{urn:com.workday/bsvc}Primary")),
                "Public": _to_bool(usage_data.get("@{urn:com.workday/bsvc}Public")),
            }
        )
    return emails_context


def _phones_context(phones) -> list:
    phones_context = []
    for phone in map(_as_dict, _as_list(phones)):
        type_data = _as_dict(_as_dict(phone.get("Usage_Data")).get("Type_Data"))
        phones_context.append(
            {
                "ID": phone.get("ID"),
                "Phone_Number": phone.get("@{urn:com.workday/bsvc}E164_Formatted_Phone"),
                "Type": get_reference_id(phone.get("Phone_Device_Type_Reference"), 1),
                "Usage": get_reference_id(type_data.get("Type_Reference"), 1),
            }
        )
    return phones_context


def _managers_context(management_chain_data, num_of_managers: int) -> list:
    chain = _as_dict(_as_dict(management_chain_data).get("Worker_Supervisory_Management_Chain_Data"))
    managers = _as_list(chain.get("Management_Chain_Data"))
    # Taking the n'th managers from the end of the list (descending from top level manager (ceo))
    managers_context = []
    for level in managers[-num_of_managers:]:
        manager = _primary_or_first(_as_dict(level).get("Manager"))
        managers_context.append(
            {
                "Manager_ID": get_reference_id(manager.get("Worker_Reference"), 1),
                "Manager_Name": manager.get("Worker_Descriptor"),
            }
        )
    return managers_context


def _worker_context(worker: dict, num_of_managers: int) -> dict:
    personal_data = _as_dict(worker.get("Personal_Data"))
    employment_data = _as_dict(worker.get("Employment_Data"))
    name_detail = _as_dict(_as_dict(_as_dict(personal_data.get("Name_Data")).get("Legal_Name_Data")).get("Name_Detail_Data"))
    international_assignment = _as_dict(employment_data.get("International_Assignment_Summary_Data"))

    worker_context = {
        "Worker_ID": worker.get("Worker_ID"),
        "User_ID": worker.get("User_ID"),
        "Country": get_reference_id(name_detail.get("Country_Reference"), 1),
        "Legal_First_Name": name_detail.get("First_Name"),
        "Legal_Last_Name": name_detail.get("Last_Name"),
        "Preferred_First_Name": name_detail.get("First_Name"),
        "Preferred_Last_Name": name_detail.get("Last_Name"),
        "Has_International_Assignment": international_assignment.get("Has_International_Assignment"),
        "Home_Country_Reference": get_reference_id(international_assignment.get("Home_Country_Reference"), 1),
        "Photo": _as_dict(worker.get("Photo_Data")).get("Image"),
    }

    position = _as_dict(_primary_or_first(employment_data.get("Worker_Job_Data")).get("Position_Data"))
    if position:
        worker_context.update(_position_context(position))

    worker_status = _as_dict(employment_data.get("Worker_Status_Data"))
    if worker_status:
        worker_context.update(_status_context(worker_status))
    if worker_status.get("Terminated") == "1":
        worker_context.update(_termination_context(worker_status))

    contact_data = _as_dict(personal_data.get("Contact_Data"))
    worker_context["Addresses"] = _addresses_context(contact_data.get("Address_Data"))
    if emails := _emails_context(contact_data.get("Email_Address_Data")):
        worker_context["Emails"] = emails
    if phones := _phones_context(contact_data.get("Phone_Data")):
        worker_context["Phones"] = phones
    if managers := _managers_context(worker.get("Management_Chain_Data"), num_of_managers):
        worker_context["Managers"] = managers

    return worker_context


def create_worker_context(workers, num_of_managers):
    return [_worker_context(_as_dict(_as_dict(worker).get("Worker_Data")), num_of_managers) for worker in _as_list(workers)]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(
        self, tenant_url, verify_certificate, proxy, tenant_name, token, username, password, api_version=DEFAULT_API_VERSION
    ):
        headers = {"content-type": "text/xml;charset=UTF-8"}
        super().__init__(base_url=tenant_url, verify=verify_certificate, proxy=proxy, headers=headers)
        self.tenant_name = tenant_name
        self.token = token
        self.username = username
        self.password = password
        self.api_version = api_version

    def list_workers(self, page, count, employee_id=None) -> tuple:
        if employee_id:
            body = GET_EMPLOYEE_BY_ID.format(
                token=self.token,
                username=self.username,
                password=self.password,
                api_version=self.api_version,
                employee_id=employee_id,
            )
        else:
            body = GET_EMPLOYEES_REQ.format(
                token=self.token,
                username=self.username,
                password=self.password,
                api_version=self.api_version,
                page=page,
                count=count,
            )
        raw_response = self._http_request(method="POST", url_suffix="", data=body, resp_type="text", timeout=120)
        return convert_to_json(raw_response)


def get_api_version(params: dict) -> str:
    """
    Returns the Workday API version configured in the instance (e.g. 'v47.0').
    Falls back to DEFAULT_API_VERSION when not set, and raises on a malformed value.
    """
    api_version = (params.get("api_version") or DEFAULT_API_VERSION).strip()
    if not API_VERSION_PATTERN.match(api_version):
        raise DemistoException(f"Invalid API version '{api_version}'. Expected a format such as {DEFAULT_API_VERSION}.")
    return api_version


def test_module(client: Client, args: dict) -> str:
    try:
        client.list_workers(page="1", count="1")
    except Exception as e:
        raise DemistoException(f"Test failed. Please check your parameters. \n {e}")
    return "ok"


def list_workers_command(client: Client, args: dict) -> CommandResults:
    count = int(args.get("count", "1"))
    page = int(args.get("page", "1"))
    num_of_managers = int(args.get("managers", "3"))
    employee_id = args.get("employee_id")
    raw_json_response, workers_data = client.list_workers(page, count, employee_id)
    workers_context = create_worker_context(workers_data, num_of_managers)
    workers_readable = tableToMarkdown("Workers", workers_context, removeNull=True, headers=HEADERS)

    return CommandResults(
        readable_output=workers_readable,
        outputs_prefix="Workday.Worker",
        outputs_key_field="Worker_ID",
        outputs=workers_context,
        raw_response=raw_json_response,
    )


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    user: str = params.get("credentials", {}).get("identifier")
    base_url: str = params.get("base_url", "").rstrip("/")
    tenant_name: str = params.get("cred_tenant_name", {}).get("password") or params.get("tenant_name", None)
    username = f"{user}@{tenant_name}"
    password: str = params.get("credentials", {}).get("password")
    token = params.get("cred_token", {}).get("password") or params.get("token")
    if not (token and tenant_name):
        raise DemistoException("Token and Tenant name must be provided.")
    verify_certificate: bool = not params.get("insecure", False)
    proxy: bool = params.get("proxy", False)
    api_version = get_api_version(params)

    tenant_url = f"{base_url}/{tenant_name}/Staffing/"

    commands = {
        "test-module": test_module,
        "workday-list-workers": list_workers_command,
    }

    command = demisto.command()
    LOG(f"Command being called is {command}")

    try:
        client = Client(
            tenant_url=tenant_url,
            verify_certificate=verify_certificate,
            proxy=proxy,
            tenant_name=tenant_name,
            token=token,
            username=username,
            password=password,
            api_version=api_version,
        )

        if command in commands:
            return_results(commands[command](client, demisto.args()))

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
