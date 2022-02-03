from typing import Dict, Tuple
import demistomock as demisto
from CommonServerPython import *

# IMPORTS
# Disable insecure warnings

# CHANGE IN PACK

requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = "v34.0"
HEADERS = ["Worker_ID", "User_ID", "Country", "Preferred_First_Name", "Preferred_Last_Name", "Active", "Position_Title",
           "Start_Date", "End_Date", "Terminated", "Termination_Date"]

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
                <bsvc:Include_Personal_Information>1</bsvc:Include_Personal_Information>
                <bsvc:Include_Reference>1</bsvc:Include_Reference>
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
                <bsvc:Include_Personal_Information>1</bsvc:Include_Personal_Information>
                <bsvc:Include_Reference>1</bsvc:Include_Reference>
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
    workers_data = raw_json_response.get('Envelope', {}).get('Body', {}).get('Get_Workers_Response', {}). \
        get('Response_Data', {}).get('Worker')
    return raw_json_response, workers_data


def create_worker_context(workers, num_of_managers):
    workers = workers if isinstance(workers, list) else [workers]
    workers_context = []

    for worker in workers:
        worker = worker.get('Worker_Data')

        # Common Paths for fields
        name_detail_data_path = worker.get('Personal_Data', {}).get('Name_Data', {}).get('Legal_Name_Data', {}). \
            get('Name_Detail_Data')
        position_data_path = worker.get('Employment_Data', {}).get('Worker_Job_Data', {}).get('Position_Data', {})
        worker_status_data = worker.get('Employment_Data', {}).get('Worker_Status_Data', {})
        business_site_address_data = position_data_path.get('Business_Site_Summary_Data', {}).get('Address_Data', {})
        if isinstance(business_site_address_data, list):
            business_site_address_data = business_site_address_data[-1]

        worker_context = {
            "Worker_ID": worker.get('Worker_ID'),
            "User_ID": worker.get('User_ID'),
            "Country": name_detail_data_path.get('Country_Reference')['ID'][1]['#text'],
            "Legal_First_Name": name_detail_data_path.get('First_Name'),
            "Legal_Last_Name": name_detail_data_path.get('Last_Name'),
            "Preferred_First_Name": name_detail_data_path.get('First_Name'),
            "Preferred_Last_Name": name_detail_data_path.get('Last_Name'),
            "Has_International_Assignment": worker.get('Employment_Data', {}).get(
                'International_Assignment_Summary_Data', {}).get('Has_International_Assignment'),
            "Home_Country_Reference":
                worker.get('Employment_Data', {}).get('International_Assignment_Summary_Data', {}).get(
                    'Home_Country_Reference', {})['ID'][1]['#text'] if worker.get('Employment_Data', {}).get(
                    'International_Assignment_Summary_Data', {}).get('Home_Country_Reference') else None,
            "Photo": worker.get('Photo_Data', {}).get('Image')}

        if position_data_path:
            position_context = {
                "Position_ID": position_data_path.get('Position_ID'),
                "Position_Title": position_data_path.get('Position_Title'),
                "Business_Title": position_data_path.get('Business_Title'),
                "Start_Date": position_data_path.get('Start_Date'),
                "End_Employment_Reason_Reference": position_data_path['End_Employment_Reason_Reference']['ID'][1][
                    '#text']
                if position_data_path.get('End_Employment_Reason_Reference') else "",
                "Worker_Type": position_data_path['Worker_Type_Reference']['ID'][1]['#text'],
                "Position_Time_Type": position_data_path['Position_Time_Type_Reference']['ID'][1]['#text'],
                "Scheduled_Weekly_Hours": position_data_path.get('Scheduled_Weekly_Hours'),
                "Default_Weekly_Hours": position_data_path.get('Default_Weekly_Hours'),
                "Full_Time_Equivalent_Percentage": position_data_path.get('Full_Time_Equivalent_Percentage'),
                "Exclude_from_Headcount": position_data_path.get('Exclude_from_Headcount'),
                "Pay_Rate_Type": position_data_path['Pay_Rate_Type_Reference']['ID'][1]['#text']
                if position_data_path.get('Pay_Rate_Type_Reference') else "",
                "Job_Profile_Name": position_data_path.get('Job_Profile_Summary_Data', {}).get('Job_Profile_Name'),
                "Work_Shift_Required": position_data_path.get('Job_Profile_Summary_Data', {}).get(
                    'Work_Shift_Required'),
                "Critical_Job": position_data_path.get('Job_Profile_Summary_Data', {}).get('Critical_Job'),
                "Business_Site_id":
                    position_data_path.get('Business_Site_Summary_Data', {}).get('Location_Reference', {}).get('ID')[1][
                        '#text'],
                "Business_Site_Name": position_data_path.get('Business_Site_Summary_Data', {}).get('Name'),
                "Business_Site_Type": position_data_path.get('Business_Site_Summary_Data', {}).
                    get('Location_Type_Reference').get('ID')[1]['#text'],
                "Business_Site_Address": {
                    "Address_ID": business_site_address_data.get('Address_ID'),
                    "Formatted_Address": business_site_address_data.get("@{urn:com.workday/bsvc}Formatted_Address"),
                    "Country": business_site_address_data.get('Country_Reference', {}).get('ID')[1]['#text'],
                    "Postal_Code": business_site_address_data.get('Postal_Code'),
                },
                "End_Date": position_data_path.get('End_Date'),
                "Pay_Through_Date": position_data_path.get('Pay_Through_Date'),
            }
            worker_context.update(position_context)
        if worker_status_data:
            status_data_context = {
                "Active": bool(int(worker_status_data.get('Active'))) if worker_status_data.get('Active') else None,
                "Hire_Date": worker_status_data.get('Hire_Date'),
                "Hire_Reason": worker_status_data.get('Hire_Reason_Reference', {}).get('ID')[2]['#text'],
                "First_Day_of_Work": worker_status_data.get('First_Day_of_Work'),
                "Retired": worker_status_data.get('Retired'),
                # Number of days unemployed since the employee first joined the work force. Used only for China:
                "Days_Unemployed": worker_status_data.get('Days_Unemployed'),
                "Terminated": bool(int(worker_status_data.get('Terminated'))) if worker_status_data.get('Terminated')
                else None,
                "Rehire": worker_status_data.get('Rehire'),
                "Resignation_Date": worker_status_data.get('Resignation_Date')
            }
            worker_context.update(status_data_context)

        if worker_status_data.get('Terminated') == '1':
            worker_context["Termination_Date"] = worker_status_data.get("Termination_Date")
            worker_context["Primary_Termination_Reason"] = \
                worker_status_data.get('Primary_Termination_Reason_Reference', {}).get('ID')[2]['#text']
            worker_context["Primary_Termination_Category"] = \
                worker_status_data.get('Primary_Termination_Category_Reference', {}).get('ID')[1]['#text']
            worker_context["Termination_Involuntary"] = worker_status_data.get('Termination_Involuntary')
            worker_context["Termination_Last_Day_of_Work"] = worker_status_data.get('Termination_Last_Day_of_Work')

        # Addresses:
        addresses = worker.get('Personal_Data', {}).get('Contact_Data', {}).get('Address_Data')
        if not isinstance(addresses, list):
            addresses = [addresses]
        worker_context["Addresses"] = [{
            "Address_ID": address.get('Address_ID'),
            "Formatted_Address": address.get("@{urn:com.workday/bsvc}Formatted_Address"),
            "Country": address['Country_Reference']['ID'][1]['#text'] if address.get('Country_Reference') else "",
            "Region": address['Country_Region_Reference']['ID'][2]['#text']
            if address.get('Country_Region_Reference') else "",
            "Region_Descriptor": address.get('Country_Region_Descriptor', ""),
            "Postal_Code": address.get('Postal_Code'),
            "Type": address['Usage_Data']['Type_Data']['Type_Reference']['ID'][1]['#text']
            if address.get('Usage_Data') else "",
        } for address in addresses]

        # Emails:
        emails = worker.get('Personal_Data', {}).get('Contact_Data', {}).get('Email_Address_Data')
        if emails:
            if not isinstance(emails, list):
                emails = [emails]
            worker_context["Emails"] = [{
                "Email_Address": email.get('Email_Address'),
                "Type": email.get('Usage_Data', {}).get('Type_Data', {}).get('Type_Reference')['ID'][1]['#text']
                if email['Usage_Data'] else "",
                "Primary": bool(int(email.get('Usage_Data', {}).get('Type_Data', {}).get
                                    ("@{urn:com.workday/bsvc}Primary"))),
                "Public": bool(int(email.get('Usage_Data', {}).get("@{urn:com.workday/bsvc}Public"))),
            } for email in emails]

        # Phones:
        phones = worker.get('Personal_Data', {}).get('Contact_Data', {}).get('Phone_Data')
        if phones:
            if not isinstance(phones, list):
                phones = [phones]
            worker_context["Phones"] = [{
                "ID": phone.get('ID'),
                "Phone_Number": phone.get('@{urn:com.workday/bsvc}E164_Formatted_Phone'),
                "Type": phone.get('Phone_Device_Type_Reference', {})['ID'][1]['#text'],
                "Usage": phone.get('Usage_Data', {}).get('Type_Data', {}).get('Type_Reference', {})['ID'][1]['#text'],
            } for phone in phones]

        # Managers:
        managers = worker.get("Management_Chain_Data", {}).get("Worker_Supervisory_Management_Chain_Data", {}).get(
            "Management_Chain_Data")
        if managers:
            if not isinstance(managers, list):
                managers = [managers]
            # Taking the n'th managers from the end of the list(descending from top level manager(ceo))
            worker_context["Managers"] = [{
                "Manager_ID": manager.get('Manager', {}).get('Worker_Reference', {})['ID'][1]['#text'],
                "Manager_Name": manager.get('Manager', {}).get('Worker_Descriptor'),
            } for manager in managers[-num_of_managers:]]

        workers_context.append(worker_context)

    return workers_context


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, tenant_url, verify_certificate, proxy, tenant_name, token, username, password):
        headers = {"content-type": "text/xml;charset=UTF-8"}
        super().__init__(base_url=tenant_url, verify=verify_certificate, proxy=proxy, headers=headers)
        self.tenant_name = tenant_name
        self.token = token
        self.username = username
        self.password = password

    def list_workers(self, page, count, employee_id=None) -> Tuple:
        if employee_id:
            body = GET_EMPLOYEE_BY_ID.format(
                token=self.token, username=self.username, password=self.password, api_version=API_VERSION,
                employee_id=employee_id)
        else:
            body = GET_EMPLOYEES_REQ.format(
                token=self.token, username=self.username, password=self.password, api_version=API_VERSION, page=page,
                count=count)
        raw_response = self._http_request(method="POST", url_suffix="", data=body, resp_type='text', timeout=120)
        return convert_to_json(raw_response)


def test_module(client: Client, args: Dict) -> str:
    try:
        client.list_workers(page='1', count='1')
    except Exception as e:
        raise DemistoException(
            f"Test failed. Please check your parameters. \n {e}")
    return 'ok'


def list_workers_command(client: Client, args: dict) -> CommandResults:
    count = int(args.get('count', '1'))
    page = int(args.get('page', '1'))
    num_of_managers = int(args.get('managers', '3'))
    employee_id = args.get('employee_id')
    raw_json_response, workers_data = client.list_workers(page, count, employee_id)
    workers_context = create_worker_context(workers_data, num_of_managers)
    workers_readable = tableToMarkdown('Workers', workers_context, removeNull=True, headers=HEADERS)

    return CommandResults(
        readable_output=workers_readable,
        outputs_prefix='Workday.Worker',
        outputs_key_field='Worker_ID',
        outputs=workers_context,
        raw_response=raw_json_response)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    user: str = params.get('credentials', {}).get('identifier')
    base_url: str = params.get('base_url', "").rstrip('/')
    tenant_name: str = params.get('tenant_name')
    username = f"{user}@{tenant_name}"
    password: str = params.get('credentials', {}).get('password')
    token = params.get('token')
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    tenant_url = f"{base_url}/{tenant_name}/Staffing/"

    commands = {
        "test-module": test_module,
        "workday-list-workers": list_workers_command,
    }

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client = Client(tenant_url=tenant_url, verify_certificate=verify_certificate, proxy=proxy,
                        tenant_name=tenant_name, token=token, username=username, password=password)

        if command in commands:
            return_results(commands[command](client, demisto.args()))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
