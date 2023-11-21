import random
import string

from gevent.pywsgi import WSGIServer
from flask import Flask, request, Response
from CommonServerPython import *

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
APP: Flask = Flask('xsoar-workday-signon')
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

SIGNON_ITEM_TEMPLATE = """
                <wd:Workday_Account_Signon>
                    <wd:Signon_DateTime>{signon_datetime}</wd:Signon_DateTime>
                    <wd:User_Name>{user_name}</wd:User_Name>
                    <wd:Successful>1</wd:Successful>
                    <wd:Failed_Signon>0</wd:Failed_Signon>
                    <wd:Invalid_Credentials>0</wd:Invalid_Credentials>
                    <wd:Password_Changed>0</wd:Password_Changed>
                    <wd:Forgotten_Password_Reset_Request>0</wd:Forgotten_Password_Reset_Request>
                    <wd:Signon_IP_Address>Workday Internal</wd:Signon_IP_Address>
                    <wd:Authentication_Channel>Web Services</wd:Authentication_Channel>
                    <wd:Authentication_Type>Trusted</wd:Authentication_Type>
                    <wd:Workday_Account_Reference>
                        <wd:ID wd:type="WID">dc28d59c523f1010e415d814cbd50002</wd:ID>
                        <wd:ID wd:type="System_User_ID">12345678</wd:ID>
                        <wd:ID wd:type="WorkdayUserName">{user_name}</wd:ID>
                    </wd:Workday_Account_Reference>
                    <wd:System_Account_Signon_Reference>
                        <wd:ID wd:type="IID">4328$170406698</wd:ID>
                    </wd:System_Account_Signon_Reference>
                    <wd:Request_Originator_Reference>
                        <wd:ID wd:type="WID">02f60ab5ed5744c0afbc9cc5096d7a73</wd:ID>
                    </wd:Request_Originator_Reference>
                    <wd:Invalid_for_Authentication_Channel>0</wd:Invalid_for_Authentication_Channel>
                    <wd:Invalid_for_Authentication_Policy>0</wd:Invalid_for_Authentication_Policy>
                    <wd:Required_Password_Change>0</wd:Required_Password_Change>
                    <wd:Account_Disabled_or_Expired>0</wd:Account_Disabled_or_Expired>
                    <wd:MFA_Authentication_Exempt>0</wd:MFA_Authentication_Exempt>
                    <wd:Has_Grace_Period_for_MFA>0</wd:Has_Grace_Period_for_MFA>
                    <wd:MFA_Enrollment>0</wd:MFA_Enrollment>
                    <wd:Short_Session_ID>{short_session_id}</wd:Short_Session_ID>
                    <wd:Device_is_Trusted>0</wd:Device_is_Trusted>
                    <wd:Tenant_Access_Read_Only>0</wd:Tenant_Access_Read_Only>
                </wd:Workday_Account_Signon>
    """


def generate_xml_template(from_date: str, to_date: str, count: int, total_responses: int):
    return f"""
<env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
    <env:Body>
        <wd:Get_Workday_Account_Signons_Response xmlns:wd="urn:com.workday/bsvc" wd:version="v37.0">
            <wd:Request_Criteria>
                <wd:From_DateTime>{from_date}</wd:From_DateTime>
                <wd:To_DateTime>{to_date}</wd:To_DateTime>
            </wd:Request_Criteria>
            <wd:Response_Filter>
                <wd:As_Of_Entry_DateTime>{from_date}</wd:As_Of_Entry_DateTime>
                <wd:Page>1</wd:Page>
                <wd:Count>{count}</wd:Count>
            </wd:Response_Filter>
            <wd:Response_Results>
                <wd:Total_Results>{total_responses}</wd:Total_Results>
                <wd:Total_Pages>1</wd:Total_Pages>
                <wd:Page_Results>{total_responses}</wd:Page_Results>
                <wd:Page>1</wd:Page>
            </wd:Response_Results>
            <wd:Response_Data>
                %%workday_account_signon_items%%
            </wd:Response_Data>
        </wd:Get_Workday_Account_Signons_Response>
    </env:Body>
</env:Envelope>
"""


def random_datetime_in_range(start_str: str, end_str: str):
    start_datetime = datetime.strptime(start_str, DATE_FORMAT)
    end_datetime = datetime.strptime(end_str, DATE_FORMAT)

    random_seconds = random.randint(0, int((end_datetime - start_datetime).total_seconds()))
    return (start_datetime + timedelta(seconds=random_seconds)).strftime(DATE_FORMAT)


def random_string(length: int = 10):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


def xml_generator(from_datetime: str, to_datetime: str, count: int):
    # Generate randomized Signon_DateTime
    random_signon_datetime = random_datetime_in_range(from_datetime, to_datetime)

    # Determine the number of Workday_Account_Signon items
    num_signon_items = random.randint(1, count)

    template = generate_xml_template(from_date=from_datetime, to_date=to_datetime, total_responses=num_signon_items,
                                     count=num_signon_items)

    # Generate Workday_Account_Signon items
    signon_items = []
    for _ in range(num_signon_items):
        signon_item = SIGNON_ITEM_TEMPLATE.format(
            signon_datetime=random_signon_datetime,
            user_name=random_string(),
            short_session_id=random_string(length=6)
        )
        signon_items.append(signon_item)

    # Insert the generated items into the main template
    populated_template = template.replace("%%workday_account_signon_items%%", "\n".join(signon_items))

    return populated_template


@APP.route('/', methods=['POST'])
def mock_workday_endpoint():
    request_text = request.get_data(as_text=True)
    demisto.info(f"{request_text}")

    # Define regex patterns
    from_datetime_pattern = r'<bsvc:From_DateTime>(.*?)</bsvc:From_DateTime>'
    to_datetime_pattern = r'<bsvc:To_DateTime>(.*?)</bsvc:To_DateTime>'
    count_pattern = r'<bsvc:Count>(\d+)</bsvc:Count>'

    # Extract values using regex
    from_datetime_match = re.search(from_datetime_pattern, request_text)
    from_datetime = from_datetime_match.group(1) if from_datetime_match else "2023-08-23T18:20:03Z"

    to_datetime_match = re.search(to_datetime_pattern, request_text)
    to_datetime = to_datetime_match.group(1) if to_datetime_match else "2023-08-23T18:20:08Z"

    count_match = re.search(count_pattern, request_text)
    count = int(count_match.group(1)) if count_match else 1

    # Use the extracted values to generate the response XML
    response_xml = xml_generator(from_datetime, to_datetime, count)

    # Return the generated XML
    return Response(response_xml, mimetype='text/xml')


def module_of_testing(is_longrunning: bool, longrunning_port: int):
    if longrunning_port and is_longrunning:
        xml_response = xml_generator('2023-08-21T11:46:02Z', '2023-08-21T11:47:02Z', 2)
        if xml_response:
            return_results('ok')
        else:
            raise DemistoException('Could not connect to the long running server. Please make sure everything is '
                                   'configured.')
    else:
        raise DemistoException('Please make sure the long running port is filled and the long running checkbox is '
                               'marked.')


''' MAIN FUNCTION '''


def main():
    command = demisto.command()
    params = demisto.params()
    port = int(params.get('longRunningPort', '5000'))
    is_longrunning = params.get("longRunning")
    try:
        if command == 'test-module':
            module_of_testing(longrunning_port=port, is_longrunning=is_longrunning)
        elif command == 'long-running-execution':
            while True:
                server = WSGIServer(('0.0.0.0', port), APP)
                server.serve_forever()
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
