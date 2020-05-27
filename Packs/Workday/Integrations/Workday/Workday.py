from typing import Dict, Tuple, List
import demistomock as demisto
from CommonServerPython import *

# IMPORTS
# Disable insecure warnings

requests.packages.urllib3.disable_warnings()

# TODO: remove before pr:


# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = "v34.0"

WORKER = {

}


# TODO: NOTICE THE COMMENT ON PAGINATION:
#  The numbered page of data Workday returns in the response. The default page is the first page(Page = 1).
#  For responses that contain more than one page of data, use this parameter to retrieve the additional pages of data.
#  For example, set Page = 2 to retrieve the second page of data. Note: If you set the page parameter, you must also
#  specify the "As_Of_Entry_Date" to ensure that the result set remains the same between your requests.
def convert_to_json(response):
    raw_json_response = json.loads(xml2json(response))
    workers_data = raw_json_response['Envelope']['Body']['Get_Workers_Response']['Response_Data']['Worker']
    return raw_json_response, workers_data


def create_worker_context(workers: List[dict]):
    pass

    #
    # raw_workers = workers if isinstance(workers, list) else [workers]
    # workers = []
    # for worker in raw_workers:
    #     worker_data = worker.get('Worker_Data')
    #     employment_data = worker.get('Worker_Data').get('Employment_Data')
    #     personal_data = worker.get('Worker_Data').get('Personal_Data')
    #     workers.append(worker_data.get('User_ID'))

    # return workers


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

    # TODO: take care of employee id and page params
    def create_soap_request(self, employee_id, page, count) -> str:
        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:bsvc="urn:com
.workday/bsvc"> 
       <soapenv:Header>
          <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401
-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility
-1.0.xsd"> 
             <wsse:UsernameToken wsu:Id="UsernameToken-{self.token}">
                <wsse:Username>{self.username}</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1
.0#PasswordText">{self.password}</wsse:Password> 
             </wsse:UsernameToken>
          </wsse:Security>
       </soapenv:Header>
<soapenv:Body>
      <bsvc:Get_Workers_Request bsvc:version="{API_VERSION}">
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
        return body

    # TODO: fill request according to params
    def list_workers(self, employee_id, page, count) -> Tuple:
        body = self.create_soap_request("employee_id", page, count)
        raw_response = self._http_request(method="POST", url_suffix="", data=body, resp_type='text')
        return convert_to_json(raw_response)


def list_workers_command(client: Client, args: Dict) -> CommandResults:
    count = int(args.get('count'))
    page = int(args.get('page'))
    raw_json_response, workers_data = client.list_workers("d", page, count)
    # workers_context = create_worker_context(workers_data)
    # workers_readable = f"### User:{workers_context.get('User_ID')}\n {tableToMarkdown('Worker', worker_data)}"
    result = CommandResults(
        # readable_output=workers_readable,
        readable_output="",
        outputs_prefix='Workday',
        outputs_key_field='Worker',
        outputs=workers_data
    )
    return result


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params: dict = demisto.params()
    user: str = params.get('username')
    base_url: str = params.get('base_url').rstrip('/')
    tenant_name: str = params.get('tenant_name')
    username = f"{user}@{tenant_name}"
    password: str = params.get('password')
    token = params.get('token')
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    tenant_url = f"{base_url}/{tenant_name}/Staffing/"

    commands = {
        # "test-module": test_module,
        "workday-list-workers": list_workers_command
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
