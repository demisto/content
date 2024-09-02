import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


""" IMPORTS """
# Std imports
import os
from datetime import datetime

# 3-rd party imports
import urllib3
import base64
import hashlib
from xml.etree import ElementTree
import re
"""

GLOBALS/PARAMS

Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""


INTEGRATION_NAME = 'Signum'
INTEGRATION_COMMAND_NAME = 'signum'
INTEGRATION_CONTEXT_NAME = 'Signum'
# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def test_module(self, username: str, password: str) -> dict:
        """
            Performs basic request to check if the API is reachable and authentication is successful.
        Returns:
            Response dictionary
        """
        return self.list_domain_users(domain_id=1, username=username, password=password)

    def list_domain_users(self, domain_id: int, username: str, password: str) -> dict:
        """
            List domain users by domain_id.
        Args:
            self
            domain_id: Domain Identification number
            username: username
            password: password
        NOTE: The username and password are requested to be provided in the SOAP Header
        Returns:
            Response dictionary
        """
        # SOAP request URL
        nonce = os.urandom(16)
        created = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        digest = base64.b64encode(
            hashlib.sha1(nonce + bytes(created, 'utf-8') + bytes(password, 'utf-8')).digest()
        ).decode("ascii")
        userToken = f'UsernameToken-{digest}'

        # structured XML
        soapHeader = (
            f'<soap:Header xmlns:wsa="http://www.w3.org/2005/08/addressing">'
            f'<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"'
            f' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
            f'<wsse:UsernameToken wsu:Id="{userToken}"> '
            f'<wsse:Username>{username}</wsse:Username>'
            f'<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0'
            f'#PasswordText">{password}</wsse:Password>'
            f'<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0'
            f'#Base64Binary">{str(nonce)}</wsse:Nonce>'
            f'<wsu:Created>{created}</wsu:Created>'
            f'</wsse:UsernameToken>'
            f'</wsse:Security><wsa:Action>urn:evolium:redtrust:administration:ws/RTAdminService/ListDomainUsers</wsa:Action>'
            f'<wsa:To>'
            f'https://signum.fis.us.app.az.keyfactorsaas.com/RTAdminService.svc/basic</wsa:To>'
            f'</soap:Header>'
        )
        payload = (
            f'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:urn="urn:evolium:redtrust:'
            f'administration:ws">'
            f'    {soapHeader}'
            f'    <soap:Body>'
            f'        <urn:ListDomainUsers>'
            f'            <!--Optional:-->'
            f'            <urn:domainId>{domain_id}</urn:domainId>'
            f'            <!--Optional:-->'
            f'            <urn:viewType>VIEW_ALL</urn:viewType>'
            f'            <!--Optional:-->'
            f'            <urn:filter></urn:filter>'
            f'            <!--Optional:-->'
            f'            <urn:numBlock>0</urn:numBlock>'
            f'            <!--Optional:-->'
            f'            <urn:orderColumn>ORDER_BY_NAME</urn:orderColumn>'
            f'            <!--Optional:-->'
            f'            <urn:orderType>ORDER_ASCENDING</urn:orderType>'
            f'        </urn:ListDomainUsers>'
            f'    </soap:Body>'
            f'</soap:Envelope>'
        )

        # headers
        headers = {
            'Content-Type': 'application/soap+xml; charset=UTF-8; '
                            'action="urn:evolium:redtrust:administration:ws/RTAdminService/ListDomainUsers"'
        }

        raw_response = self._http_request(method='POST',
                                          headers=headers,
                                          data=payload,
                                          resp_type='response')
        return raw_response


''' HELPER FUNCTIONS '''


def xml_to_dict_recursive(root, simple_view: bool = True) -> dict:
    """
        Convert XML to Dictionary
    Args:
        root: XML format data
        simple_view: if "True", strip off prefixes, such as "{urn:.*}" and "{http://.*}", from each dictionary Key name.
    Returns:
        Response dictionary
    """
    if simple_view:
        if len(list(root)) == 0:
            return {re.sub("{urn:.*}", "", re.sub("{http://.*}", "", root.tag)): root.text}
        else:
            return {re.sub("{urn:.*}", "", re.sub("{http://.*}", "", root.tag)): list(map(xml_to_dict_recursive, list(root)))}
    else:
        if len(list(root)) == 0:
            return {root.tag: root.text}
        else:
            return {root.tag: list(map(xml_to_dict_recursive, list(root)))}


def dict_find_key_recursively(d: dict, target_key: str, result=None):
    """
        Find the value of specific key in dictionary
    Args:
        d: Dictionary
        target_key: The key for which the value is being searched.
        result: result of findings
    Returns:
        any: The value associated with the target_key, if found; otherwise, None.
    """
    if result is None:
        for current_key, value in d.items():
            if current_key == target_key:
                return value
            if isinstance(value, dict):
                result = dict_find_key_recursively(value, target_key, result)
            elif isinstance(value, list):
                for item in value:
                    result = dict_find_key_recursively(item, target_key, result)
    return result


def list_domain_users_ec(raw_response, simple_view: bool = True) -> tuple[list, list, dict]:
    """
        Get users info
    Args:
        raw_response: raw_response
        simple_view: if "True", strip off prefixes, such as "{urn:.*}" and "{http://.*}", from each dictionary Key name.
    Returns:
        tuple of List of users info
    """
    entry_context = []
    human_readable = []
    if raw_response_text := raw_response.text:
        xml = re.findall("<s:Envelope.*<\/s:Envelope>", raw_response_text)[0]
        root_xml = ElementTree.fromstring(xml)
        xml_dict = xml_to_dict_recursive(root=root_xml, simple_view=simple_view)
        result = None
        if simple_view:
            result = dict_find_key_recursively(d=xml_dict, target_key="ResultData", result=result)
        else:
            result = xml_dict
        for item in result:
            user_data = {}
            for d in item.get('LU1UserView'):
                user_data.update(d)
            entry_context.append(user_data)
            human_readable.append(user_data)
        raw_response = xml_dict

    return entry_context, human_readable, raw_response


''' COMMANDS '''


@logger
def test_module_command(client: Client, username: str, password: str, *_) -> tuple[None, None, str]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        username: username
        password: password
        *_: Usually demisto.args()
    NOTE: The username and password are requested to be provided in the SOAP Header
    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module(username=username, password=password)
    if results.status_code == 200:  # type: ignore
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {results}')


@logger
def list_domain_users_command(client: Client,
                              domain_id: int,
                              username: str,
                              password: str,
                              simple_view: bool = True) -> tuple[str, dict, Union[list, dict]]:
    """
        List Domain Users

    Args:
        client:
        domain_id: Domain Identification number
        username: username
        password: password
        simple_view: if "True", strip off prefixes, such as "{urn:.*}" and "{http://.*}", from each dictionary Key name.
    NOTE: The username and password are requested to be provided in the SOAP Header

    Returns:
        human readable (markdown format), entry context and raw response
    """

    simple_view: bool = argToBoolean(simple_view)
    raw_response: dict = client.list_domain_users(domain_id=domain_id, username=username, password=password)
    title = f'{INTEGRATION_NAME} - list domain users command'
    entry_context, human_readable_ec, raw_response = list_domain_users_ec(raw_response=raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.ListDomainUsers": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():

    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client = Client(
        base_url=params.get('url'),
        verify=verify_ssl,
        proxy=proxy,
        auth=(
            username, password
        )
    )
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-list-domain-users': list_domain_users_command,
    }
    try:
        readable_output, outputs, raw_response = commands[command](
            client=client, username=username, password=password, **demisto.args())
        results = CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=raw_response
        )
        return_results(results)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
