#register_module_line('JizoNDR', 'start', __line__())
### pack version: 1.0.0

import demistomock as demisto
from CommonServerPython import *

import json
#import requests
from typing import Any, Dict, Tuple



# Disable Secure Warnings
#requests.packages.urllib3.disable_warnings() # pylint: disable=no-member
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()


''' CLIENT CLASS '''

class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """


    def test_module(self)-> bool:
        """Check if the API is active 

        Returns:
            dict: response body of the ping endpoint
        """

        url = f"{self._base_url}/ping" 
        # Define headers
        headers = {"Content-Type": "application/json"}

        # Sending POST request to the API endpoint with the specified headers and request body
        response = requests.get(
            url, headers=headers, verify=False
        )  # Setting verify=False ignores SSL certificate verification. Be cautious about using it in a production environment.
        # Checking if the request was successful (status code 200)
        return response.status_code == 200
   

    def get_protocols(self, args:Dict[str,Any]):
        """
        Get jizo protocols. You can filter by ip_src, ip_dest. 
        You can filter also by timestamp or probe name
        """

        url = f'{self._base_url}/jizo_get_protocols'

        response = requests.get(
            url, params=args,headers=self._headers, verify=False
        )
        if response.status_code==200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)

    def get_peers(self,args:Dict[str,Any]):
        """
        Get jizo peers. You can filter by ip_src, ip_dest. 
        You can filter also by timestamp or probe name or probe Ip

        """
        
        url = f'{self._base_url}/jizo_get_peers'

        response = requests.get(
            url, params=args,headers=self._headers, verify=False
        )
        if response.status_code==200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)



    def get_query_records(self,args:Dict[str,Any]):
        """
        Get jizo query records. You can filter by ip_src, proto, port_src, FlowId, Sid.
        You can filter also by timestamp or probe name

        """
        url = f'{self._base_url}/jizo_query_records'

        response = requests.get(
            url, params=args,headers=self._headers, verify=False
        )
        if response.status_code==200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)
        
        
    def get_alert_rules(self, args:Dict[str,Any]):
        """
        Get jizo alert rules

        """
        url = f'{self._base_url}/jizo_get_alert_rules'

        response = requests.get(
            url, params=args,headers=self._headers, verify=False
        )
        if response.status_code==200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)
        

    def get_device_records(self,args:Dict[str,Any]):
        """
        Get jizo device records. You can filter by ip_src, mac, hostname.
        One of this params is mandatory. You can filter also by timestamp or probe name

        """
        url = f'{self._base_url}/jizo_device_records'

        response = requests.get(
            url, params=args,headers=self._headers, verify=False
        )
        if response.status_code==200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)

    def get_device_alerts(self,args:Dict[str,Any]):
        """
        Get jizo device alerts. You can filter by ip_src, ip_dest.
        One of this params is mandatory. You can filter also by timestamp or probe name

        """
        url = f'{self._base_url}/jizo_get_devicealerts'

        response = requests.get(
            url, params=args,headers=self._headers, verify=False
        )
        if response.status_code==200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)


''' COMMAND FUNCTIONS '''

def test_module( client: Client)->str:
    if client.test_module():
        return "ok"
    else:
        return "Request error, please check your API"


def get_token(client: Client):

    try:
        url = f"{client._base_url}/login"

        # Include username and password as JSON in the request body
        data = {
            "username": client._auth[0],
            "password": client._auth[1],
        }

        # Define headers
        headers = {"Content-Type": "application/json"}

        # Sending POST request to the API endpoint with the specified headers and request body
        response = requests.post(
            url, headers=headers, json=data, verify=False
        )  # Setting verify=False ignores SSL certificate verification. Be cautious about using it in a production environment.
        # Checking if the request was successful (status code 200)
        if response.status_code == 200:
            return response.json()
        else:
            return_error(f"Error: {response.status_code} - Authentification failed, please try again with propriate credentials ")


    except Exception as e:
        return_error(f"An error occurred: {e}")


def get_protocols_command(client: Client,args:Dict[str,Any]) -> CommandResults:
    """
    Returns response of jizo_get_protocols endpoint

    Args:
        client (Client): JizoM client to use.

    Returns:
        CommandResults: A ``CommandResults`` object that will be then passed to ``return_results``
    """

    # Call the Client function and get the raw response
    result = client.get_protocols(args)

    return CommandResults(
        readable_output=tableToMarkdown(name="Jizo Protocols", t=result),
        outputs_prefix='JizoM.Protocols',
        outputs=result,
        replace_existing=True,

    )

def get_peers_command(client: Client, args:Dict[str,Any]) -> CommandResults:

    # Call the Client function and get the raw response
    result = client.get_peers(args)

    return CommandResults(
        readable_output=tableToMarkdown(name="Jizo Peers", t=result),
        outputs_prefix='JizoM.Peers',
        outputs_key_field='',
        outputs=result,

    )

def get_query_records_command(client: Client, args:Dict[str,Any]) -> CommandResults:

    # Call the Client function and get the raw response
    result = client.get_query_records(args)

    return CommandResults(
        readable_output=tableToMarkdown(name="Jizo Query Records", t=result),
        outputs_prefix='JizoM.QueryRecords',
        outputs_key_field='',
        outputs=result,

    )

def get_alert_rules_command(client: Client,args:Dict[str,Any]) -> CommandResults:

    # Call the Client function and get the raw response
    result = client.get_alert_rules(args)
    
    return CommandResults(
        readable_output=tableToMarkdown(name="Jizo Alert Rules", t=result),
        outputs_prefix='JizoM.AlertRules',
        outputs_key_field='',
        outputs=result,

    )

def get_device_records_command(client: Client, args:Dict[str,Any]) -> CommandResults:

    # Call the Client function and get the raw response
    result= client.get_device_records(args)

    return CommandResults(
        readable_output=tableToMarkdown(name="Jizo Device Records", t=result),
        outputs_prefix='JizoM.Device.Records',
        outputs_key_field='',
        outputs=result,

    )

def get_device_alerts_command(client: Client,args:Dict[str,Any]) -> CommandResults:

    # Call the Client function and get the raw response
    result = client.get_device_alerts(args)
  
    return CommandResults(
        readable_output=tableToMarkdown(name="Jizo Device Alerts", t=result),
        outputs_prefix='JizoM.Device.Alerts',
        outputs_key_field='',
        outputs=result,

    )


''' MAIN FUNCTION '''

def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get the service API url
    base_url = params.get('url')

    # If your Client class inherits from BaseClient, SSL verification is handled out-of-the-box by it.
    # Just pass ``verify_certificate`` to the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)
    headers={
            "Content-Type": "application/json",
        }
    username = demisto.params().get('credentials', {}).get('identifier')
    password = demisto.params().get('credentials', {}).get('password')
    demisto.debug(f'Command being called is {command}')
    try:

        client = Client(
            base_url=base_url,
            auth=(username, password),
            headers=headers,
            verify=verify_certificate,
            proxy=proxy)

        # get token
        connect = get_token(client)
        token = connect["token"]
        # add token to headers
        client._headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'get-protocols':
            return_results(get_protocols_command(client,args))

        elif command == 'get-peers':
            return_results(get_peers_command(client,args))

        elif command == 'get-query-records':
            return_results(get_query_records_command(client,args))

        elif command == 'get-alert-rules':
            return_results(get_alert_rules_command(client,args))

        elif command == 'get-device-records':
            return_results(get_device_records_command(client,args))

        elif command == 'get-device-alerts':
            return_results(get_device_alerts_command(client,args))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

#register_module_line('JizoNDR', 'end', __line__())

