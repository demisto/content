"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import json
import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}
    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API

    # test function
    def get_alert(self, alert_id: str) -> Dict[str, Any]:

        # return self._http_request(
        #     method='GET',
        #     url_suffix='http://www.randomnumberapi.com/api/v1.0/random',
        #     params={
        #         min:100,
        #         max:1000,
        #         "count":5,
        #     }
        # )
        return {"alert_id": alert_id}

    def get_ip(self,ip: str,params: Dict[str, str],) -> Dict[str, Any]:
        global_username=params.get('username')
        global_password =params.get('password')
        global_usrn=params.get('usrn')
        global_client_id=params.get('clientid')
        body={'usrn':global_usrn,'clientID':global_client_id,'limit':2}
        res = self._http_request('POST',
                                 url_suffix='',
                                 full_url="https://api.nucleoncyber.com/feed/activethreats",
                                 auth=(global_username,global_password),
                                  data=body,
                                 resp_type='text',
                                 )
        json_payload=json.loads(res)
        result =[]
        all_data= json_payload.get("data")
        for data in all_data:
            result.append(
                {
                    'value':data.get("ip"),
                    # "type":"IP",
                    # "reputation":"Bad",
                    
                }
            )

        # return {"ip": "1.1.1.1","exp":"1621336358","attackDetails":{"remote":{"uptime":0,"os":False,"osVersion":False,"lang":False},"timeStamp":1620998271.6226,"maliciousURL":["http:\/\/88.218.17.142\/x86_64|2021-05-13","http:\/\/51.75.170.84\/installer.sh|2021-05-13","http:\/\/bestony.club\/poll\/db09fb86-b82e-4d9c-b80d-c8ac7672a24e|2021-05-13","http:\/\/104.248.142.228\/yoyobins.sh|2021-05-13","http:\/\/71.127.148.69\/.x\/2sh|2021-05-13","http:\/\/71.127.148.69\/.x\/3sh|2021-05-13","http:\/\/bestony.club\/poll\/b7147ce7-0e80-4a7b-b7cf-31dc65214a3c|2021-05-14","http:\/\/209.141.43.118\/sh|2021-05-14","http:\/\/bestony.club\/poll\/bf49652e-5caf-4d8a-92cd-f524e2587e76|2021-05-14","https:\/\/raw.githubusercontent.com\/C3Pool\/xmrig_setup\/master\/setup_c3pool_miner.sh|2021-05-14","http:\/\/strtbiz.site\/poll\/cf710a07-959d-4b25-9f2c-be1f29526c17|2021-05-14","http:\/\/sh.haxibao.cn\/becardmore.sh|2021-05-14","http:\/\/88.218.17.142\/x86_64|2021-05-14","http:\/\/sh.haxibao.cn\/workmore.sh|2021-05-14","libc.so","http:\/\/104.248.142.228\/yoyobins.sh|2021-05-14","http:\/\/myfrance.xyz\/poll\/915f8ba8-0a0e-4943-a24e-21cd09b00434|2021-05-14","http:\/\/107.175.194.108\/sh|2021-05-14"],"targetCountry":"global","segment":None,"data":{"message":"Connectionlost after 2 seconds","timestamp":1620998271.6226},"attackMeta":{"governments":False,"darknet":False,"bot":False,"cnc":False,"proxy":False,"port":0,"sourceCountry":"VN","automated":False,"bruteForce":False}}}
        # return {"ip":"1.1.1.1","attackDetails":json_payload.get("data")[0].get("attackDetails").get("remote")}
        return {"ip":"1.1.1.1","attackDetails":result}

    # def get_ips(self) -> List:
    #     global_username="ext6dev"
    #     global_password ="G5ty812QQ3"
    #     global_usrn="moranz"
    #     global_client_id="abc123AZ-1234-nucnuc"
    #     body={'usrn':global_usrn,'clientID':global_client_id,'limit':4}
    #     result = []
    #     res = self._http_request('POST',
    #                              url_suffix='',
    #                              full_url="https://api.nucleoncyber.com/feed/activethreats",
    #                              auth=(global_username,global_password),
    #                               data=body,
    #                              resp_type='text',
    #                              )
    #     json_payload=json.loads(res)
    #     all_data= json_payload.get("data")
    #     for data in all_data:
    #         result.append(
    #             {
    #                 'value':data.get("ip"),
    #                 "type":"ip",
    #             }
    #         )

    #     return result

       
''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
        # client.get_alert(alert_id='something')
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def fetch_indicators(client: Client, limit: int = -1) \
        -> List[Dict]:
    indicators = []
    iterator =client.get_ips()

    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value_,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})
        indicator_obj = {
            # The indicator value.
            'value': value_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            'type': type_,
            # The name of the service supplying this feed.
            'service': 'HelloWorldTry',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {},
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data
        }

        indicators.append(indicator_obj)

    return indicators    



def get_indicators_command(client: Client,
                           params: Dict[str, str],
                           args: Dict[str, str]
                           ) -> CommandResults:

    limit = int(args.get('limit', '10'))
    indicators = fetch_indicators(client,limit)
    

    
    human_readable = tableToMarkdown('Indicators from HelloWorldTry Feed:', indicators,
                                     headers=['value', 'type'], headerTransform=string_to_table_header, removeNull=True)
    
    demisto.info(f"human_readable: {human_readable}")
    
    return CommandResults(
        # outputs_prefix='HelloWorldTry.Indicators',
        # outputs_key_field='value',
        # # raw_response=indicators,
        # outputs=indicators,
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},

    )

def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    # limit = int(args.get('limit', '10'))
    limit =1
    indicators = fetch_indicators(client,limit)
    return indicators

# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


def get_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get('alert_id', None)
    if not alert_id:
        raise ValueError('alert_id not specified')

    alert = client.get_alert(alert_id)
    return CommandResults(
        outputs_prefix='HelloWorldTry.Alert',
        outputs_key_field='alert_id', # in Xsoar it helps to update exist instead of adding new
        outputs=alert,
    )

def get_ip_command(client: Client,params: Dict[str, str], args: Dict[str, Any]) -> CommandResults:
    ip = args.get('ip', None)
    if not ip:
        raise ValueError('ip not specified')

    res = client.get_ip(ip,params)
    return CommandResults(
        outputs_prefix='HelloWorldTry.Ip',
        outputs_key_field='ip', # in Xsoar it helps to update exist instead of adding new
        outputs=res,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('apikey')
    params = demisto.params()
    args = demisto.args()

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')
    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)
    

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement
        elif demisto.command() == 'HelloWorldTry-get-alert':
            return_results(get_alert_command(client, demisto.args()))
        elif demisto.command() == 'HelloWorldTry-get-ip':
            return_results(get_ip_command(client,params, demisto.args()))
        # elif demisto.command == 'helloworldTry-get-indicators':
        #     return_results(get_indicators_command(client, demisto.args()))
        # elif demisto.command == 'fetch-indicators':
        #     indicators = fetch_indicators_command(client, params)
        #     for iter_ in batch(indicators, batch_size=2000):
        #         demisto.createIndicators(iter_)


    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
