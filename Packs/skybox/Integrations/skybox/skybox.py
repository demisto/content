"""HelloWorld Integration for Cortex XSOAR (aka Demisto)

This integration is a good example on you can build a Cortex XSOAR Integration
using Python 3. Please follow the documentation links below and make sure that
your integration follows the Code Conventions and passes the Linting phase.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

When building a Cortex XSOAR integration that is reusable, a lot of effort
must be placed in the design. We recommend to fill a Design Document template,
that allows you to capture Use Cases, Requirements and Inputs/Outputs.

Example Design document for the this Integration (HelloWorld):
https://docs.google.com/document/d/1wETtBEKg37PHNU8tYeB56M1LE314ux086z3HFeF_cX0


HelloWorld API
--------------

The HelloWorld API is a simple API that shows a realistic use case for an XSOAR
integration. It's actually a real API that is available to the following URL:
- if you need an API Key to test it out please
reach out to your Cortex XSOAR contacts.

This API has a few basic functions:
- Alerts: the endpoint returns mocked alerts and allows you to search based on
a number of parameters, such as state (ACTIVE or CLOSED), type, timestamp. It
can also return a single alert by ID. This is used to create new Incidents in
XSOAR by using the ``fetch-incidents`` command, which is by default invoked
every minute.
There is also an endpoint that allows to retrieve additional details about a
specific alert by ID, and one to change the alert status to "CLOSED" once
it has been resolved.

- Reputation (ip and domain): these endpoints return, for an IP and
domain respectively, a WHOIS lookup of the entity as well as a reputation score
(from 0 to 100) that is used to determine whether the entity is malicious. This
endpoint is called by XSOAR reputation commands ``ip`` and ``domain`` that
are run automatically every time an indicator is extracted in XSOAR. As a best
practice of design, it is important to map and document the mapping between
a score in the original API format (0 to 100 in this case) to a score in XSOAR
format (0 to 3). This score is called ``DBotScore``, and is returned in the
context to allow automated handling of indicators based on their reputation.
More information: https://xsoar.pan.dev/docs/integrations/dbot


- Scan: to demonstrate how to run commands that are not returning instant data,
the API provides a scan endpoint that simulates scanning a host and generating
a report after the scan is completed. The API has endpoints to start a scan,
which returns a job ID, poll for the scan status and, if the scan is completed,
retrieved the job results.
This function is used in conjunction of the HelloWorld Scan playbook that uses
the GenericPolling mechanism to implement the job polling loop. The results
can be returned in JSON or attachment file format.
Info on GenericPolling: https://xsoar.pan.dev/docs/playbooks/generic-polling

Please check the HelloWorld Design Document referenced above for details about
the raw API responsens as well as the design details for this integration.

This integration also has a ``say-hello`` command for backward compatibility,
that doesn't connect to an API and just returns a ``Hello {name}`` string,
where name is the input value provided.


Integration File Structure
--------------------------

An integration usually consists of the following parts:
- Imports
- Constants
- Client Class
- Helper Functions
- Command Functions
- Main Function
- Entry Point


Imports
-------

Here you can import Python module you need for your integration. If you need
a module that is not part of the default XSOAR Docker images, you can add
a custom one. More details: https://xsoar.pan.dev/docs/integrations/docker

There are also internal imports that are used by XSOAR:
- demistomock (imported as demisto): allows your code to work offline for
testing. The actual ``demisto`` module is provided at runtime when the
code runs in XSOAR.
- CommonServerPython.py: contains a set of helper functions, base classes
and other useful components that will make your integration code easier
to maintain.
- CommonServerUserPython.py: includes a set of user defined commands that
are specific to an XSOAR installation. Do not use it for integrations that
are meant to be shared externally.

These imports are automatically loaded at runtime within the XSOAR script
runner, so you shouldn't modify them

Constants
---------

Usually some constants that do not require user parameters or inputs, such
as the default API entry point for your service, or the maximum numbers of
incidents to fetch every time.


Client Class
------------

We recommend to use a Client class to wrap all the code that needs to interact
with your API. Moreover, we recommend, when possible, to inherit from the
BaseClient class, defined in CommonServerPython.py. This class already handles
a lot of the work, such as system proxy settings, SSL certificate verification
and exception handling for HTTP errors.

Note that the Client class should NOT contain any Cortex XSOAR specific code,
i.e. it shouldn't use anything in the ``demisto`` class (functions such as
``demisto.args()`` or ``demisto.results()`` or even ``return_results`` and
``return_error``.
You will use the Command Functions to handle XSOAR inputs and outputs.

When calling an API, you should use the ``_http.request()`` method and you
can return the raw data to the calling function (usually a Command function).

You should usually have one function for each API endpoint.

Look at the code and the commends of this specific class to better understand
the implementation details.


Helper Functions
----------------

Helper functions are usually used as utility functions that are used by several
command functions throughout your code. For example they map arguments to types
or convert severity formats from integration-specific to XSOAR.
Many helper functions are already defined in ``CommonServerPython.py`` and are
often very handy.


Command Functions
-----------------

Command functions perform the mapping between XSOAR inputs and outputs to the
Client class functions inputs and outputs. As a best practice, they shouldn't
contain calls to ``demisto.args()``, ``demisto.results()``, ``return_error``
and ``demisto.command()`` as those should be handled through the ``main()``
function.
However, in command functions, use ``demisto`` or ``CommonServerPython.py``
artifacts, such as ``demisto.debug()`` or the ``CommandResults`` class and the
``Common.*`` classes.
Usually you will have one command function for every specific XSOAR command
you want to implement in your integration, plus ``test-module``,
``fetch-incidents`` and ``fetch-indicators``(if the latter two are supported
by your integration). Each command function should invoke one specific function
of the Client class.

Command functions, when invoked through an XSOAR command usually return data
using the ``CommandResults`` class, that is then passed to ``return_results()``
in the ``main()`` function.
``return_results()`` is defined in ``CommonServerPython.py`` to return
the data to XSOAR. ``return_results()`` actually wraps ``demisto.results()``.
You should never use ``demisto.results()`` directly.

Sometimes you will need to return values in a format that is not compatible
with ``CommandResults`` (for example files): in that case you must return a
data structure that is then pass passed to ``return.results()``. (i.e.
check the ``scan_results_command`` function in this file that has the option
to return a file to Cortex XSOAR).

In any case you should never call ``return_results()`` directly from the
command functions.

When you use create the CommandResults object in command functions, you
usually pass some types of data:

- Human Readable: usually in Markdown format. This is what is presented to the
analyst in the War Room. You can use ``tableToMarkdown()``, defined in
``CommonServerPython.py``, to convert lists and dicts in Markdown and pass it
to ``return_results()`` using the ``readable_output`` argument, or the
``return_results()`` function will call ``tableToMarkdown()`` automatically for
you.

- Context Output: this is the machine readable data, JSON based, that XSOAR can
parse and manage in the Playbooks or Incident's War Room. The Context Output
fields should be defined in your integration YML file and is important during
the design phase. Make sure you define the format and follow best practices.
You can use ``demisto-sdk json-to-outputs`` to autogenerate the YML file
outputs section. Context output is passed as the ``outputs`` argument in ``demisto_results()``,
and the prefix (i.e. ``HelloWorld.Alert``) is passed via the ``outputs_prefix``
argument.

More information on Context Outputs, Standards, DBotScore and demisto-sdk:
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/context-standards
https://xsoar.pan.dev/docs/integrations/dbot
https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/json_to_outputs/README.md

Also, when you write data in the Context, you want to make sure that if you
return updated information for an entity, to update it and not append to
the list of entities (i.e. in HelloWorld you want to update the status of an
existing ``HelloWorld.Alert`` in the context when you retrieve it, rather than
adding a new one if you already retrieved it). To update data in the Context,
you can define which is the key attribute to use, such as (using the example):
``outputs_key_field='alert_id'``. This means that you are using the ``alert_id``
key to determine whether adding a new entry in the context or updating an
existing one that has the same ID. You can look at the examples to understand
how it works.
More information here:
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/dt

- Raw Output: this is usually the raw result from your API and is used for
troubleshooting purposes or for invoking your command from Automation Scripts.
If not specified, ``return_results()`` will use the same data as ``outputs``.


Main Function
-------------

The ``main()`` function takes care of reading the integration parameters via
the ``demisto.params()`` function, initializes the Client class and checks the
different options provided to ``demisto.commands()``, to invoke the correct
command function passing to it ``demisto.args()`` and returning the data to
``return_results()``. If implemented, ``main()`` also invokes the function
``fetch_incidents()``with the right parameters and passes the outputs to the
``demisto.incidents()`` function. ``main()`` also catches exceptions and
returns an error message via ``return_error()``.


Entry Point
-----------

This is the integration code entry point. It checks whether the ``__name__``
variable is ``__main__`` , ``__builtin__`` (for Python 2) or ``builtins`` (for
Python 3) and then calls the ``main()`` function. Just keep this convention.

"""
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
import random

import tempfile

from requests import Session
from zeep import helpers
from zeep import Client as zClient
from zeep import Settings
from zeep.cache import SqliteCache
from zeep.transports import Transport

from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


SKYBOX_NETWORK_SERVICE_WSDL = "skybox/webservice/jaxws/network?wsdl"
SKYBOX_TICKET_SERVICE_WSDL = "skybox/webservice/jaxws/tickets?wsdl"

''' SOAP TEMPLATES'''

SOAP_TEST  = " \
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:sky=\"http://skyboxsecurity.com\">\
   <soapenv:Header/>\
   <soapenv:Body>\
      <sky:testService>\
         <anyValue>{anyVal}</anyValue>\
      </sky:testService>\
   </soapenv:Body>\
</soapenv:Envelope>"



DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def test_request(self, anyVal: int) -> Dict[str, Any]:
        """Calls the test service

        :type value: ``int``
        :param anyVal: test value to be returned

        :return: dict containing the IP reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        soap_data = SOAP_TEST.format(anyVal=anyVal)


        try:
            soap_response = self._http_request(
                method='POST',
                url_suffix='/administration',
                data=soap_data,
                resp_type='content'
            )

            json_response = json.loads(xml2json(soap_response))

            retval = int(json_response['Envelope']['Body']['testServiceResponse']['return'])

        except DemistoException as e:
            if 'Forbidden' in str(e):
                return 'Authorization Error: make sure username/password are correct.'
            else:
                raise e



        return retval


    def getDeviceVulnerabilities(self, hostId: int, startIndex: int, size: int):

        params = {
            'startIndex':startIndex,
            'size' : size
        }

        url = f'{self._base_url}/netmodel/v1/hosts/{hostId}/vulnerabilities'

        response = self._http_request("GET",full_url=url,params=params)

        return response









''' HELPER FUNCTIONS '''

def get_cache_path():
    path = tempfile.gettempdir() + "/zeepcache"
    try:
        os.makedirs(path)
    except OSError:
        if os.path.isdir(path):
            pass
        else:
            raise
    db_path = os.path.join(path, "cache.db")
    try:
        if not os.path.isfile(db_path):
            static_init_db = os.getenv('ZEEP_STATIC_CACHE_DB', '/zeep/static/cache.db')
            if os.path.isfile(static_init_db):
                demisto.debug(f'copying static init db: {static_init_db} to: {db_path}')
                shutil.copyfile(static_init_db, db_path)
    except Exception as ex:
        # non fatal
        demisto.error(f'Failed copying static init db to: {db_path}. Error: {ex}')
    return db_path

def parse_domain_date(domain_date: Union[List[str], str], date_format: str = '%Y-%m-%dT%H:%M:%S.000Z') -> Optional[str]:
    """Converts whois date format to an ISO8601 string

    Converts the HelloWorld domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.

    :type domain_date: ``Union[List[str],str]``
    :param date_format:
        a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'

    :return: Parsed time in ISO8601 format
    :rtype: ``Optional[str]``
    """

    if isinstance(domain_date, str):
        # if str parse the value
        domain_date_dt = dateparser.parse(domain_date)
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    elif isinstance(domain_date, list) and len(domain_date) > 0 and isinstance(domain_date[0], str):
        # if list with at least one element, parse the first element
        domain_date_dt = dateparser.parse(domain_date[0])
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    # in any other case return nothing
    return None


def convert_to_demisto_severity(severity: str) -> int:
    """Maps HelloWorld severity to Cortex XSOAR severity

    Converts the HelloWorld alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the HelloWorld API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'Low': 1,  # low severity
        'Medium': 2,  # medium severity
        'High': 3,  # high severity
        'Critical': 4   # critical severity
    }[severity]


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')

def resolve_datetime(input: OrderedDict) -> Dict:

    output = {}
    for key in input:

        if isinstance(input[key],datetime):

            output[key] = input[key].__str__()

        else:
            output[key] = input[key]

    return output



''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error

    anyVal = random.randrange(100)


    if int(client.test_request(anyVal)) == anyVal:
        return 'ok'
    else:
        return f'Value {anyVal} does not match'

def getDeviceVulnerabilities_command(client: Client, args):

    hostId = args.get('hostId',0)
    startIndex = args.get('startIndex',0)
    size = args.get('size',10)

    results = client.getDeviceVulnerabilities(hostId,startIndex,size)

    return CommandResults(
        outputs_prefix='Skybox.Vulnerabilities',
        outputs_key_field='id',
        outputs=results['elements'],
        readable_output=f"Returned {len(results['elements'])} vulnerabilities for asset id {hostId}"

    )





def findFirewallObjectsIdentifications_command(client:zClient, args):

    hostId = args.get('hostId',0)
    objectNameFilter = args.get('objectNameFilter',"*")

    resp = findFirewallObjectsIdentifications(client, hostId,objectNameFilter)

    resp=helpers.serialize_object(resp)

    command_results = CommandResults(
        outputs_prefix="Skybox.Network.FirewallObjects",
        outputs_key_field="objectName",
        outputs= resp
    )

    return command_results




def findFirewallObjectsIdentifications(client: zClient, hostId, objectNameFilter):

    resp = client.service.findFirewallObjectsIdentifications(
        hostId =hostId,
        objectNameFilter = f'"{objectNameFilter}"' #Quote marks force an explicit match.
    )

    return resp



def findAssetsbyName_command(client:zClient, args):

    NameFilter = args.get("NameFilter","*")
    size = int(args.get("size", 1))
    start = int(args.get("start",0))

    resp = findAssetsbyName(client, NameFilter,start=start,size=size)

    resp = helpers.serialize_object(resp)

    command_results = CommandResults (
        outputs_prefix="Skybox.Network.Assets",
        outputs_key_field="id",
        outputs=resp
    )

    return command_results

def findAssetsbyName(client: zClient, NameFilter,start=0,size=1):

    resp = client.service.findAssetsByNames(
        names = NameFilter,
        subRange = {
            'start':start,
            'size':size
        }
    )

    return resp






def findFirewallsByName(client: zClient, args):

    resp = client.service.findFirewallsByName(
        name = args.get('name','')
    )

    resp = helpers.serialize_object(resp['fwElements'])


    command_results = CommandResults(
        outputs_prefix="Skybox.Network.Firewalls",
        outputs_key_field="id",
        outputs=resp
      )

    return(command_results)



def createChangeManagerTicket(client: zClient, args):




    customField_type = client.get_type('ns0:customField')
    customField = customField_type(
        comment = '',
        createdBy = '',
        creationTime = '',
        description = '',
        id = 0,
        lastModificationTime = '',
        lastModifiedBy = '',
        name= '',
        typeCode = 0,
        value = ''
    )


    emailRecipient_type = client.get_type('ns0:emailRecipient')
    emailRecipient = emailRecipient_type(
        email = 'test@test.com',
        userName = 'xsoar'
    )

    accessChangeTicket_type = client.get_type('ns0:accessChangeTicket')
    accessChangeTicket = accessChangeTicket_type(
        id=-1,
        status=args.get('status', 'New'),
        likelihood=args.get('likelihood', 'Unknown'),
        priority=args.get('priority', 'P5'),
        title=args.get('title', ''),
        comment=args.get('comment', ''),
        externalTicketId=args.get('externalTicketId', ''),
        externalTicketStatus=args.get('externalTicketStatus', 'Pending'),
        changeDetails=args.get('changeDetails',''),
        owner=args.get('owner', ''),
        description=args.get('description', ''),
        ccList = [emailRecipient],
        #customFields = [customField]
    )

    resp = client.service.createChangeManagerTicket(
        accessChangeTicket = accessChangeTicket,
        workflowId=1
    )




    command_results = CommandResults(
        outputs_prefix="Skybox.ChangeManagerTicket",
        outputs_key_field="id",
        outputs=helpers.serialize_object(resolve_datetime(resp)),
        readable_output=f"Created Ticket {resp['id']}"
    )

    return command_results


def createTicketAccessRequestsForObjectChange(client: zClient, args):

    resp = client.service.createTicketAccessRequestsForObjectChange(
        ticketId = args.get('ticketId',0),
        hostId = args.get('hostId',0),
        objectName = args.get('objectName',''),
        changeType = args.get('changeType',0),
        addressChange = args.get('addressChange',['']),
        portChange = args.get('portChange',''),
        maxAccessRequestsToCreate = args.get('maxAccessRequestsToCreate',1),
        chainFilterMode = args.get('chainFilterMode',1),
        chainNames = args.get('chainNames','')
    )



    return "Change Requested"

def implementChangeRequests(client: zClient, args):


    ChangeRequestImplementation_type = client.get_type('ns0:changeRequestImplementation')
    ChangeRequestImplementation = ChangeRequestImplementation_type(
        id = args.get('id',0),
        ticketId = args.get('ticketId',0),
        dueDate = args.get('dueDate','2020-05-30T09:00:00'),
        ticketPriority = args.get('ticketPriority', 'P5'),
        changeType = args.get('changeType',''),
        firewallName = args.get('firewallName',''),
        firewallManagementName = args.get('firewallManagementName',''),
        objectId = args.get('objectId',''),
        globalUniqueId = args.get('globalUniqueId',''),
        changeDetails =args.get('changeDetails',''),
        additionalDetails = args.get('additionalDetails',''),
        isRequiredStatus = args.get('isRequiredStatus','UNCOMPUTED'),
        owner = args.get('owner','xsoar'),
        completeDate = args.get('completeData','2002-05-30T09:00:00'),
        workflowName = args.get('workflowName',''),
        comment = args.get('comment',''),
        lastModificationTime = args.get('lastModificationTime','2002-05-30T09:00:00'),
        implementationStatus = args.get('implementationStatus','')


    )


    resp = client.service.implementChangeRequests(
        changeRequests = ChangeRequestImplementation,
        comment = ''
    )


    return_results(str(resp))


def addBlockAccess(ticket_client: zClient,network_client: zClient, args):


    dHostId = args.get('dhostId')
    dObject = args.get('dObject')
    destinationAddresses = args.get('destinationAddresses')

    if dHostId and dObject:
        destinationObjects = findFirewallObjectsIdentifications(network_client, hostId=dHostId, objectNameFilter=dObject)
        destinationObjects =[destinationObjects]
    elif destinationAddresses:
        destinationObjects = None
    else:
        return_error("Destination Object or Address must be provided")

    sHostId = args.get('shostId')
    sObject = args.get('sObject')
    sourceAddresses = args.get('sourceAddresses')

    if sHostId and sObject:
        sourceObjects = findFirewallObjectsIdentifications(network_client, hostId = sHostId, objectNameFilter=sObject)
        sourceObjects = [sourceObjects]
    elif sourceAddresses:
        sourceObjects=None
    else:
        return_error("Source Object or Addresses must be provided")

    blockAccessChangeRequestV7_type = ticket_client.get_type('ns0:blockAccessChangeRequestV7')
    blockAccessChangeRequestV7 = blockAccessChangeRequestV7_type(

    comment = args.get('comment'),
    complianceStatus = args.get('complianceStatus', 'UNCOMPUTED'),
    createdBy = args.get('createdBy', ''),
    # creationTime = args.get('creationTime',''),
    description = args.get('description', ''),
    id = args.get('id', 0),
    isRequiredStatus = args.get('isRequiredStatus', 'UNCOMPUTED'),
    # lastModificationTime = args.get('lastModificationTime',''),
    # lastModifiedBy = args.get('lastModifiedBy','xsoar'),
    originalChangeRequestId = args.get('originalChangeRequestId', 0),
    verificationStatus = args.get('verificationStatus', 'UNKNOWN'),  # END of ChangeRequestV3 BASE.
    destinationAddresses = destinationAddresses,
    destinationObjects=destinationObjects,
    ports=args.get('ports', ""),
    sourceAddresses=sourceAddresses,
    sourceObjects=sourceObjects
    )

    resp = ticket_client.service.addOriginalChangeRequestsV7(
        ticketId=args.get('ticketId', 0),
        changeRequests=blockAccessChangeRequestV7
    )

    return(
        CommandResults(
            outputs_prefix='Skybox.ChangeRequest',
            outputs_key_field = 'id',
            outputs=helpers.serialize_object(resolve_datetime(resp[0]))
        )
    )


def addRequireAccess(ticket_client: zClient,network_client: zClient, args):

    dHostId = args.get('dhostId')
    dObject = args.get('dObject')
    destinationAddresses = args.get('destinationAddresses')

    if dHostId and dObject:
        destinationObjects = findFirewallObjectsIdentifications(network_client, hostId=dHostId,
                                                                objectNameFilter=dObject)
        destinationObjects = [destinationObjects]
    elif destinationAddresses:
        destinationObjects = None
    else:
        return_error("Destination Object or Address must be provided")

    sHostId = args.get('shostId')
    sObject = args.get('sObject')
    sourceAddresses = args.get('sourceAddresses')

    if sHostId and sObject:
        sourceObjects = findFirewallObjectsIdentifications(network_client, hostId=sHostId, objectNameFilter=sObject)
        sourceObjects = [sourceObjects]
    elif sourceAddresses:
        sourceObjects = None
    else:
        return_error("Source Object or Addresses must be provided")

    requireAccessChangeRequestV7_type = ticket_client.get_type('ns0:requireAccessChangeRequestV7') #This uses ChangeRequestV3 as a base
    requireAccessChangeRequestV7 = requireAccessChangeRequestV7_type(
        comment = args.get('comment'),
        complianceStatus = args.get('complianceStatus','UNCOMPUTED'),
        createdBy = args.get('createdBy',''),
        #creationTime = args.get('creationTime',''),
        description = args.get('description',''),
        id = args.get('id',0),
        isRequiredStatus =  args.get('isRequiredStatus','UNCOMPUTED'),
        #lastModificationTime = args.get('lastModificationTime',''),
        #lastModifiedBy = args.get('lastModifiedBy','xsoar'),
        originalChangeRequestId = args.get('originalChangeRequestId',0),
        verificationStatus = args.get('verificationStatus','UNKNOWN'), #END of ChangeRequestV3 BASE.
        destinationAddresses=destinationAddresses,
        destinationObjects = destinationObjects,
        isGlobal = False,
        isInstallOnAny = False,
        isLogEnabled = args.get('isLogEnabled', True),
        isSharedObject = args.get('isSharedObject',False),
        NATPorts = args.get('NATPorts', ""),
        ports = args.get('ports',""),
        sourceAddresses = args.get('sourceAddresses',""),
        sourceObjects=sourceObjects,
        useApplicationsDefaultPorts = False,
        userUsage = "ANY"

    )

    resp=ticket_client.service.addOriginalChangeRequestsV7(
        ticketId = args.get('ticketId',64),
        changeRequests = requireAccessChangeRequestV7
    )

    return(
        CommandResults(
            outputs_prefix='Skybox.ChangeRequest',
            outputs_key_field='id',
            outputs=helpers.serialize_object(resolve_datetime(resp[0]))
        )
    )


def addRuleChange(ticket_client: zClient,network_client: zClient, args):

    firewallName = args.get("firewallName","")

    asset = findAssetsbyName(network_client,NameFilter=firewallName)['assets'][0]
    #demisto.log(str(asset['assets']))

    dHostId = args.get('hostId')
    dObject = args.get('dObject')
    destinationAddresses = args.get('destinationAddresses')

    if dHostId and dObject:
        destinationObjects = findFirewallObjectsIdentifications(network_client, hostId=dHostId,
                                                                objectNameFilter=dObject)
        destinationObjects = [destinationObjects]
    elif destinationAddresses:
        destinationObjects = None
    else:
        return_error("Destination Object or Address must be provided")

    sHostId = args.get('hostId')
    sObject = args.get('sObject')
    sourceAddresses = args.get('sourceAddresses')

    if sHostId and sObject:
        sourceObjects = findFirewallObjectsIdentifications(network_client, hostId=sHostId, objectNameFilter=sObject)
        sourceObjects = [sourceObjects]
    elif sourceAddresses:
        sourceObjects = None
    else:
        return_error("Source Object or Addresses must be provided")

    addRuleChangeRequestV7_type = ticket_client.get_type('ns0:addRuleChangeRequestV7')
    addRuleChangeRequestV7 = addRuleChangeRequestV7_type(

        comment=args.get('comment'),
        complianceStatus=args.get('complianceStatus', 'UNCOMPUTED'),
        createdBy=args.get('createdBy', ''),
        # creationTime = args.get('creationTime',''),
        description=args.get('description', ''),
        id=args.get('id', 0),
        isRequiredStatus=args.get('isRequiredStatus', 'UNCOMPUTED'),
        # lastModificationTime = args.get('lastModificationTime',''),
        # lastModifiedBy = args.get('lastModifiedBy','xsoar'),
        originalChangeRequestId=args.get('originalChangeRequestId', 0),
        verificationStatus=args.get('verificationStatus', 'UNKNOWN'),  # END of ChangeRequestV3 BASE.
        destinationAddresses=destinationAddresses,
        destinationObjects=destinationObjects,
        firewall=asset,
        hideSourceBehindGW=True,
        isGlobal=False,
        isInstallOnAny=False,
        isLogEnabled=args.get('isLogEnabled', True),
        isSharedObject=args.get('isSharedObject', False),
        NATPorts=args.get('NATPorts', ""),
        ports=args.get('ports', ""),
        ruleType=args.get('ruleType', ""),
        sourceAddresses=args.get('sourceAddresses', ""),
        sourceObjects=sourceObjects,
        useApplicationDefaultPorts=False,

        userUsage="ANY"
    )

    resp = ticket_client.service.addOriginalChangeRequestsV7(
        ticketId=args.get('ticketId', 64),
        changeRequests=addRuleChangeRequestV7
    )

    return (
        CommandResults(
            outputs_prefix='Skybox.ChangeRequest',
            outputs_key_field='id',
            outputs=helpers.serialize_object(resolve_datetime(resp[0]))
        )
    )





def operateOnAccessChangeTicket(ticket_client:zClient, args):

    phaseOperation_type = ticket_client.get_type('ns0:phaseOperation')
    phaseOperation = phaseOperation_type(
        phaseId = 0,
        reject = False,
        type = args.get('phaseType',"ACCEPT"),
        phaseOwner= args.get('phaseOwner','xsoar')


    )

    resp = ticket_client.service.operateOnAccessChangeTicket(
        ticketId = args.get('ticketId',0),
        phaseOperation = phaseOperation
    )

    return (f"Requested to {args.get('phaseType')} for ticket {args.get('ticketId')}")

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = demisto.params()['url']
    soap_service_url = urljoin(base_url, '/skybox/webservice/jaxws')
    service_url = urljoin(base_url, '/skybox/webservice/jaxrs')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents


    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    username=demisto.params().get('username')
    password=demisto.params().get('password')

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging




    #verify_ssl = not demisto.params.get('insecure', False)
    if demisto.command().startswith("skybox-network"):
        wsdl: str = f'{base_url}/{SKYBOX_NETWORK_SERVICE_WSDL}'

    else :
        wsdl: str = f'{base_url}/{SKYBOX_TICKET_SERVICE_WSDL}'


    session: Session = Session()
    session.auth = (username, password)
    session.verify = verify_certificate
    cache: SqliteCache = SqliteCache(path=get_cache_path(), timeout=None)
    transport: Transport = Transport(session=session, cache=cache)
    settings: Settings = Settings(strict=False, xsd_ignore_sequence_order=True)

    wsdl: str = f'{base_url}/{SKYBOX_TICKET_SERVICE_WSDL}'
    ticket_client: zClient = zClient(wsdl=wsdl, transport=transport, settings=settings)

    wsdl: str = f'{base_url}/{SKYBOX_NETWORK_SERVICE_WSDL}'
    network_client: zClient = zClient(wsdl=wsdl, transport=transport, settings=settings)




    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=service_url,
            verify=verify_certificate,
            auth=(username,password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(ticket_client)
            return_results(result)

        elif demisto.command()== 'skybox-getDeviceVulnerabilities':
            return_results(getDeviceVulnerabilities_command(client,demisto.args()))

        elif demisto.command()== 'skybox-network-findAssetsbyName':
            return_results(findAssetsbyName_command(network_client,demisto.args()))

        elif demisto.command() == 'skybox-network-findfirewallsbyname':
            return_results(findFirewallsByName(network_client,demisto.args()))

        elif demisto.command() == 'skybox-network-findFirewallObjectsIdentifications':
            return_results(findFirewallObjectsIdentifications_command(network_client, demisto.args()))

        elif demisto.command() == 'skybox-tickets-createChangeManagerTicket':
            return_results(createChangeManagerTicket(ticket_client,demisto.args()))

        elif demisto.command() == 'skybox-tickets-createTicketAccessRequestsForObjectChange':
            return_results(createTicketAccessRequestsForObjectChange(ticket_client,demisto.args()))

        elif demisto.command() == 'skybox-tickets-implementChangeRequests':
            return_results(implementChangeRequests(ticket_client, demisto.args()))

        elif demisto.command() == 'skybox-tickets-addRequireAccess':
            return_results(addRequireAccess(network_client=network_client, ticket_client=ticket_client, args=demisto.args()))

        elif demisto.command() == 'skybox-tickets-addBlockAccess':
            return_results(addBlockAccess(network_client=network_client, ticket_client=ticket_client, args=demisto.args()))

        elif demisto.command() == 'skybox-tickets-addRule':
            return_results(addRuleChange(network_client=network_client, ticket_client=ticket_client, args=demisto.args()))

        elif demisto.command() == 'skybox-tickets-operateOnAccessChangeTicket':
            return_results(operateOnAccessChangeTicket(ticket_client=ticket_client,args=demisto.args()))




        elif demisto.command() == 'domain':
            default_threshold_domain = int(demisto.params().get('threshold_domain', '65'))
            return_results(domain_reputation_command(client, demisto.args(), default_threshold_domain))

        elif demisto.command() == 'helloworld-say-hello':
            return_results(say_hello_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-search-alerts':
            return_results(search_alerts_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-get-alert':
            return_results(get_alert_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-update-alert-status':
            return_results(update_alert_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-start':
            return_results(scan_start_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-status':
            return_results(scan_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-results':
            return_results(scan_results_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
