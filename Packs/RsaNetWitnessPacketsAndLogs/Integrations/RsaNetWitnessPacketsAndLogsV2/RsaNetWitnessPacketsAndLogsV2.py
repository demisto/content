import io
import os
import re
import struct
import tempfile
import time
import zipfile
from datetime import datetime

import requests
from requests.auth import HTTPBasicAuth

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# #=====================================================================================================================
# #  ____   ____      _       _   _ _____ _______        _____ _____ _   _ _____ ____ ____
# # |  _ \ / ___|    / \     | \ | | ____|_   _\ \      / /_ _|_   _| \ | | ____/ ___/ ___|
# # | |_) |\___ \   / _ \    |  \| |  _|   | |  \ \ /\ / / | |  | | |  \| |  _| \___ \___ \
# # |  _ <  ___) | / ___ \   | |\  | |___  | |   \ V  V /  | |  | | | |\  | |___ ___) |__) |
# # |_| \_\|____/ /_/   \_\  |_| \_|_____| |_|    \_/\_/  |___| |_| |_| \_|_____|____/____/
# #
# #=====================================================================================================================

# #--------------------------------------------------------------------------------------------------------------------#
# # HOUSE KEEPING                                                                                                      #
# #--------------------------------------------------------------------------------------------------------------------#

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

# 32 MB Numeric
SIZE_32_MB = 33554432

# #--------------------------------------------------------------------------------------------------------------------#
# # CONFIGURATION OBJECTS                                                                                              #
# #--------------------------------------------------------------------------------------------------------------------#

"""
    This is a Central Object to contain the Netwitness Meta that will be storing a Category Map.
    Each entry will house a Set of Netwitness Meta.

    Four categories are defined in the Map as of now which are IP, USER, DOMAIN, and HOST

    Users are allowed to add and edit these categories as they like!
"""
NwQueryMetaMappingConfig = {
    'IP': ['ip.src', 'ip.dst', 'alias.ip', 'device.ip'],
    'HOST': ['alias.host'],
    'USER': ['username', 'ad.username.src', 'ad.username.dst', 'user.src', 'user.dst', 'user', 'user.all'],
    'DOMAIN': ['domain', 'tld', 'dn', 'domain.src', 'domain.dst', 'domain.all'],
}


# End of NwQueryMetaMappingConfig


class Enum:
    # Value of the Enum
    _value_ = None

    def __init__(self, v):
        self._value_ = v

    def __eq__(self, other):
        """Overrides the default implementation"""
        if isinstance(other, Enum):
            return self._value_ == other._value_
        return self._value_ == other

    def value(self):
        return self._value_


# End of Class Enum

# #--------------------------------------------------------------------------------------------------------------------#
# # COMMON CLASSES AND UTILITIES                                                                                       #
# #--------------------------------------------------------------------------------------------------------------------#


class NwEndpointType:
    """
        Supported Client Type
    """

    # Netwitness Respond API
    def __init__(self):
        pass

    INTEGRATION = 1

    # Netwitness Core API
    CORE = 2

    # Netwitness Server API
    SERVER = 3


# End of NwEndpointType


class NwConstants:
    """
        Constants to be used in the implementation!
    """

    # URL for Netwitness Admin Server OAuth Token API
    OAUTH_PATH = '/oauth/token'

    # Auth API for Authentication via Integration Server
    INTEGRATION_SERVER_AUTH = '/rest/api/auth/userpass'


# End of NwConstants


class NwIndexLevel(Enum):
    """
        Netwitness Meta Key Index Level Constants!
    """
    INDEX_NONE = 1
    INDEX_KEY = 2
    INDEX_VALUE = 3
    INDEX_KEY_FILTER = 4


# End of NwIndexLevel


class NwMetaFormat(Enum):
    """
        Netwitness Meta Format Enums. These formats can be inferred in the Query Response Delivered from Core
    """
    nwUndefined = 0
    nwInt8 = 1
    nwUInt8 = 2
    nwInt16 = 3
    nwUInt16 = 4
    nwInt32 = 5
    nwUInt32 = 6
    nwInt64 = 7
    nwUInt64 = 8
    nwUInt128 = 9
    nwFloat32 = 10
    nwFloat64 = 11
    nwTimeT = 32
    nwDayOfWeek = 33
    nwHourOfDay = 34
    nwBinary = 64
    nwText = 65
    nwIPv4 = 128
    nwIPv6 = 129
    nwMAC = 130
    nwRtp = 140
    nwLowerBound = 500
    nwUpperBound = 501


# End of NwMetaFormat


class NwQueryOperator:
    """
        Supported Netwitness Query Operators
    """

    # Check for Equality of values
    def __init__(self):
        pass

    EQUALS = ' = '

    # Checks for In-Equality of values
    NOT_EQUALS = ' != '

    # Checks if LHS Meta contains RHS String
    CONTAINS = ' contains '

    # Checks if LHS Meta begins with RHS String
    BEGINS = ' begins '

    # Checks if LHS Meta ends with RHS String
    ENDS = ' ends '

    # Checks if LHS Meta is Greater than RHS Value
    GT = ' > '

    # Checks if LHS Meta is Greater Than or Equal to RHS Value
    GTE = ' >= '

    # Checks if LHS Meta is Less Than or Equal to RHS Value
    LT = ' < '

    # Checks if LHS Meta is Less Than or Equal to RHS Value
    LTE = ' <= '

    # Checks if LHS Meta value matches RHS RegEx
    REGEX = ' regex '


# End of NwQueryOperator

class NwSessionRenderType:
    """
        Supported Netwitness Rendering Options for A Session
    """

    # Check for Equality of values
    def __init__(self):
        pass

    # Auto Select HTML Content View
    AUTO = 0

    # HTML Meta Details View
    DETAILS = 1

    # HTML Text View
    TEXT = 2

    # Hex View
    HEX = 3

    # Packets View
    PACKETS = 4

    # Mail View
    MAIL = 5

    # WEB View
    WEB = 6

    # VOIP
    VOIP = 7

    # IM View
    IM = 8

    # PCAP View
    PCAP = 100

    # RAW CONTENT
    RAW = 102

    # Meta View
    XML = 103

    # Meta CSV
    CSV = 104

    # Meta Tab Separated
    TXT = 105

    # Netwitness Data File
    NWD = 106

    # Original Files
    FILE = 107


# End of NwSessionRenderType


class NwMeta:
    """
        Class encapsulating a Meta Definition associated with the Netwitness Core Service
    """

    # Meta name
    def __init__(self):
        pass

    name = None

    # Meta Format
    type = None

    # Meta Flags
    flags = None

    # Meta Description
    description = None

    # Utility method to get the Index Level out of Flags Value of Meta
    def getIndexLevel(self):
        level = 0x00F & self.flags
        return NwIndexLevel(level)


# End of NwMeta


class NwEvent:
    """
        A Simple class encapsulating a Netwitness Event. All the Core APIs returning Netwitness Events will be
        returning list of instance of this class
    """

    # Netwitness Session Id
    sessionId = None

    # The  dictionary containing Meta Value for the Event
    meta = None

    # Optional Log for this Event
    rawLog = None

    # Optional Netwitness Basic File Associated with this session
    files = None

    # Constructor
    def __init__(self, sessionId):
        self.sessionId = sessionId
        self.meta = dict()


# End of NwEvent


class NwQueryField:
    """
        Class for encapsulating Result Line returned by the Core Service
    """

    # Meta Id 1
    id1 = 0

    # Meta Id 2
    id2 = 0

    # Count Associated
    count = 0

    # Integer representing the NwMetaFormat
    format = 0

    # Value
    value = None

    # Meta Type / Name
    type = None

    # Flags if any
    flags = 0

    # SessionId if any
    group = 0

    # Constructor
    def __init__(self, line=''):
        """
            This constructor will read the line from the Netwitness Query Response and will try to parse information
            There are cases where Broker sends additional lines that describes the Source information about downstream
            devices. We want to skip those line!

                :param line: The Query Response Line as Sent by Core for any SDK Call
        """
        try:
            _temp = line

            # read id1
            v = re.search('\\s*id1=\\d+', _temp).group(0).strip()
            self.id1 = int(v.split('=')[1])
            _temp = _temp.replace(v, '')

            # read id2
            v = re.search('\\s*id2=\\d+', _temp).group(0).strip()
            self.id2 = int(v.split('=')[1])
            _temp = _temp.replace(v, '')

            # read count
            v = re.search('\\s*count=\\d+', _temp).group(0).strip()
            self.count = int(v.split('=')[1])
            _temp = _temp.replace(v, '')

            # read format
            v = re.search('\\s*format=\\d+', _temp).group(0).strip()
            self.format = int(v.split('=')[1])
            _temp = _temp.replace(v, '')

            # read group
            v = re.search('\\s*group=\\d+', _temp).group(0).strip()
            self.group = int(v.split('=')[1])
            _temp = _temp.replace(v, '')

            # read flags_temp
            v = re.search('\\s*flags=\\d+', _temp).group(0).strip()
            self.flags = int(v.split('=')[1])
            _temp = _temp.replace(v, '')

            # read type
            v = re.search('\\s*type=[a-zA-Z0-9.]+', _temp).group(0).strip().strip()
            self.type = v.split('=')[1]
            _temp = _temp.replace(v, '')

            # read value
            v = re.search('\\s*value=.*', _temp).group(0).strip().strip()
            self.value = v.split('=')[1]

        except:
            raise Exception("Error while parsing query response [ " + line + " ]")


# End of NwQueryField


class NwQueryResponse:
    """
        A Class to hold the SDK Response in a parsed manner
    """

    # Starting Meta Id
    id1 = 0

    # End Meta Id
    id2 = 0

    # List of @NwQueryField that will be rows for each result!
    result = None

    # Constructor
    def __init__(self):
        self.result = list()

    # Wrapper method to read from Plain Text SDK Response
    def parseFromHttpResponse(self, response=''):
        """
            Reads the SDK Response obtained by firing a SDK Request via Netwitness Core Service Rest Interface

            :param response: The HTTP Response from the Netwitness Core Service
        """
        # Split lines on Line Breaks!
        lines = response.splitlines()

        # Iterate thru lines!
        _c = len(lines)
        for index in range(0, _c - 1):

            l = lines[index]
            if l == '[' or l == ']':
                continue
            elif l.startswith('['):

                # If line starts with '[' then its ID Range for response
                # self.id1 = int(re.search('\\s*id1=\\d+', l).group(0).split('=')[1])
                self.id2 = int(re.search('\\s*id2=\\d+', l).group(0).split('=')[1])

            else:
                # Else parse it as the Query Response Field
                try:
                    self.result.append(NwQueryField(l))
                except:
                    # demisto.log('Error in while parsing line [ ' + l + ' ]')
                    pass
                continue

    # End of Function parseFromHttpResponse

    def asSDKQueryResponse(self):
        """
            Parses the Query Response as SDK Query Events grouped by Session Ids

            :return: a dictionary containing a map from Session Ids to NwEvent parsed from Response
        """
        data = dict()
        for f in self.result:

            # Add Entry for Session Id
            if f.group not in data:
                data[f.group] = dict()

            # Add Entry for Meta Dictionary
            if f.type not in data[f.group]:
                data[f.group][f.type] = list()

            # Add value to the existing list of Meta Value
            data[f.group][f.type].append(f.value)
        return data

    # End of Function asSDKQueryResponse

    def asSDKValuesResponse(self):
        """
            Parses the Query Response as SDK Values Response

            :return: A list of tuples containing values followed by it count values
        """
        data = []
        for f in self.result:
            data.append([f.value, f.count])
        return data

    # End of Function asSDKValuesResponse

    def asSDKLanguageResponse(self):
        """
            Parses the Query Response as SDK Language Response

            :return: A list of NwMeta
        """
        _result = []
        for n in self.result:
            nwm = NwMeta()
            nwm.name = n.type
            nwm.type = NwMetaFormat(n.format)
            nwm.flags = n.flags
            _result.append(nwm)
        return _result
    # End of asSDKLanguageResponse


# End of class NwQueryResponse


class NwIoBufferWrapper:
    """
        Simple Wrapper for Netwitness File Wrapper that can be used to view File Details
    """

    def __init__(self):
        pass

    # Current Buffer Position
    position = 0

    # Maximum Available Buffer Position
    maximum = -1

    # Remaining Buffer Capacity
    remaining = -1

    # Original Content
    content = bytearray()

    # Endian Setting!
    endian = 'little'

    # Load from File Path from Disk!
    def loadFromFile(self, filepath):
        """
        Reads the file as Byte Array!

        :param filepath: Location of file in File System
        :return:
        """
        self.loadFromByteArray(bytearray(open(filepath, 'rb').read()))

    # End of function loadFromFile

    def loadFromByteArray(self, byte_array):
        """
        Loads Buffer with the Byte Array

        :param byte_array: bytearray to be supplied by script!
        :return:
        """
        self.content = bytearray(byte_array)
        self.maximum = len(self.content)

    # End of function loadFromByteArray

    def readBytesOfSize(self, size):
        """
        Reads the fixed number of bytes from buffer and increments the Current Position
        :param size:
        :return:
        """
        if (self.position + size) > len(self.content):
            raise Exception("Buffer Overflown. This might not be a Netwitness Content Wrapper")
        _arr = self.content[self.position:self.position + size]
        self.position = self.position + size
        return _arr

    # End of function readBytesOfSize

    def readBytes(self):
        """
        Reads the Bytes Data from the Buffer!

        :return:
        """
        v = self.readUnsignedInt()
        if v < 0 or v > SIZE_32_MB:
            raise Exception("Read Size is more than 32 MB. Cannot read such large numbers")
        return self.readBytesOfSize(v)

    # End of function readBytes

    def readUnsignedInt(self):
        """
        Read four bytes of the Buffer as Integer!

        :return:
        """
        if self.endian == 'little':
            return int(struct.unpack("<L", str(self.readBytesOfSize(4)))[0])
        else:
            return int(struct.unpack(">L", str(self.readBytesOfSize(4)))[0])

    # End of function readUnsignedInt

    def readStringOfSize(self, size):
        """
        Reads the fixed number of bytes as String!
        :param size:
        :return:
        """
        return self.readBytesOfSize(size).decode("utf-8")

    # End of function readString

    def readString(self):
        """
        Reads the byte array as Integer and then string of that length
        :return:
        """
        v = self.readUnsignedInt()
        if v < 0 or v > SIZE_32_MB:
            raise Exception("Read Size is more than 32 MB. Cannot read such large numbers")
        return self.readBytesOfSize(v).decode("utf-8")

    # End of function readString

    def readLine(self, crlf=False):
        """
        Reads the byte array as Integer and then string of that length
        :return:
        """
        array = bytearray()
        array.extend(self.readBytesOfSize(2))
        if crlf:
            while not array.endswith('\r\n'):
                array.extend(self.readBytesOfSize(1))
        else:
            while not array.endswith('\n'):
                array.extend(self.readBytesOfSize(1))
        return array.decode("utf-8")

    # End of function readString

    def hasMore(self):
        """
        Reads the byte array as Integer and then string of that length
        :return:
        """
        return self.position < self.maximum

    # End of function hasMore

    def reset(self):
        """
        Resets the IO Buffer!
        :return:
        """
        self.position = 0
    # End of function reset


class NwStringParams:
    """
    A simple class to wrap an IoBuffer as String Parameters!
    """

    # String Parameters contained in the IoBuffer
    values = {}

    def __init__(self, ioBuffer):

        # Read Number of Parameters!
        numberOfParams = ioBuffer.readUnsignedInt()

        if numberOfParams <= 0 or numberOfParams > 32:
            raise Exception(
                "Number of parameters in the Headers is [ " + str(numberOfParams) + " ] not in range [1,32]")

        # Read those number of parameters
        for index in range(numberOfParams):
            # Read Parameter Key
            key = ioBuffer.readString()

            # Read Parameter Value
            value = ioBuffer.readString()
            self.values[key] = value

    # End of Init

    def get(self, key):
        """
        Returns the Value of the Parameter

        :param key:
        :return:
        """
        return self.values[key]

    # End of function Get


class NwBaseFile:
    """
    A wrapper class to hold the File Inside the captured session in Netwitness
    """
    # Captured file name
    filename = ''

    # File Size captured
    filesize = -1

    # Type of file captured
    filetype = ''

    # Byte Content of file
    data = bytearray()

    def __init__(self, filename, fileSize, fileType, data):
        """
        Needs the String Parameters and the data to create this wrapper!

        :param params: The NwStringParams instance containing the properties
        :param data: The Byte array captured
        """
        self.filename = filename
        self.filesize = fileSize
        self.filetype = fileType
        self.data = data

    # End of function init

    # End of function init


class NwContentFileResponse:
    """"
    The wrapper class to Hold the Nw Content Response for Render Type as FILE
    """

    # Number of file contained in the Response
    filecount = -1

    # The NwBaseFiles in the response
    nwfiles = list()

    def __init__(self, ioBuffer):

        # Check if it is Mime Message!
        if 'This is a message with multiple parts in MIME format.' == ioBuffer.readStringOfSize(53):

            # Skip New Line CRLF
            assert ioBuffer.readStringOfSize(4) == '\r\n\r\n'

            # Boundary
            boundary = ioBuffer.readLine(crlf=True).strip()

            while ioBuffer.hasMore():

                # Mime Headers
                mime_heades = dict()

                # Encoding
                while True:
                    _line = ioBuffer.readLine().strip()
                    if _line.startswith('Content'):
                        sp = _line.split(':', 2)
                        mime_heades[sp[0]] = sp[1]
                    else:
                        break

                # Content of File
                filename = mime_heades['Content-Disposition'].split('=')[1][1:-1]
                filesize = int(mime_heades['Content-Length'])
                filetype = mime_heades['Content-Type']
                data = ioBuffer.readBytesOfSize(filesize)
                self.nwfiles.append(NwBaseFile(filename, filesize, filetype, data))

                # New Line After Content!
                assert '\r\n' == ioBuffer.readLine(crlf=True)

                # Increment file count!
                self.filecount = len(self.nwfiles)

                # Boundary After New Line
                _boundary = ioBuffer.readLine(crlf=True).strip()
                if boundary == _boundary:
                    continue
                elif (boundary + '--') == _boundary:
                    break
                else:
                    raise Exception("Invalid Mime Boundary, expected [ " + boundary + " ] found [ " + _boundary + " ]")

            # End of While Loop

        else:
            # Reset the Buffer!
            ioBuffer.reset()

            # Treat file as Proto Packaged!
            sp = NwStringParams(ioBuffer)

            # Get the file count
            self.filecount = int(sp.get("fileCount"))
            if self.filecount > 0:
                # Read the first file
                self.nwfiles.append(NwBaseFile(sp.get('fileName'), int(sp.get('fileSize')), sp.get('fileType'),
                                               ioBuffer.readBytes()))

            for x in range(1, self.filecount):
                # Read subsequent files
                sp = NwStringParams(ioBuffer)
                self.nwfiles.append(NwBaseFile(sp.get('fileName'), int(sp.get('fileSize')), sp.get('fileType'),
                                               ioBuffer.readBytes()))

    # End of function Init


# #--------------------------------------------------------------------------------------------------------------------#
# # BASE DEFINITION FOR NW CLIENT                                                                                      #
# #--------------------------------------------------------------------------------------------------------------------#


class NwClient:
    """
        Base class to be defined for Netwitness Clients!
    """

    # The type of endpoint
    def __init__(self):
        pass

    endpointType = None

    # Server Details
    server = {}

    # Credentials
    credentials = {}

    # Proxy
    proxy = None

    # Token
    token = ''

    # URL
    url = None

    # Session
    session = None

    # Device Summary
    deviceInfo = {}

    # Meta Information
    metaInformation = {}

    # set
    typeToMeta = set()

    # Method to set the initial values!
    def configure(self, host, port, ssl=True, secure=True, username='admin', password='netwitness',
                  endpointtype=NwEndpointType.INTEGRATION):
        """
        Method to configure the Client with commonly used paramters.

        :param host: The host name or IP Address of the Server where Service is running
        :param port: Port on which Service is listening
        :param ssl: Use SSL Connection to connect
        :param secure: Validate the Certificate in case of SSL ENabled
        :param username: Service Username
        :param password: Service Password
        :param endpointtype: Type of Server
        :return:
        """

        # Server Details
        self.server['host'] = host
        self.server['port'] = port
        self.server['secure'] = secure
        self.server['ssl'] = ssl

        # Credentials
        self.credentials['username'] = username
        self.credentials['password'] = password

        # Protocols
        self.endpointType = endpointtype

        # Set URL
        url = 'https://'
        if not self.server['ssl']:
            url = 'http://'
        self.url = url + self.server['host'] + ":" + str(self.server['port'])

        # Proxy
        self.proxy = None

    # End of function configure

    def enableProxy(self):
        """
        Enables the Proxy for the Client
        :return:
        """

        http = os.environ['http_proxy'] or os.environ['HTTP_PROXY']
        https = os.environ['https_proxy'] or os.environ['HTTPS_PROXY']
        self.proxy = {
            'http': http,
            'https': https
        }

    # End of function enableProxy

    def getBaseURL(self, path):
        return self.url + path

    # End of function getBaseURL

    def doLogin(self):
        """
                    Authenticate to the Server based on the parameters passed into the Configure Method
                    :return:
                """
        pass

    # End of function doLogin

    def start(self):
        """
            A method to be overridden by Client Implementations to initiate the post authentication steps
        :return:
        """
        return None

    # End of function start


class NwAlert:
    def __init__(self):
        pass

    alertId = None
    time = None
    events = None


class NwIncident:
    incidentId = None
    incident = None
    alerts = None

    def __init__(self, incident):
        self.incident = incident
        self.incidentId = incident['id']
        self.alerts = list()

    def extractIPAddresses(self):
        return None

    def extractHosts(self):
        return None

    def extractDomains(self):
        return None

    def extractUsers(self):
        return None


class NwIntegrationClient(NwClient):
    # Last Incident Time
    lastIncidentTime = None

    def __init__(self, host, port, ssl, secure, uname, pwd):
        self.configure(host, port, ssl, secure, uname, pwd, NwEndpointType.INTEGRATION)

    def doLogin(self):
        """
            Function to esatblish the authenticated session with Integration Server!
        """

        # Raise exception in case of wrong Endpoint Type
        if self.endpointType != NwEndpointType.INTEGRATION:
            raise Exception("Only Integration Server Authentication Is Supported in this Client")

        # default headers for HTTP Request to be sent to the Netwitness Server for getting Auth Token
        httpHeaders = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=ISO-8859-1',
            'Accept': 'application/json; charset=UTF-8',
            'NetWitness-Version': "11.1.0.0"
        }

        # format the user info
        uap = {
            "username": self.credentials['username'],
            "password": self.credentials['password']
        }

        loginURL = self.getBaseURL(NwConstants.INTEGRATION_SERVER_AUTH)

        response = requests.post(loginURL,
                                 headers=httpHeaders,
                                 data=uap,
                                 verify=self.server['secure'],
                                 proxies=self.proxy
                                 )

        # successful get_token
        if response.status_code == 200:
            self.token = response.json()
            self.session = requests.session()
            self.start()
            return

        # bad request - NetWitness returns a common json structure for errors
        raise ValueError('Error in Authenticating to Integration Server with Status: {}'.format(response.status_code))

    # End of function doLogin

    def __makeRestCall(self, url, method='get', headers={}, params={}):
        _headers = {
            'Netwitness-Token': self.token['accessToken']
        }
        _headers.update(headers)
        _params = {}
        _params.update(params)

        if method == 'get':
            response = self.session.get(
                url,
                headers=_headers,
                verify=self.server['secure'],
                proxies=self.proxy,
                params=_params
            )
        if method == 'post':
            response = self.session.get(
                url,
                headers=_headers,
                verify=self.server['secure'],
                proxies=self.proxy,
                data=_params
            )

        return response

    def __getAlertsForIncidentId(self, incidentId='', limit=0):

        # URL to fetch alerts!
        _url = self.getBaseURL('/rest/api/incidents/' + incidentId + '/alerts')

        # Page Number to keep track of!
        _page_number = 0

        # Result variable
        result = list()

        while _page_number != -1 and len(result) <= limit:
            _url_params = {
                'pageNumber': _page_number,
                'pageSize': 100
            }
            response = self.__makeRestCall(_url, params=_url_params)

            # successful request
            if response.status_code == 200:

                # Decode JSON
                _json = response.json()

                # Get Alerts Array!
                _items = _json['items']

                # Append them to Result
                for _item in _items:
                    result.append(_item)
                # See if we have more results!
                if _json['hasNext']:
                    _page_number = _page_number + 1
                else:
                    _page_number = -1

            # Else, raise Exception!
            else:
                # bad request - NetWitness returns a common json structure for errors
                error_lst = response.json().get('errors')
                raise ValueError(
                    'Request failed with status: {}\n{}'.format(response.status_code, str(error_lst)))
        # Return the result!
        return result

    def getAllIncidentsBetween(self, startEpoch=None, endEpoch=None, fetchAlerts=False, limit=1000, alertLimit=0):

        # URL to send REST Request
        _url = self.getBaseURL('/rest/api/incidents')

        # List to send Result!
        result = list()

        # Page Number to Track!
        _page_number = 0

        # Run while more results to fetch
        while len(result) < limit and _page_number != -1:
            _url_params = {
                'since': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(startEpoch)),
                'until': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(endEpoch)),
                'pageNumber': _page_number,
                'pageSize': 100
            }
            response = self.__makeRestCall(_url, params=_url_params)

            # successful request
            if response.status_code == 200:
                _json = response.json()
                items = _json['items']

                # Add all the items into the result after casting them to NwIncident
                for _item in items:
                    result.append(NwIncident(_item))

                if _json['hasNext']:
                    _page_number = _page_number + 1
                else:
                    _page_number = -1

                if fetchAlerts:
                    # If we are fetching alerts make sure that we are doing it for all the incidents!
                    for _inc in result:
                        _inc.alerts = self.__getAlertsForIncidentId(_inc.incidentId, alertLimit)
            else:
                # bad request - NetWitness returns a common json structure for errors
                error_lst = response.json().get('errors')
                raise ValueError(
                    'Request failed with status: {}\n{}'.format(response.status_code, error_lst))

        # Return result
        return result

    def getNewIncidents(self, fetchAlerts=False):
        # See if last recorded time is available
        if not self.lastIncidentTime:
            self.lastIncidentTime = int(time.time()) - 172800
        return self.getAllIncidentsBetween(self.lastIncidentTime, int(time.time()), fetchAlerts=True, alertLimit=1)

    def readIncident(self, incidentId):
        return self.__getAlertsForIncidentId(incidentId)


# #--------------------------------------------------------------------------------------------------------------------#
# # NETWITNESS CORE SERVICE CLIENT                                                                                     #
# #--------------------------------------------------------------------------------------------------------------------#

class NwCoreClient(NwClient):
    # Summary Information
    deviceSummary = None

    # Meta Information
    metaInformation = None

    # Constructor
    def __init__(self, host, port, ssl, secure, uname, pwd):
        self.configure(host, port, ssl, secure, uname, pwd, NwEndpointType.CORE)
        self.deviceSummary = dict()
        self.metaInformation = dict()

    # End of constructor

    def doLogin(self):
        """
            Creates a session with Netwitness Core Server REST API Server
        """

        # Raise exception in case of wrong type
        if self.endpointType != NwEndpointType.CORE:
            raise Exception("Only Netwitness Core Service Authentication Is Supported in this Client")

        # default headers for HTTP Request to be sent to the Netwitness Server for getting Auth Token
        httpHeaders = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=ISO-8859-1',
            'Accept': 'application/json; charset=UTF-8',
            'NetWitness-Version': "11.1.0.0",
            "Authorization": "Basic bndfdWk6"
        }

        loginURL = self.getBaseURL('')

        response = requests.get(loginURL,
                                headers=httpHeaders,
                                verify=self.server['secure'],
                                proxies=self.proxy,
                                auth=HTTPBasicAuth(self.credentials['username'], self.credentials['password'])
                                )

        # successful get_token
        if response.status_code == 200:
            self.token = response.json()
            self.session = requests.session()
            self.session.auth = HTTPBasicAuth(self.credentials['username'], self.credentials['password'])
            self.start()
            return

        # bad request - NetWitness returns a common json structure for errors
        raise ValueError('Error in Authenticating to Core Server with Status: {}'.format(response.status_code))

    # End of function doLogin

    # REST Call Method
    def __makeNodeCall(self, node, msg, options={}, params={}):
        """
        Do a REST Get call for a particular node

        :param node: Netwitness REST Node
        :param msg: Operation on REST Node
        :param options: Params to be sent to Node
        :param params: Override Params to be used given by user
        :return:
        """
        _url = self.getBaseURL('/' + node)
        z = {'msg': msg, 'force-content-type': 'text/plain'}
        z.update(options)
        z.update(params)
        return self.session.get(_url, verify=self.server['secure'], proxies=self.proxy, params=z)

    # End of __makeNodeCall

    # Reads the Netwitness SDK Summary
    def __readSummary(self):
        # Make node call
        response = self.__makeNodeCall('sdk', 'summary')

        if response.status_code == 200:

            # Reset Summary
            self.deviceSummary = None

            _s = response.content.decode('utf-8')
            self.deviceSummary = {}

            # Parse the values!
            for x in _s.split():
                _kv = x.split('=', 1)
                self.deviceSummary[_kv[0]] = _kv[1]

    # End of function __readSummary

    # Reads the Meta Information
    def __readMetaLanguages(self):

        # Make node call
        response = self.__makeNodeCall('sdk', 'language', {'size': '1000'})

        if response.status_code == 200:

            # Parse the HTTP Response
            r = NwQueryResponse()
            r.parseFromHttpResponse(response.content.decode('utf-8'))

            # Reset Meta Information
            self.metaInformation = {}

            # Read as Language Response
            meta = r.asSDKLanguageResponse()

            # Populate Meta Information
            for nwm in meta:
                self.metaInformation[nwm.name] = nwm
        return self.metaInformation

    # End of function __readMetaLanguages

    def __executeSDKQuery(self, nwQuery='', size=1000, params={}):
        """
        Fires the SDK Query on the Core Service and reads the response as NwQueryResponse

        :param query: Query String to be sent to Core
        :param size: Size Parameter to be sent to Core
        :param params: Override Parameters
        :return:
        """
        demisto.log('Executing SDK Query : ' + nwQuery)
        response = self.__makeNodeCall('sdk', 'query',
                                       {
                                           'size': str(size),
                                           'query': nwQuery
                                       }, params)
        if response.status_code == 200:
            r = NwQueryResponse()
            r.parseFromHttpResponse(response.content.decode('utf-8', errors='replace'))
            return r
        raise Exception("Error while executing SDK Query with status code [ " + str(response.status_code) + " ] [ "
                        + str(response.content))

    # End of function __executeSDKQuery

    def __executeSDKValues(self, fieldName, where='', size=1000, params={}):
        """
        Fires the SDK Values on the Core Service and reads the response as NwQueryResponse

        :param fieldName: Pivoting Meta Name
        :param where: Query String to be sent to Core
        :param size: Size Parameter to be sent to Core
        :param params: Override Parameters
        :return:
        """
        demisto.log('Executing SDK Values : ' + where)
        response = self.__makeNodeCall('sdk', 'values',
                                       {
                                           'size': str(size),
                                           'fieldName': fieldName,
                                           'where': where
                                       }, params)

        if response.status_code == 200:
            r = NwQueryResponse()
            r.parseFromHttpResponse(response.content.decode('utf-8'))
            return r
        raise Exception("Error while executing SDK Query with status code [ " + response.status_code + " ] [ "
                        + str(response.content))

    # End of function __executeSDKValues

    def __executeSDKMSearch(self, searchString='', where='', searchMeta=True, searchIndex=True, regEx=False,
                            searchRawData=False, caseInsensitive=True, size=1000, maxSession=100000, params={}):
        """
        Fires a M Search on the Core Service

        :param searchString: Text to search
        :param where: Conditional Query
        :param searchMeta: Enabled searching of Meta
        :param searchIndex: Enabled Searching of Index
        :param regEx: Treat search string as RegEx
        :param searchRawData: Search in RAW Logs!
        :param caseInsensitive: Match string without matching case
        :param size: Maximum Results to return
        :param maxSession: Maximum Sessions to be scanned
        :param params: Override Parameters
        :return:
        """

        flags = list()
        if searchIndex:
            flags.append("si")
        if searchMeta:
            flags.append("sm")
        if regEx:
            flags.append("regex")
        if searchRawData:
            flags.append("sp")
        if caseInsensitive:
            flags.append("ci")

        if (len(flags) == 0) or (len(searchString) == 0):
            demisto.log("Invalid Parameters for M Search. Please review the parameters")
            return None
        demisto.log('Executing SDK-MSearch : ' + where + ' with params ' + str(params) + ' search string ' + str(
            searchString))

        response = self.__makeNodeCall('sdk', 'msearch',
                                       {
                                           'search': searchString,
                                           'where': where,
                                           'limit': size,
                                           'flags': ",".join(flags),

                                       }, params)
        if response.status_code == 200:
            r = NwQueryResponse()
            r.parseFromHttpResponse(response.content.decode('utf-8'))
            return r
        raise Exception("Error while executing SDK MSearch with status code [ " + response.status_code + " ] [ "
                        + str(response.content))

    # End of function __executeSDKMSearch

    # Utiliy function to create Where Clause for Single Meta
    def __generateWhereClauseForSingleMeta(self, metaname, value=[], op=NwQueryOperator.EQUALS, searchAll=False):
        """
        Generates the Where Clause for the Meta with multiple values given! The type information for the meta will be
        taken from the Meta Information Map and the quotes will be added accordingly. By default only the Meta Keys
        which are Indexed by Value will be included in the clause. In case meta is not Indexed, empty clause will be
        created. To enable claused for Non-Indexed meta set :searchAll as True

        :param metaname: Meta name to be used
        :param value: List of values to be used
        :param op: Default Operation between Meta and Value
        :param searchAll: Enable clause generation for Non Indexed Meta
        :return:
        """

        if metaname in self.metaInformation and (
                searchAll or self.metaInformation[metaname].getIndexLevel() == NwIndexLevel.INDEX_VALUE):
            if self.metaInformation[metaname].type == NwMetaFormat.nwText:
                _cl = list()
                for v in value:
                    _cl.append(metaname + str(op) + '"' + v + '"')
                return '( ' + " || ".join(_cl) + ' )'
            else:
                return metaname + str(op) + ",".join(value)
        return ''

    # End of function __generateWhereClauseForSingleMeta

    # This function will create the Where Clause for a Multiple Meta and Multiple Values
    def __generateWhereClauseForMultipleMeta(self, meta=[], value=[], op=NwQueryOperator.EQUALS, searchAll=False,
                                             must=False):
        """
        Generates the Where Clause for the lis of Meta and for list of values. All the clauses for Meta are joined by
        OR operator. If :must has been set to True, the AND operator is used

        :param meta: Meta names to be used
        :param value: List of values to be used
        :param op: Default Operation between Meta and Value
        :param searchAll: Enable clause generation for Non Indexed Meta
        :param must When set to True, "AND" is used between the Meta Value operators insted of "OR"
        :return:
        """

        clauses = []

        # Iterate through Meta and generate Where Clause for each of the Meta
        for m in meta:
            wc = self.__generateWhereClauseForSingleMeta(m, value, op, searchAll)
            if len(wc) > 0:
                clauses.append(wc)

        if len(clauses) > 0:
            # Apply correct join operator
            if must:
                return '( ' + " && ".join(clauses) + ' )'
            else:
                return '( ' + " || ".join(clauses) + ' )'
        else:
            return ''

    # End of function __generateWhereClauseForMultipleMeta

    # Executes the SDK Query based on User Input
    def __executeSDKQueryForMetaKeys(self, meta=[], value=[], op=NwQueryOperator.EQUALS, size=1000, searchAll=False,
                                     must=False, startTimeEpoch=-1, endTimeEpoch=-1, params={}):
        """
        Executes the SDK Query for the Set of Meta and values

        :param meta: List of Meta to be used
        :param value: List of Values to be applied
        :param op: Operator to be used between Meta and Value
        :param size: Maximum number of results
        :param searchAll: Enable searching on Non Indexed meta as well
        :param must: Join mutliple Meta Clauses with AND instead of OR
        :param startTimeEpoch: Time Range Size in Minutes
        :param endTimeEpoch: Time Range End Epoch for Query
        :param params: Override Parameters to be sent to Core
        :return:
        """

        # Generate the Query!
        query = self.__generateWhereClauseForMultipleMeta(meta, value, op, searchAll, must)

        # Generate Final Clause
        _cl = "select * where "

        # Get Time range clause
        if query and len(query) > 0:
            _cl = _cl + query + ' && '
        _cl = _cl + ' ' + self.__generateTimeClause(startTimeEpoch, endTimeEpoch)

        # Send Query
        return self.__executeSDKQuery(_cl, size, params)

    # End of function __executeSDKQueryForMetaKeys

    def __executeSDKValuesForMetaKeys(self, fieldName, meta=[], value=[], op=NwQueryOperator.EQUALS, size=1000,
                                      searchAll=False, must=False, startTimeEpoch=-1, endTimeEpoch=-1, params={}):
        """
        Executes the SDK Value for a Single Meta

        :param fieldName: The Meta for which the SDK Values has to be performed
        :param meta: List of Meta to be used
        :param value: List of Values to be applied
        :param op: Operator to be used between Meta and Value
        :param size: Maximum number of results
        :param searchAll: Enable searching on Non Indexed meta as well
        :param must: Join mutliple Meta Clauses with AND instead of OR
        :param startTimeEpoch: Time Range Size in Minutes
        :param endTimeEpoch: Time Range End Epoch for Query
        :param params: Override Parameters to be sent to Core
        :return:
        """

        # Generate the Query!
        query = self.__generateWhereClauseForMultipleMeta(meta, value, op, searchAll, must)

        # Generate Final Clause
        _cl = ""
        if query and len(query) > 0:
            _cl = _cl + query + ' && '
        _cl = _cl + ' ' + self.__generateTimeClause(startTimeEpoch, endTimeEpoch)

        # Send Query
        return self.__executeSDKValues(fieldName, _cl, size, params)

    # End of function __executeSDKValuesForMetaKeys

    def __executeSDKContentCall(self, sessionId=None, renderType=0, params={}):
        """
        Executes the SDK Content Call for the List of Sessions

        :param sessionId: The Session Id to Render
        :param renderType: The render Type Options
        :param params: Override Parameters to be sent to Core
        :return:
        """

        demisto.log('Executing SDK Content call with Session Id : ' + str(sessionId))
        response = self.__makeNodeCall('sdk/content', 'content',
                                       {
                                           'session': sessionId,
                                           'render': renderType
                                       }, params)

        if response.status_code == 200:
            _bytes = response.content
            return _bytes
        raise Exception("Error while executing SDK Content Call with status code [ " + str(response.status_code)
                        + " ] [ " + str(response.content))

    # End of function __executeSDKValuesForMetaKeys

    # Utility function to generate Time Clause
    def __generateTimeClause(self, startTimeEpoch=-1, endTimeEpoch=-1):

        # If past minute is negative. Do not include the time clause
        if startTimeEpoch <= 0 or endTimeEpoch <= 0:
            return ''

        # Generate Time Range!
        _time_clause = 'time="' + time.strftime('%Y-%b-%d %H:%M:%S', time.gmtime(startTimeEpoch)) + '" - '
        _time_clause += '"' + time.strftime('%Y-%b-%d %H:%M:%S', time.gmtime(endTimeEpoch)) + '"'
        return _time_clause

    # #----------------------------------------------------------------------------------------------------------------#
    # # PUBLIC API FOR THE NETWITNESS CORE CLIENT START BELOW. IF YOU WANT TO ADD UTILITY FUNCTION, ADD ABOVE THIS     #
    # # ONLY API FUNCTIONS ARE ALLOWED TO BE DECLARED BELOW THIS LATCH
    # #----------------------------------------------------------------------------------------------------------------#

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This function loads the current Summary and Meta Information from the Server. This is an Overridden Method and
    # # is called via "doLogin" call. All the initial house cleaning stub can be placed here
    # # RETURN: This function is not supposed to return anything
    # #----------------------------------------------------------------------------------------------------------------#
    def start(self):
        self.__readSummary()
        self.__readMetaLanguages()

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This function will return an array of two number representing the First and the Last Session Id available on
    # # the Netwitness Core Service. Before making any Session Specific request, we can use this API to verify if the
    # # session is available on the Core Service or not
    # #----------------------------------------------------------------------------------------------------------------#
    def getSessionIdRange(self):
        self.__readSummary()
        return [int(self.deviceSummary['sid1']), int(self.deviceSummary['sid2'])]

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This function will return an array of two number representing the First and the Last Meta Id available on
    # # the Netwitness Core Service.
    # #----------------------------------------------------------------------------------------------------------------#
    def getMetaIdRange(self):
        self.__readSummary()
        return [int(self.deviceSummary['mid1']), int(self.deviceSummary['mid2'])]

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This function will return an array of two number representing the First and the Last Session Time available on
    # # the Netwitness Core Service.
    # #----------------------------------------------------------------------------------------------------------------#
    def getTimeRange(self):
        self.__readSummary()
        return [int(self.deviceSummary['time1']), int(self.deviceSummary['time2'])]

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # Returns a Dictionary with Key as the Netwitness Meta Name and value as the class NwMeta Object as available on
    # # the Netwitness Core Service.
    # #----------------------------------------------------------------------------------------------------------------#
    def getMetaInformation(self):
        return self.__readMetaLanguages()

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This is most basic API to search Events in Netwitness. It fires the Netwitness Query specified in the argument
    # # directly on the Netwitness Core Service.
    # #
    # # @PARAMS
    # #     nwQuery :   Netwitness query of format [ select <meta1,meta1> where <criteria> ]
    # #     size    :   The maximum number of Events/Sessions to be returned
    # #     params  :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def searchByNwQuery(self, nwQuery='', size=20, params={}, **kwargs):
        return self.__executeSDKQuery(nwQuery, size, params)

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to search Events in Netwitness along with a Simpler Time range. It fires the Netwitness Query
    # # specified in the argument directly on the Netwitness Core Service. The criteria is appended with Disjunction
    # # (&&) before sending the final query to the Core Service
    # #
    # # @PARAMS
    # #     where       :   Netwitness query of format [ select <meta1,meta1> where <criteria> ]
    # #     size        :   The maximum number of Events/Sessions to be returned
    # #     endTimeEpoch:   End of time range. A negative value will take the End Time as Last Session time as available
    # #                     on the Core Service. Default: -1
    # #     startTimeEpoch :   Number of Minutes in the Time Range. Default: 180
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def searchByNwQueryAndTime(self, where='', size=20, endTimeEpoch=-1, startTimeEpoch=-1, params={}, **kwargs):

        # Create Time Clause
        _tClause = self.__generateTimeClause(startTimeEpoch, endTimeEpoch)

        # Collect SessionId
        response = None
        if len(where) > 0:
            response = self.__executeSDKQuery('select sessionid where ( ' + where + ' ) && ' + _tClause, size, params)
        else:
            response = self.__executeSDKQuery('select sessionid where ' + _tClause, size, params)

        # Get Session Ids
        sessionIds = response.asSDKQueryResponse()
        if len(sessionIds) == 0:
            return response

        sessions = list()
        for sid in sessionIds:
            sessions.append(str(sid))
        return self.__executeSDKQuery('select * where sessionid=' + ','.join(sessions), 100000, params)

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to search Events in Netwitness over a set of Meta on a set of Values along with a Simpler Time
    # # range. The query is generated based on the options provided in the arguments
    # #
    # # @PARAMS
    # #     meta        :   List of Netwitness Meta to be searched for
    # #     values      :   List of Values to be searched upon
    # #     op          :   Netwitness Operator to be applied between a meta and a value
    # #     size        :   The maximum number of Events/Sessions to be returned
    # #     must        :   By default the a Single Meta is searched upon a Value and then these criteria are joined
    # #                     by OR Operator (criteria is checking if a Meta in an Event has one of these values matching
    # #                     by Operator provided). In case of Multiple Meta in the arguments, the criteria between Meta
    # #                     is joined by OR, if you want to make this join using "AND", set this value to True.
    # #                     For ex.
    # #                          meta=[ A, B ]; values= [ X , Y] / must = False will yield a query like
    # #                             ( (A = X) || (A = Y) ) || ( (B = X) || (B = Y) )
    # #                          meta=[ A, B ]; values= [ X , Y] / must = True will yield a query like
    # #                             ( (A = X) || (A = Y) ) && ( (B = X) || (B = Y) )
    # #     searchAll   :   By default, all queries will allow queries to be executed over Meta which are Indexed as
    # #                     INDEX_VALUES. If searchAll is set as True, query will allowed to be executed on Non-Indexed
    # #                     Netwitness Meta as well.
    # #                     CAUTION: Searching on Non Indexed Meta caused Heavy Load on Service as the whole databased
    # #                     is scanned instead of Indices
    # #     endTimeEpoch:   End of time range. A negative value will take the End Time as Last Session time as available
    # #                     on the Core Service. Default: -1
    # #     startTimeEpoch :   Number of Minutes in the Time Range. Default: 180
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def searchByMeta(self, meta=[], values=[], op=NwQueryOperator.EQUALS, size=20, must=False, searchAll=False,
                     endTimeEpoch=-1, startTimeEpoch=-1, params={}, **kwargs):
        return self.__executeSDKQueryForMetaKeys(meta, values, op, size, searchAll, must, startTimeEpoch, endTimeEpoch,
                                                 params)

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to read Top Values for Netwitness Meta amoong all Events/Sessions that Matches some criteria. A
    # # simple use case can be as defined as "Search for most visited domains by a user" or "User who visited a domain
    # # the most in last 24 hours"
    # #
    # # @PARAMS
    # #     pivotMeta   :   List of Meta for which the Top Values needs to be calculated
    # #     where     :   Netwitness criteria (query) to filter the sessions
    # #     size        :   The maximum number of Values to be returned. Default: 20
    # #     searchAll   :   By default, all queries will allow queries to be executed over Meta which are Indexed as
    # #                     INDEX_VALUES. If searchAll is set as True, query will allowed to be executed on Non-Indexed
    # #                     Netwitness Meta as well.
    # #                     CAUTION: Searching on Non Indexed Meta caused Heavy Load on Service as the whole databased
    # #                     is scanned instead of Indices
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def topValuesByNwQuery(self, pivotMeta=[], nwQuery='', size=20, searchAll=False, params={}, **kwargs):
        result = {}
        for m in pivotMeta:
            if m in self.metaInformation and (
                    searchAll or self.metaInformation[m].getIndexLevel() == NwIndexLevel.INDEX_VALUE):
                result[m] = self.__executeSDKValues(m, nwQuery, size, params).asSDKValuesResponse()
        return result

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to read Top Values for Netwitness Meta among all Events/Sessions that Matches some criteria
    # # within a Simple Time Range. A simple use case can be "User who visited a domain the most in last 24 hours"
    # #
    # # @PARAMS
    # #     pivotMeta   :   List of Meta for which the Top Values needs to be calculated
    # #     where       :   Netwitness criteria (query) to filter the sessions
    # #     size        :   The maximum number of Values to be returned. Default: 20
    # #     searchAll   :   By default, all queries will allow queries to be executed over Meta which are Indexed as
    # #                     INDEX_VALUES. If searchAll is set as True, query will allowed to be executed on Non-Indexed
    # #                     Netwitness Meta as well.
    # #                     CAUTION: Searching on Non Indexed Meta caused Heavy Load on Service as the whole databased
    # #                     is scanned instead of Indices
    # #     endTimeEpoch:   End of time range. A negative value will take the End Time as Last Session time as available
    # #                     on the Core Service. Default: -1
    # #     startTimeEpoch :   Number of Minutes in the Time Range. Default: 180
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def topValuesByNwQueryAndTime(self, pivotMeta=[], where='', size=20, searchAll=False, endTimeEpoch=-1,
                                  startTimeEpoch=-1, params={}, **kwargs):
        result = {}

        # Time clause
        timeclause = self.__generateTimeClause(startTimeEpoch, endTimeEpoch)

        # Create final clause
        cl = ''
        if len(where) > 0:
            cl = '( ' + where + ' ) && ' + timeclause
        else:
            cl = timeclause

        return self.topValuesByNwQuery(pivotMeta, cl, size, searchAll, params)

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to read Top Values for Netwitness Meta amoong all Events/Sessions that Matches some criteria. A
    # # simple use case can be as defined as "Search for most visited domains by a user" or "User who visited a domain
    # # the most in last 24 hours"
    # #
    # # @PARAMS
    # #     pivotMeta   :   List of Meta for which the Top Values needs to be calculated
    # #     meta        :   List of Netwitness Meta to be searched for
    # #     values      :   List of Values to be searched upon
    # #     op          :   Netwitness Operator to be applied between a meta and a value
    # #     size        :   The maximum number of Values to be returned. Default: 20
    # #     must        :   By default the a Single Meta is searched upon a Value and then these criteria are joined
    # #                     by OR Operator (criteria is checking if a Meta in an Event has one of these values matching
    # #                     by Operator provided). In case of Multiple Meta in the arguments, the criteria between Meta
    # #                     is joined by OR, if you want to make this join using "AND", set this value to True.
    # #                     For ex.
    # #                          meta=[ A, B ]; values= [ X , Y] / must = False will yield a query like
    # #                             ( (A = X) || (A = Y) ) || ( (B = X) || (B = Y) )
    # #                          meta=[ A, B ]; values= [ X , Y] / must = True will yield a query like
    # #                             ( (A = X) || (A = Y) ) && ( (B = X) || (B = Y) )
    # #     searchAll   :   By default, all queries will allow queries to be executed over Meta which are Indexed as
    # #                     INDEX_VALUES. If searchAll is set as True, query will allowed to be executed on Non-Indexed
    # #                     Netwitness Meta as well.
    # #                     CAUTION: Searching on Non Indexed Meta caused Heavy Load on Service as the whole databased
    # #                     is scanned instead of Indices
    # #     endTimeEpoch:   End of time range. A negative value will take the End Time as Last Session time as available
    # #                     on the Core Service. Default: -1
    # #     startTimeEpoch :   Number of Minutes in the Time Range. Default: 180
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def topValuesByMeta(self, pivotMeta=[], meta=[], values=[], op=NwQueryOperator.EQUALS, size=20, must=False,
                        searchAll=False, endTimeEpoch=-1, startTimeEpoch=-1, params={}, **kwargs):
        cl = self.__generateWhereClauseForMultipleMeta(meta, values, op, searchAll, must)
        return self.topValuesByNwQueryAndTime(pivotMeta, cl, size, searchAll, endTimeEpoch, startTimeEpoch, params)

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to search Events/Session which contains a specific string and optionally matches a criteria.
    # #
    # # @PARAMS
    # #     searchString:   The string we are searching for in the Events
    # #     where       :   The Netwitness Query which acts as an additional criteria for filtering Events
    # #     searchMeta  :   If Enabled, Event Meta is also searched for Matching String
    # #     searchIndex :   If Enabled, Indexes created on Meta is also searched for Matching String
    # #     regEx       :   If Enabled, searchString is taken as a RegEx and pattern matching is applied
    # #     searchRawData:  If Enabled, packet data is also searched for String
    # #                     CAUTION: Scanning raw data will take a lot of time and resources on the Core Service
    # #     caseInsensitive:If Enabled, string is matched ignoring the case of the alphabets
    # #     maxSession :   The maximum number of sessions to be searched for string before ending the operation
    # #     size        :   The maximum number of Values to be returned. Default: 20
    # #     endTimeEpoch:   End of time range. A negative value will take the End Time as Last Session time as available
    # #                     on the Core Service. Default: -1
    # #     startTimeEpoch :   Number of Minutes in the Time Range. Default: 180
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def mSearchEventsByNwQuery(self, searchString='', where='', searchMeta=True, searchIndex=True, regEx=False,
                               searchRawData=False, caseInsensitive=True, size=1000, maxSession=100000, params={},
                               **kwargs):
        _response = self.__executeSDKMSearch(searchString, where, searchMeta, searchIndex, regEx,
                                             searchRawData, caseInsensitive, size, maxSession, params)
        _data = _response.result
        sessionIds = list()
        for f in _data:
            sessionIds.append(f.group)
        if len(sessionIds) > 0:

            sessionIds.sort()
            return self.__executeSDKQuery("select * where sessionid=" + ",".join(str(x) for x in sessionIds), size,
                                          params)
        else:
            return None

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to search Events/Session which contains a specific string and optionally matches a criteria and
    # # time range.
    # #
    # # @PARAMS
    # #     searchString:   The string we are searching for in the Events
    # #     where       :   The Netwitness Query which acts as an additional criteria for filtering Events
    # #     searchMeta  :   If Enabled, Event Meta is also searched for Matching String
    # #     searchIndex :   If Enabled, Indexes created on Meta is also searched for Matching String
    # #     regEx       :   If Enabled, searchString is taken as a RegEx and pattern matching is applied
    # #     searchRawData:  If Enabled, packet data is also searched for String
    # #                     CAUTION: Scanning raw data will take a lot of time and resources on the Core Service
    # #     caseInsensitive:If Enabled, string is matched ignoring the case of the alphabets
    # #     maxSession :   The maximum number of sessions to be searched for string before ending the operation
    # #     size        :   The maximum number of Values to be returned. Default: 20
    # #     endTimeEpoch:   End of time range. A negative value will take the End Time as Last Session time as available
    # #                     on the Core Service. Default: -1
    # #     startTimeEpoch :   Number of Minutes in the Time Range. Default: 180
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def mSearchEventsByNwQueryAndTime(self, searchString='', where='', searchMeta=True, searchIndex=True, regEx=False,
                                      searchRawData=False, caseInsensitive=True, size=1000, maxSession=100000,
                                      endTimeEpoch=-1,
                                      startTimeEpoch=-1, params={}, **kwargs):
        cl = self.__generateTimeClause(startTimeEpoch, endTimeEpoch)
        if len(where) > 0:
            cl = '( ' + where + ' ) && ' + cl
        return self.mSearchEventsByNwQuery(searchString, cl, searchMeta, searchIndex, regEx, searchRawData,
                                           caseInsensitive, size, maxSession, params)

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to search Events/Session which contains a specific string and optionally matches a criteria.
    # #
    # # @PARAMS
    # #     searchString:   The string we are searching for in the Events
    # #     query       :   The Netwitness Query which acts as an additional criteria for filtering Events
    # #     searchMeta  :   If Enabled, Event Meta is also searched for Matching String
    # #     searchIndex :   If Enabled, Indexes created on Meta is also searched for Matching String
    # #     regEx       :   If Enabled, searchString is taken as a RegEx and pattern matching is applied
    # #     searchRawData:  If Enabled, packet data is also searched for String
    # #                     CAUTION: Scanning raw data will take a lot of time and resources on the Core Service
    # #     caseInsensitive:If Enabled, string is matched ignoring the case of the alphabets
    # #     maxSession :   The maximum number of sessions to be searched for string before ending the operation
    # #     meta        :   List of Netwitness Meta to be searched for
    # #     values      :   List of Values to be searched upon
    # #     op          :   Netwitness Operator to be applied between a meta and a value
    # #     size        :   The maximum number of Values to be returned. Default: 20
    # #
    # #     must        :   By default the a Single Meta is searched upon a Value and then these criteria are joined
    # #                     by OR Operator (criteria is checking if a Meta in an Event has one of these values matching
    # #                     by Operator provided). In case of Multiple Meta in the arguments, the criteria between Meta
    # #                     is joined by OR, if you want to make this join using "AND", set this value to True.
    # #                     For ex.
    # #                          meta=[ A, B ]; values= [ X , Y] / must = False will yield a query like
    # #                             ( (A = X) || (A = Y) ) || ( (B = X) || (B = Y) )
    # #                          meta=[ A, B ]; values= [ X , Y] / must = True will yield a query like
    # #                             ( (A = X) || (A = Y) ) && ( (B = X) || (B = Y) )
    # #     searchAll   :   By default, all queries will allow queries to be executed over Meta which are Indexed as
    # #                     INDEX_VALUES. If searchAll is set as True, query will allowed to be executed on Non-Indexed
    # #                     Netwitness Meta as well.
    # #                     CAUTION: Searching on Non Indexed Meta caused Heavy Load on Service as the whole databased
    # #                     is scanned instead of Indices
    # #     endTimeEpoch:   End of time range. A negative value will take the End Time as Last Session time as available
    # #                     on the Core Service. Default: -1
    # #     startTimeEpoch :   Number of Minutes in the Time Range. Default: 180
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def mSearchEventsByMeta(self, searchString='', searchMeta=True, searchIndex=True, regEx=False, searchRawData=False,
                            caseInsensitive=True, maxSession=100000, meta=[], values=[], op=NwQueryOperator.EQUALS,
                            size=1000, must=False, searchAll=False, endTimeEpoch=-1, startTimeEpoch=-1, params={},
                            **kwargs):
        # Generate the Query!
        where = self.__generateWhereClauseForMultipleMeta(meta, values, op, searchAll, must)
        return self.mSearchEventsByNwQueryAndTime(searchString, where, searchMeta, searchIndex, regEx, searchRawData,
                                                  caseInsensitive, size, maxSession, endTimeEpoch, startTimeEpoch,
                                                  params)

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This API allows to see details for a list of Session Ids which can be used to see more details about the
    # # sessions
    # #
    # # @PARAMS
    # #     sessionIds  :   The list of Session Ids
    # #     renderType  :   The rendering options for the Sessions
    # #     params      :   A dictionary containing string parameters to be overridden in the request sent to Core
    # #----------------------------------------------------------------------------------------------------------------#
    def renderSessions(self, sessionIds=[], renderType=0, params={}, **kwargs):
        result = dict()
        for sid in sessionIds:
            try:
                result[sid] = self.__executeSDKContentCall(sid, renderType, params)
            except Exception as _error:
                result[sid] = _error
        return result


# #=====================================================================================================================
# #  _____  ______ __  __ _____  _____ _______ ____
# # |  __ \|  ____|  \/  |_   _|/ ____|__   __/ __ \
# # | |  | | |__  | \  / | | | | (___    | | | |  | |
# # | |  | |  __| | |\/| | | |  \___ \   | | | |  | |
# # | |__| | |____| |  | |_| |_ ____) |  | | | |__| |
# # |_____/|______|_|__|_|_____|_____/___|_|  \____/ ______ _____  ______
# # |  _ \|  ____/ ____|_   _| \ | |/ ____|  | |  | |  ____|  __ \|  ____|
# # | |_) | |__ | |  __  | | |  \| | (___    | |__| | |__  | |__) | |__
# # |  _ <|  __|| | |_ | | | | . ` |\___ \   |  __  |  __| |  _  /|  __|
# # | |_) | |___| |__| |_| |_| |\  |____) |  | |  | | |____| | \ \| |____
# # |____/|______\_____|_____|_| \_|_____/   |_|  |_|______|_|  \_\______|
# #
# #=====================================================================================================================


# #
# #=====================================================================================================================
# # UTILITY FUNCTIONS TO BE USED FOR PARSING COMMANDS
# #=====================================================================================================================
# Get time range from User Time Input
def utilParseTimeRange(userInput, endTimeEpoch):
    # Get the input and convert as
    input = userInput.lower()

    # Result Array
    result = list()

    # Now date
    now = datetime.now()

    # RegEx Library
    TR = {
        'YYYY': '\\d{4}',
        'MMM': '(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)',
        '12': '(0[1-9]|1[0-2]|[1-9])',  # Non Zero Month
        '31': '(0[1-9]|[1-2][0-9]|30|31|[1-9])',
        'HYPHEN': '(\\s+-\\s+|\/)',
        '60': '([0-4][0-9]|5[0-9]|[0-9])',
        'SEP': '(\\s+)'
    }

    # Example Date 2018-Jun-12 23:50:50 - 2018-Jun-12 23:59:50
    ISOT1 = TR['YYYY'] + '-' + TR['MMM'] + '-' + TR['31'] + TR['SEP'] + TR['60'] + ':' + TR['60'] + ':' + TR['60']

    # Example Date 2018-06-12 23:50:50 - 2018-06-12 23:59:50
    ISOT2 = TR['YYYY'] + '-' + TR['12'] + '-' + TR['31'] + TR['SEP'] + TR['60'] + ':' + TR['60'] + ':' + TR['60']

    # Jun-12 01:50:50 - Jun-12 23:59:50
    MDHM1 = TR['MMM'] + '-' + TR['31'] + TR['SEP'] + TR['60'] + ':' + TR['60'] + ':' + TR['60']

    # 06-12 01:50:50 - 06-12 23:59:50
    MDHM2 = TR['12'] + '-' + TR['31'] + TR['SEP'] + TR['60'] + ':' + TR['60'] + ':' + TR['60']

    # 01:50:50 - 23:59:50
    HM1 = TR['60'] + ':' + TR['60'] + ':' + TR['60']

    # 1:50 - 23:59
    HM2 = TR['60'] + ':' + TR['60']

    # See if Input Matches Last Patterns!
    if re.compile("^last[0-9]+(m|h|d)$").match(input):
        tp = input.strip("last")
        num = int(re.compile("\\d+").match(tp).group(0))
        if tp.endswith("m"):
            num = num
        elif tp.endswith("h"):
            num = num * 60
        elif tp.endswith("d"):
            num = num * 60 * 24
        else:
            return None
        # Convert Minutes into Seconds!
        num = num * 60
        result.append(endTimeEpoch - num)
        result.append(endTimeEpoch)

    # See if time range is "today"
    elif "today" == input:

        currentEpoch = time.mktime(now.timetuple())
        midnightEpoch = time.mktime(datetime(now.year, now.month, now.day, 0).timetuple())
        result.append(int(midnightEpoch))
        result.append(int(currentEpoch))

    # See if time is "yesterday"
    elif "yesterday" == input:

        currentEpoch = time.mktime(now.timetuple())
        midnightEpoch = time.mktime(datetime(now.year, now.month, now.day, 0).timetuple())
        result.append(int(midnightEpoch))
        result.append(int(currentEpoch))

    elif re.compile(ISOT1 + TR['HYPHEN'] + ISOT1).match(input):
        d1 = re.compile(ISOT1).match(input).group(0)
        input = input.replace(d1, '', 1)
        input = input.replace('-', '', 1)
        d2 = input.strip()
        if re.compile(ISOT1).match(d2) and re.compile(ISOT1).match(d1):
            startDate = datetime.strptime(d1, '%Y-%b-%d %H:%M:%S')
            endDate = datetime.strptime(d2, '%Y-%b-%d %H:%M:%S')
            result.append(int(time.mktime(startDate.timetuple())))
            result.append(int(time.mktime(endDate.timetuple())))
        else:
            # Invalid Date Format. May be a Bug ?
            return None

    elif re.compile(ISOT2 + TR['HYPHEN'] + ISOT2).match(input):
        d1 = re.compile(ISOT2).match(input).group(0)
        input = input.replace(d1, '', 1)
        input = input.replace('-', '', 1)
        d2 = input.strip()
        if re.compile(ISOT2).match(d2) and re.compile(ISOT2).match(d1):
            startDate = datetime.strptime(d1, '%Y-%m-%d %H:%M:%S')
            endDate = datetime.strptime(d2, '%Y-%m-%d %H:%M:%S')
            result.append((int(time.mktime(endDate.timetuple())) - int(time.mktime(startDate.timetuple()))) / 60)
            result.append(int(time.mktime(endDate.timetuple())))
        else:
            # Invalid Date Format. May be a Bug ?
            return None

    elif re.compile(MDHM1 + TR['HYPHEN'] + MDHM1).match(input):
        d1 = re.compile(MDHM1).match(input).group(0)
        input = input.replace(d1, '', 1)
        input = input.replace('-', '', 1)
        d2 = input.strip()
        if re.compile(MDHM1).match(d2) and re.compile(MDHM1).match(d1):
            startDate = datetime.strptime(d1, '%b-%d %H:%M:%S')
            endDate = datetime.strptime(d2, '%b-%d %H:%M:%S')
            startDate = datetime(now.year, startDate.month, startDate.day, startDate.hour, startDate.minute,
                                 startDate.second)
            endDate = datetime(now.year, endDate.month, endDate.day, endDate.hour, endDate.minute,
                               endDate.second)
            result.append(int(time.mktime(startDate.timetuple())))
            result.append(int(time.mktime(endDate.timetuple())))
        else:
            # Invalid Date Format. May be a Bug ?
            return None

    elif re.compile(MDHM2 + TR['HYPHEN'] + MDHM2).match(input):
        d1 = re.compile(MDHM2).match(input).group(0)
        input = input.replace(d1, '', 1)
        input = input.replace('-', '', 1)
        d2 = input.strip()
        if re.compile(MDHM2).match(d2) and re.compile(MDHM2).match(d1):
            startDate = datetime.strptime(d1, '%m-%d %H:%M:%S')
            endDate = datetime.strptime(d2, '%m-%d %H:%M:%S')
            startDate = datetime(now.year, startDate.month, startDate.day, startDate.hour, startDate.minute,
                                 startDate.second)
            endDate = datetime(now.year, endDate.month, endDate.day, endDate.hour, endDate.minute,
                               endDate.second)
            result.append(int(time.mktime(startDate.timetuple())))
            result.append(int(time.mktime(endDate.timetuple())))
        else:
            # Invalid Date Format. May be a Bug ?
            return None

    elif re.compile(HM1 + TR['HYPHEN'] + HM1).match(input):
        d1 = re.compile(HM1).match(input).group(0)
        input = input.replace(d1, '', 1)
        input = input.replace('-', '', 1)
        d2 = input.strip()
        if re.compile(HM1).match(d2) and re.compile(HM1).match(d1):
            startDate = datetime.strptime(d1, '%H:%M:%S')
            endDate = datetime.strptime(d2, '%H:%M:%S')
            startDate = datetime(now.year, now.month, now.day, startDate.hour, startDate.minute,
                                 startDate.second)
            endDate = datetime(now.year, now.month, now.day, endDate.hour, endDate.minute,
                               endDate.second)
            result.append(int(time.mktime(startDate.timetuple())))
            result.append(int(time.mktime(endDate.timetuple())))
        else:
            # Invalid Date Format. May be a Bug ?
            return None

    elif re.compile(HM2 + TR['HYPHEN'] + HM2).match(input):
        d1 = re.compile(HM2).match(input).group(0)
        input = input.replace(d1, '', 1)
        input = input.replace('-', '', 1)
        d2 = input.strip()
        if re.compile(HM2).match(d2) and re.compile(HM2).match(d1):
            startDate = datetime.strptime(d1, '%H:%M')
            endDate = datetime.strptime(d2, '%H:%M')
            startDate = datetime(now.year, now.month, now.day, startDate.hour, startDate.minute, 00)
            endDate = datetime(now.year, now.month, now.day, endDate.hour, endDate.minute, 59)
            result.append(int(time.mktime(startDate.timetuple())))
            result.append(int(time.mktime(endDate.timetuple())))
        else:
            # Invalid Date Format. May be a Bug ?
            return None
    else:
        demisto.log("Invalid Time Range Given. Please see the Documentation for correct formatting of date ranges")
        return None
    return result


# #
# #=====================================================================================================================
# # PING CLIENT AND VERIFY THAT THINGS ARE WORKING AS NEEDED BY ACQUIRING A LOGIN TOKEN
# #=====================================================================================================================
def test_module_command(client, _):
    """
    PING CLIENT AND VERIFY THAT THINGS ARE WORKING AS NEEDED BY ACQUIRING A LOGIN TOKEN
    """
    client.getMetaInformation()
    return 'ok'


# #
# #=====================================================================================================================
# # COMPLETE SET OF ARGUMENTS THAT WILL BE USED IN THE COMMANDS
# #=====================================================================================================================

class NwParams:

    def __init__(self):
        pass

    Size = ('size', 1000)
    NwQuery = ('nwQuery', '')
    Where = ('q', '')
    Time = ('time', '')
    Meta = ('meta', '')
    Values = ('values', '')
    Op = ('op', 'EQUALS')
    Must = ('must', 'False')
    SearchAll = ('searchAll', 'False')
    PivotMeta = ('find', '')
    MSearch = ('text', '')
    SearchInPackets = ('searchInPackets', 'False')
    SearchAsRegEx = ('searchAsRegEx', 'False')
    CaseInSensitive = ('caseInSensitive', 'True')
    MaxSessionsToScan = ('maxSessionsToScan', 100000)
    SessionIds = ('sessionIds', '')
    DetailType = ('renderType', 'AUTO')
    IpSearch = ('ip', '')
    UserSearch = ('user', '')
    DomainSearch = ('domain', '')
    HostSearch = ('host', '')
    ExtractFileToWarRoom = ('getFiles', 'False')
    Params = ('params', '{}')
    ExportType = ('exportType', 'WARROOM')
    ExportAsZip = ('exportAsZip', 'False')


def hasParam(param):
    return param[0] in demisto.args()


def getParam(param):
    return demisto.args().get(param[0]) or param[1]


# #=====================================================================================================================
# # Collect all the parameters into a Dictionary
# #=====================================================================================================================
def process_args(client, args):
    p = {
        'size': int(getParam(NwParams.Size)),
        'nwQuery': getParam(NwParams.NwQuery),
        'where': getParam(NwParams.Where),
        'meta': getParam(NwParams.Meta).split(','),
        'values': getParam(NwParams.Meta).split(r'(?<!\\),'),
        'op': getattr(NwQueryOperator(), getParam(NwParams.Op)),
        'must': (getParam(NwParams.Must) == 'True'),
        'searchAll': (getParam(NwParams.SearchAll) == 'True'),
        'pivotMeta': re.split(r'(?<!\\),', getParam(NwParams.PivotMeta)),
        'searchString': getParam(NwParams.MSearch),
        'searchRaw': (getParam(NwParams.SearchInPackets) == 'True'),
        'regEx': (getParam(NwParams.SearchAsRegEx) == 'True'),
        'caseInsensitive': (getParam(NwParams.CaseInSensitive) == 'True'),
        'maxSession': int(getParam(NwParams.MaxSessionsToScan)),
        'params': {},
        'sessionIds': re.split(r'(?<!\\),', getParam(NwParams.SessionIds)),
        'renderType': int(getattr(NwSessionRenderType(), getParam(NwParams.DetailType))),
        'startTimeEpoch': -1,
        'endTimeEpoch': -1,
        'params': json.loads(getParam(NwParams.Params)),
        'exportType': getParam(NwParams.ExportType).split(r'(?<!\\),'),
    }

    # Collect Time Parameter
    t_param = getParam(NwParams.Time)
    if len(t_param) > 0:
        start_time, end_time = utilParseTimeRange(t_param, client.getTimeRange()[1])
        if start_time and end_time:
            p.update({
                'startTimeEpoch': start_time,
                'endTimeEpoch': end_time,
            })
        else:
            demisto.log('Time range was ommitted as the format was incorrect')

    return p


# #=====================================================================================================================
# # EVENT SEARCH API FOR NETWTTNESS.
# # This API will search for Events in Netwitness and will return the matching sessions for the Query Fired
# #=====================================================================================================================
def nw_events_search_command(client, args):

    if hasParam(NwParams.IpSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['IP'],
            'values': re.split(r'(?<!\\),', getParam(NwParams.IpSearch)),
        })
        c1_results = client.searchByMeta(**args)
    elif hasParam(NwParams.UserSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['USER'],
            'values': re.split(r'(?<!\\),', getParam(NwParams.UserSearch)),
        })
        c1_results = client.searchByMeta(**args)
    elif hasParam(NwParams.HostSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['HOST'],
            'values': re.split(r'(?<!\\),', getParam(NwParams.HostSearch)),
        })
        c1_results = client.searchByMeta(**args)
    elif hasParam(NwParams.DomainSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['DOMAIN'],
            'values': re.split(r'(?<!\\),', getParam(NwParams.DomainSearch)),
        })
        c1_results = client.searchByMeta(**args)
    elif hasParam(NwParams.Where):
        c1_results = client.searchByNwQueryAndTime(**args)
    elif hasParam(NwParams.MSearch):
        c1_results = client.mSearchEventsByNwQueryAndTime(**args)
    elif hasParam(NwParams.Meta) and hasParam(NwParams.Values):
        if hasParam(NwParams.MSearch):
            c1_results = client.mSearchEventsByMeta(**args)
        else:
            c1_results = client.searchByMeta(**args)
    else:
        c1_results = client.searchByNwQueryAndTime(**args)

    # Show results
    if c1_results is not None:
        _response = c1_results.asSDKQueryResponse()
        demisto.results([
            {'ContentsFormat': formats['text'], 'Type': entryTypes['note'],
                'Contents': "Total Number Of Sessions Fetched : " + str(len(c1_results.asSDKQueryResponse()))},
            {'ContentsFormat': formats['json'], 'Type': entryTypes['note'],
                'Contents': _response, 'EntryContext': {'NetwitnessSessions': _response}}
        ])
    else:
        demisto.results("No Data Returned from the Query")

    sys.exit(0)

# #
# #=====================================================================================================================
# # PRINT SUMMARY OF THE CORE SERVICE AS PROVIDED BY THE SDK SUMMARY CALL
# #=====================================================================================================================
def nw_events_info_command(client, args):
    # Rows of Summary Table
    c2_summary = list()

    # Get information
    c2_sid = client.getSessionIdRange()
    c2_mid = client.getMetaIdRange()
    c2_time = client.getTimeRange()
    c2_meta = client.getMetaInformation()

    # Add Session Ids
    c2_summary.append(["Range of Session Ids", c2_sid[0], c2_sid[1]])

    # Add Meta Ids
    c2_summary.append(["Range of Meta Ids", c2_mid[0], c2_mid[1]])

    # Add Time Range in Epoch
    c2_summary.append(["Range of Time (Epoch)", c2_time[0], c2_time[1]])

    # Add Time Range Human Readable
    c2_summary.append(["Range of Time (GMT)", time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(c2_time[0])),
                       time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(c2_time[1]))])

    indexed_meta = list()
    indexed_key_meta = list()
    unindexed_meta = list()
    for _m in c2_meta:
        _meta = c2_meta[_m]
        if _meta.getIndexLevel() == NwIndexLevel.INDEX_VALUE:
            indexed_meta.append(_m)
        elif _meta.getIndexLevel() == NwIndexLevel.INDEX_KEY or _meta.getIndexLevel() == NwIndexLevel.INDEX_KEY_FILTER:
            indexed_meta.append(_m)
        else:
            indexed_meta.append(_m)

    # Sort
    indexed_meta.sort()
    indexed_key_meta.sort()
    unindexed_meta.sort()

    # JSON
    _json = dict()
    _json['INDEX_NONE'] = unindexed_meta
    _json['INDEX_VALUE'] = indexed_meta
    _json['INDEX_KEY'] = indexed_key_meta

    # Add Meta Information
    c2_summary.append(["Meta Indexed By Values", "These Meta are Fastest to Search", len(indexed_meta)])
    c2_summary.append(["Meta Indexed By Keys", "These Meta are Faster to Search", len(indexed_key_meta)])
    c2_summary.append(["Meta Not Indexed", "These Meta are Slow to Search", len(unindexed_meta)])

    # Show results
    demisto.results([
        {'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': c2_summary},
        {'ContentsFormat': formats['json'], 'Type': entryTypes['note'], 'Contents': _json}
    ])

    sys.exit(0)

# #
# #=====================================================================================================================
# # VALUES SEARCH API FOR NETWTTNESS.
# # This API will look up for the Top Values for any Meta under specific criteria and time range
# #=====================================================================================================================
def nw_events_values_command(client, args):

    # Rows of Summary Table
    c3_summary = list()

    if hasParam(NwParams.IpSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['IP'],
            'values': re.split(r'(?<!\\),', getParam(NwParams.IpSearch)),
        })
        c3_results = client.topValuesByMeta(**args)
    elif hasParam(NwParams.UserSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['USER'],
            'values': re.split(r'(?<!\\),', getParam(NwParams.UserSearch)),
        })
        c3_results = client.topValuesByMeta(**args)
    elif hasParam(NwParams.HostSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['HOST'],
            'values': re.split(r'(?<!\\),', getParam(NwParams.HostSearch)),
        })
        c3_results = client.topValuesByMeta(**args)
    elif hasParam(NwParams.DomainSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['DOMAIN'],
            'values': re.split(r'(?<!\\),', getParam(NwParams.DomainSearch)),
        })
        c3_results = client.topValuesByMeta(**args)
    elif hasParam(NwParams.Where):
        c3_results = client.topValuesByNwQueryAndTime(**args)
    else:
        c3_results = client.topValuesByNwQueryAndTime(**args)

    for p in c3_results:
        demisto.log("Total Number Of Unique Values Fetched for Key [ " + p + " ] is " + str(len(c3_results[p])))

    # Show results
    demisto.results({'ContentsFormat': formats['json'], 'Type': entryTypes['note'], 'Contents': c3_results})
    sys.exit(0)


# #
# #=====================================================================================================================
# # SESSION API FOR NETWITNESS.
# # These APIs will act on specific sessions to get details about the session
# #=====================================================================================================================
def nw_events_details_command(client, args):

    if hasParam(NwParams.SessionIds):
        c4_results = client.renderSessions(**args)

    else:
        demisto.log('Need at least one SessionId to execute this command')
        sys.exit(0)

    # Create zip file!
    _zip_bytes = io.BytesIO(bytearray())
    _zip_file = zipfile.ZipFile(_zip_bytes, mode='w')

    # Create directory!
    _zip_dir = tempfile.mkdtemp()

    # Files Written already!
    _zipInfo = list()

    for _r in c4_results:

        # Get RAW Content
        _b_data = c4_results[_r]
        putFileOnWarRoom = (getParam(NwParams.ExtractFileToWarRoom) == 'True')

        if isinstance(_b_data, Exception):

            # See if it is an Exception
            demisto.log("Error occurred while fetching the content for Session [ " + _r + " ] " + _b_data.message)

        else:

            # Check the Render Option Taken
            if getParam(NwParams.DetailType) in ['RAW', 'CSV', 'XML', 'TXT']:

                demisto.log("Collected RAW Bytes for Session [ " + _r + " ] of length : " + str(len(_b_data)))
                _fn = 'nw-content-' + _r + '.' + getParam(NwParams.DetailType).lower()
                demisto.results(fileResult(_fn, _b_data))

            elif ('FILE' == getParam(NwParams.DetailType)):

                # Read file information
                nwiob = NwIoBufferWrapper()
                nwiob.loadFromByteArray(_b_data)

                try:
                    nwcfr = NwContentFileResponse(nwiob)
                    file_results = list()
                    for nwbf in nwcfr.nwfiles:

                        # Save the File On Disk Information
                        fr = fileResult(data=nwbf.data, filename=nwbf.filename)

                        # Append War Room Results as JSON
                        if 'WARROOM' in args['exportType']:

                            file_results.append(fr)

                        # See if we need to Export as Base64
                        if 'BASE64' in args['exportType']:

                            # Creata a JSON Dictionary
                            d = dict()

                            # Set the file name
                            d['filename'] = nwbf.filename
                            # d['base64'] = getBase64Encode(nwbf.data)
                            d['fileId'] = fr['FileID']
                            d['invId'] = demisto.investigation()['id']

                            # Append into the Results!
                            file_results.append({'ContentsFormat': formats['json'], 'Type': entryTypes['note'], 'Contents': d})

                        if 'ZIP' in args['exportType']:

                            # Compute file name!
                            _filename = nwbf.filename

                            if _filename in _zipInfo:
                                _filename = str(len(_zipInfo)) + '_' + _filename

                            # Add into Dictionary!
                            _zipInfo.append(_filename)
                            # demisto.log(_zipInfo)

                            # Path in Temp Dir!
                            _fn = os.path.join(_zip_dir, _filename)

                            # Create file name
                            with open(_fn, 'wb') as file_:
                                file_.write(nwbf.data)

                            # Add to Zip!
                            _zip_file.write(_fn, _filename)

                    demisto.log("Collected Files for Session [ " + _r + " ] with Count " + str(nwcfr.filecount))
                    demisto.results(file_results)
                except Exception as _ex:
                    demisto.log("Error occurred while parsing file data for Session [ " + _r + " ] " + _ex.message)

            else:
                demisto.log("Render Option Not Supported for Session [ " + _r + " ] " + getParam(NwParams.DetailType))

    if 'ZIP' in args['exportType']:
        demisto.results(fileResult(data=_zip_bytes.getvalue(), filename='data.zip'))

    sys.exit(0)


def main():
    # #=====================================================================================================================
    # # COMMON CONFIGURATIONS FOR CLIENTS
    # #=====================================================================================================================

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    commands = {
        'test-module': test_module_command,
        'nw-events-search': nw_events_search_command,
        'nw-events-info': nw_events_info_command,
        'nw-events-values': nw_events_values_command,
        'nw-events-details': nw_events_details_command,
    }

    # #=====================================================================================================================
    # # Client Initialization
    # #=====================================================================================================================

    try:

        # # Create client instances
        client = NwCoreClient(
            params['hostname'],
            params.get('port'),
            params.get('ssl'),
            params.get('secure'),
            params.get('credentials', {}).get('identifier'),
            params.get('credentials', {}).get('password'),
        )
        processed_args = process_args(client, args)

        # Enable System Proxy
        # client.enableProxy()

        # Attempt Login
        client.doLogin()

        if command in commands:
            command_func = commands[command]
            return_results(command_func(client, processed_args))

    except Exception as ex:
        return_error("Test Result Failed with Exception:\n" + str(ex))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


# #=====================================================================================================================
# #   _____ ____  _   _ _______ ______ _   _ _______   ______ _   _ _____   _____   _    _ ______ _____  ______
# #  / ____/ __ \| \ | |__   __|  ____| \ | |__   __| |  ____| \ | |  __ \ / ____| | |  | |  ____|  __ \|  ____|
# # | |   | |  | |  \| |  | |  | |__  |  \| |  | |    | |__  |  \| | |  | | (___   | |__| | |__  | |__) | |__
# # | |   | |  | | . ` |  | |  |  __| | . ` |  | |    |  __| | . ` | |  | |\___ \  |  __  |  __| |  _  /|  __|
# # | |___| |__| | |\  |  | |  | |____| |\  |  | |    | |____| |\  | |__| |____) | | |  | | |____| | \ \| |____
# #  \_____\____/|_| \_|  |_|  |______|_| \_|  |_|    |______|_| \_|_____/|_____/  |_|  |_|______|_|  \_\______|
# #
# #=====================================================================================================================
