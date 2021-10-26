import io
import os
import re
import struct
import tempfile
import time
import zipfile
from datetime import datetime
from typing import Tuple

import requests
from requests.auth import HTTPBasicAuth

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def debug(msg: str):
    demisto.info(f'\n\n{msg}\n\n')


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


# #--------------------------------------------------------------------------------------------------------------------#
# # COMMON CLASSES AND UTILITIES                                                                                       #
# #--------------------------------------------------------------------------------------------------------------------#


class NwConstants:
    """
        Constants to be used in the implementation!
    """

    # URL for Netwitness Admin Server OAuth Token API
    OAUTH_PATH = '/oauth/token'

    # Auth API for Authentication via Integration Server
    INTEGRATION_SERVER_AUTH = '/rest/api/auth/userpass'


# End of NwConstants


class NwIndexLevel:
    """
        Netwitness Meta Key Index Level Constants!
    """
    INDEX_NONE = 1
    INDEX_KEY = 2
    INDEX_VALUE = 3
    INDEX_KEY_FILTER = 4


# End of NwIndexLevel


class NwMetaFormat:
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
    def __init__(self, name, type_, description: str = '', flags: int = 0):
        self.name = name
        self.type = type_
        self.description = description
        self.flags = flags

    # Utility method to get the Index Level out of Flags Value of Meta
    def getIndexLevel(self):
        level = 0x00F & int(self.flags or 0)
        return level


# End of NwMeta


class NwEvent:
    """
        A Simple class encapsulating a Netwitness Event. All the Core APIs returning Netwitness Events will be
        returning list of instance of this class
    """

    # Optional Log for this Event
    rawLog = None

    # Optional Netwitness Basic File Associated with this session
    files = None

    # Constructor
    def __init__(self, sessionId):
        # Netwitness Session Id
        self.sessionId = sessionId

        # The  dictionary containing Meta Value for the Event
        self.meta = dict()


# End of NwEvent


class NwQueryField:
    """
        Class for encapsulating Result Line returned by the Core Service
    """

    # Constructor
    def __init__(self, line: str = ''):
        """
            This constructor will read the line from the Netwitness Query Response and will try to parse information
            There are cases where Broker sends additional lines that describes the Source information about downstream
            devices. We want to skip those line!

                :param line: The Query Response Line as Sent by Core for any SDK Call
        """
        try:
            _temp = line

            # Meta Id 1
            full_match, value = self._extract_field(r'\s*id1=(\d+)', _temp, default_value=0)
            self.id1 = int(value)
            _temp = _temp.replace(full_match, '')

            # Meta Id 2
            full_match, value = self._extract_field(r'\s*id2=(\d+)', _temp, default_value=0)
            self.id2 = int(value)
            _temp = _temp.replace(full_match, '')

            # Count Associated
            full_match, value = self._extract_field(r'\s*count=(\d+)', _temp, default_value=0)
            self.count = int(value)
            _temp = _temp.replace(full_match, '')

            # Integer representing the NwMetaFormat
            full_match, value = self._extract_field(r'\s*format=(\d+)', _temp, default_value=0)
            self.format = int(value)
            _temp = _temp.replace(full_match, '')

            # SessionId if any
            full_match, value = self._extract_field(r'\s*group=(\d+)', _temp, default_value=0)
            self.group = int(value)
            _temp = _temp.replace(full_match, '')

            # Flags if any
            full_match, value = self._extract_field(r'\s*flags=(\d+)', _temp, default_value=0)
            self.flags = int(value)
            _temp = _temp.replace(full_match, '')

            # Meta Type / Name
            full_match, value = self._extract_field(r'\s*type=([a-zA-Z0-9.]+)', _temp)
            self.type = value
            _temp = _temp.replace(full_match, '')

            # Value
            full_match, value = self._extract_field(r'\s*value=(.*)', _temp)
            self.value = value
            _temp = _temp.replace(full_match, '')

        except Exception as exc:
            raise DemistoException(f'Error while parsing query response [{line}]: {exc}', exception=exc)

    @staticmethod
    def _extract_field(regex: str, search_string: str, default_value: Any = None):
        if match := re.search(regex, search_string):
            full_match = match.group(0).strip()
            value = match.group(1).strip()
            return full_match, value
        else:
            return '', default_value


# End of NwQueryField


class NwQueryResponse:
    """
        A Class to hold the SDK Response in a parsed manner
    """

    # Constructor
    def __init__(self):
        self.id1 = 0
        self.id2 = 0
        # List of @NwQueryField that will be rows for each result!
        self.result: List[NwQueryField] = []

    # Wrapper method to read from Plain Text SDK Response
    def parseFromHttpResponse(self, response: str = ''):
        """
            Reads the SDK Response obtained by firing a SDK Request via Netwitness Core Service Rest Interface

            :param response: The HTTP Response from the Netwitness Core Service
        """

        # Split lines on Line Breaks!
        lines = response.splitlines()

        # Iterate thru lines!
        _c = len(lines)
        for index in range(0, _c - 1):

            line = lines[index]
            if line in ('[', ']'):
                continue
            elif line.startswith('['):
                # If line starts with '[' then its ID Range for response
                self.id1 = int(NwQueryField._extract_field(r'\s*id1=(\d+)', line, default_value=0)[1])
                self.id2 = int(NwQueryField._extract_field(r'\s*id2=(\d+)', line, default_value=0)[1])

            else:
                # Else parse it as the Query Response Field
                try:
                    self.result.append(NwQueryField(line))
                except Exception as exc:
                    demisto.error(f'Ignored an error while parsing a response. Error: {exc}')

    # End of Function parseFromHttpResponse

    @logger
    def asSDKQueryResponse(self):
        """
            Parses the Query Response as SDK Query Events grouped by Session Ids

            :return: a dictionary containing a map from Session Ids to NwEvent parsed from Response
        """
        # data is a mapping of session IDs to mapping of NwEvent objects:
        # {
        #     <Session ID>: {
        #         <Query Type>: [<list of values>],
        #     }
        # }
        data: Dict[int, Dict] = {}
        for f in self.result:
            data.setdefault(f.group, {}).setdefault(f.type, []).append(f.value)

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
            nwm = NwMeta(n.type, n.format, flags=n.flags)
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
    def loadFromFile(self, filepath: str):
        """
        Reads the file as Byte Array!

        :param filepath: Location of file in File System
        :return:
        """
        self.loadFromByteArray(bytearray(open(filepath, 'rb').read()))

    # End of function loadFromFile

    def loadFromByteArray(self, byte_array: bytearray):
        """
        Loads Buffer with the Byte Array

        :param byte_array: bytearray to be supplied by script!
        :return:
        """
        self.content = bytearray(byte_array)
        self.maximum = len(self.content)

    # End of function loadFromByteArray

    def readBytesOfSize(self, size: int):
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
            return int(struct.unpack("<L", self.readBytesOfSize(4))[0])
        else:
            return int(struct.unpack(">L", self.readBytesOfSize(4))[0])

    # End of function readUnsignedInt

    def readStringOfSize(self, size: int):
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

    def readLine(self, crlf: bool = False):
        """
        Reads the byte array as Integer and then string of that length
        :return:
        """
        array = bytearray()
        array.extend(self.readBytesOfSize(2))
        if crlf:
            while not array.endswith(br'\r\n'):
                array.extend(self.readBytesOfSize(1))
        else:
            while not array.endswith(br'\n'):
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

    def __init__(self, ioBuffer: NwIoBufferWrapper):

        # Read Number of Parameters!
        numberOfParams = ioBuffer.readUnsignedInt()

        if numberOfParams <= 0 or numberOfParams > 32:
            raise Exception(
                "Number of parameters in the Headers is [ " + str(numberOfParams) + " ] not in range [1,32]")

        self.values = {}
        # Read those number of parameters
        for index in range(numberOfParams):
            # Read Parameter Key
            key = ioBuffer.readString()

            # Read Parameter Value
            value = ioBuffer.readString()
            self.values[key] = value

    # End of Init

    def get(self, key: str) -> str:
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

    def __init__(self, ioBuffer: NwIoBufferWrapper):
        self.nwfiles: List[NwBaseFile] = []

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
    def __init__(self, host: str, port: str, username: str, password: str, proxy: Optional[Dict] = None,
                 ssl: bool = True, secure: bool = True):
        """
        :param host: The host name or IP Address of the Server where Service is running
        :param port: Port on which Service is listening
        :param username: Service Username
        :param password: Service Password
        :param ssl: Use SSL Connection to connect
        :param secure: Validate the Certificate in case of SSL ENabled
        :return:
        """
        # URL
        if ssl:
            self.url = f'https://{host}:{port}'
        else:
            self.url = f'http://{host}:{port}'

        # SSL validation
        self.secure = secure

        # Proxy
        self.proxy = proxy

        # Credentials
        self.credentials = {
            'username': username,
            'password': password,
        }

        # Token
        self.token = ''

        # Session
        self.session = requests.Session()

        # Meta Information
        self.metaInformation: Dict[str, NwMeta] = {}

    def getBaseURL(self, path: str):
        return self.url + path

    @abstractmethod
    def doLogin(self):  # pragma: no cover
        """
            Authenticate to the Server based on the object settings.
            :return:
        """
        pass

    @abstractmethod
    def start(self):  # pragma: no cover
        """
            A method to be overridden by Client Implementations to initiate the post authentication steps
        :return:
        """
        return None


# #--------------------------------------------------------------------------------------------------------------------#
# # NETWITNESS CORE SERVICE CLIENT                                                                                     #
# #--------------------------------------------------------------------------------------------------------------------#

class NwCoreClient(NwClient):
    # Constructor
    def __init__(self, host: str, port: str, uname: str, pwd: str, proxy: Dict, ssl: bool, secure: bool):
        super().__init__(host, port, uname, pwd, proxy=proxy, ssl=ssl, secure=secure)
        self.device_summary = dict()

    # End of constructor

    def doLogin(self):
        """
            Creates a session with Netwitness Core Server REST API Server
        """
        # default headers for HTTP Request to be sent to the Netwitness Server for getting Auth Token
        httpHeaders = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=ISO-8859-1',
            'Accept': 'application/json; charset=UTF-8',
            'NetWitness-Version': "11.1.0.0",
            "Authorization": "Basic bndfdWk6"
        }

        response = requests.get(self.url,
                                headers=httpHeaders,
                                verify=self.secure,
                                proxies=self.proxy,
                                auth=HTTPBasicAuth(self.credentials['username'], self.credentials['password'])
                                )

        # successful get_token
        if response.status_code == 200:
            self.token = response.json()
            self.session.auth = HTTPBasicAuth(self.credentials['username'], self.credentials['password'])
            self.start()
            return

        # bad request - NetWitness returns a common json structure for errors
        raise ValueError('Error in Authenticating to Core Server with Status: {}'.format(response.status_code))

    # End of function doLogin

    # REST Call Method
    @logger
    def __makeNodeCall(self, node: str, msg: str, options: dict = None, params: dict = None):
        """
        Do a REST Get call for a particular node

        :param node: Netwitness REST Node
        :param msg: Operation on REST Node
        :param options: Params to be sent to Node
        :param params: Override Params to be used given by user
        :return:
        """
        options = options or {}
        params = params or {}
        _url = self.getBaseURL('/' + node)
        z = {'msg': msg, 'force-content-type': 'text/plain'}
        z.update(options)
        z.update(params)

        return self.session.get(_url, verify=self.secure, proxies=self.proxy, params=z)

    # End of __makeNodeCall

    # Reads the Netwitness SDK Summary
    def __readSummary(self):
        # Make node call
        response = self.__makeNodeCall('sdk', 'summary')

        if response.status_code == 200:

            # Reset Summary
            self.device_summary = {}

            _s = response.content.decode('utf-8')

            # Parse the values!
            for x in _s.split():
                _kv = x.split('=', 1)
                self.device_summary[_kv[0]] = _kv[1]

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

    @logger
    def __executeSDKQuery(self, nwQuery='', size=1000, params=None):
        """
        Fires the SDK Query on the Core Service and reads the response as NwQueryResponse

        :param query: Query String to be sent to Core
        :param size: Size Parameter to be sent to Core
        :param params: Override Parameters
        :return:
        """
        params = params or {}
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

    @logger
    def __executeSDKValues(self, fieldName, where='', size=1000, params={}):
        """
        Fires the SDK Values on the Core Service and reads the response as NwQueryResponse

        :param fieldName: Pivoting Meta Name
        :param where: Query String to be sent to Core
        :param size: Size Parameter to be sent to Core
        :param params: Override Parameters
        :return:
        """
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
        raise Exception("Error while executing SDK Values Query with status code [ " + response.status_code + " ] [ "
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
    @logger
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
        return [int(self.device_summary['sid1']), int(self.device_summary['sid2'])]

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This function will return an array of two number representing the First and the Last Meta Id available on
    # # the Netwitness Core Service.
    # #----------------------------------------------------------------------------------------------------------------#
    def getMetaIdRange(self):
        self.__readSummary()
        return [int(self.device_summary['mid1']), int(self.device_summary['mid2'])]

    # #
    # #----------------------------------------------------------------------------------------------------------------#
    # # @PUBLIC
    # #
    # # This function will return an array of two number representing the First and the Last Session Time available on
    # # the Netwitness Core Service.
    # #----------------------------------------------------------------------------------------------------------------#
    def getTimeRange(self):
        self.__readSummary()
        return [int(self.device_summary['time1']), int(self.device_summary['time2'])]

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
    @logger
    def searchByNwQueryAndTime(self, where='', size=20, endTimeEpoch=-1, startTimeEpoch=-1, params=None, **kwargs):
        params = params or {}

        # Create Time Clause
        _tClause = self.__generateTimeClause(startTimeEpoch, endTimeEpoch)

        # Collect SessionId
        response = None
        if len(where) > 0:
            response = self.__executeSDKQuery(f'select sessionid where ( {where} ) && {_tClause}', size, params)
        else:
            response = self.__executeSDKQuery(f'select sessionid where {_tClause}', size, params)

        # Get Session Ids
        sessionIds = response.asSDKQueryResponse()
        if not sessionIds:
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
        # Time clause
        timeclause = self.__generateTimeClause(startTimeEpoch, endTimeEpoch)

        # Create final clause
        cl = ''
        if len(where) > 0:
            cl = '( ' + where + ' ) && ' + timeclause
        else:
            cl = timeclause

        return self.topValuesByNwQuery(pivotMeta, cl, size, searchAll, params, **kwargs)

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
        return self.topValuesByNwQueryAndTime(pivotMeta, cl, size, searchAll, endTimeEpoch, startTimeEpoch, params, **kwargs)

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
                                           caseInsensitive, size, maxSession, params, **kwargs)

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
                                                  params, **kwargs)

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
        _ = kwargs  # ignoring extra arguments
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
def get_time_range(time_frame=None, start_time=None, end_time=None):
    if time_frame is None:
        return None, None

    time_frame = time_frame.lower()
    now = datetime.now()

    if time_frame == 'custom':
        if start_time is None and end_time is None:
            raise ValueError('invalid custom time frame: need to specify one of start_time, end_time')

        if start_time is None:
            start_time = now
        else:
            start_time = dateparser.parse(start_time)

        if end_time is None:
            end_time = now
        else:
            end_time = dateparser.parse(end_time)

        return date_to_timestamp(start_time) / 1000, date_to_timestamp(end_time) / 1000

    end_time = now
    if time_frame == 'today':
        start_time = now.date()

    elif time_frame == 'yesterday':
        start_time = (end_time - timedelta(days=1)).date()

    elif 'last' in time_frame:
        start_time = dateparser.parse(time_frame.replace('last', ''))
    else:
        raise ValueError('Could not parse time frame: {}'.format(time_frame))

    return date_to_timestamp(start_time) / 1000, date_to_timestamp(end_time) / 1000


def utilParseTimeRange(userInput: str, endTimeEpoch: int):
    # Get the input and convert as
    input = userInput.lower()

    # Result Array
    result = list()

    # Now date
    now = datetime.now()

    # RegEx Library
    TR = {
        'YYYY': r'\d{4}',
        'MMM': '(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)',
        '12': '(0?[1-9]|1[0-2])',  # Non Zero Month
        '31': '(0?[1-9]|[1-2][0-9]|30|31)',
        'HYPHEN': r'(\s+-\s+|/)',
        '60': '([0-5]?[0-9])',
        'SEP': r'(\s+)'
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
        result.append(int(endTimeEpoch) - num)
        result.append(int(endTimeEpoch))

    # See if time range is "today"
    elif "today" == input:

        currentEpoch = time.mktime(now.timetuple())
        midnightEpoch = time.mktime(now.date().timetuple())
        result.append(int(midnightEpoch))
        result.append(int(currentEpoch))

    # See if time is "yesterday"
    elif "yesterday" == input:

        currentEpoch = time.mktime(now.timetuple())
        midnightEpoch = time.mktime((now.date() - timedelta(days=1)).timetuple())
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
            result.append(int(time.mktime(startDate.timetuple())))
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
        raise DemistoException("Invalid Time Range Given. Please see the Documentation for correct formatting of date ranges.")

    return result


# #
# #=====================================================================================================================
# # COMPLETE SET OF ARGUMENTS THAT WILL BE USED IN THE COMMANDS
# #=====================================================================================================================

class NwParams:
    Time = ('time', '')
    TimeFrame = ('time_frame', '')
    StartTime = ('start_time', '')
    EndTime = ('end_time', '')

    Size = ('size', 1000)
    Where = ('query', '')
    Meta = ('meta', '')  # add to yml
    Values = ('values', '')  # add to yml
    Operation = ('operation', 'EQUALS')
    Must = ('must', 'False')
    # SearchAll = ('searchAll', 'False')
    PivotMeta = ('find', '')
    MSearch = ('text', '')
    # SearchInPackets = ('searchInPackets', 'False')
    # SearchAsRegEx = ('searchAsRegEx', 'False')
    # CaseInSensitive = ('caseInSensitive', 'True')
    # MaxSessionsToScan = ('maxSessionsToScan', 100000)
    SessionIds = ('sessionIds', '')
    DetailType = ('renderType', 'AUTO')
    IpSearch = ('ip', '')
    UserSearch = ('user', '')
    DomainSearch = ('domain', '')
    HostSearch = ('host', '')
    Params = ('params', '{}')
    ExportType = ('exportType', 'WARROOM')
    # ExtractFileToWarRoom = ('getFiles', 'False')
    # ExportAsZip = ('exportAsZip', 'False')


def hasParam(args, param):
    return args.get(param[0])


def getParam(args, param: Tuple[str, Any]):
    return args.get(param[0]) or param[1]


# #=====================================================================================================================
# # Collect all the parameters into a Dictionary
# #=====================================================================================================================
def process_args(client: NwCoreClient, args):
    p = {
        'size': int(getParam(args, NwParams.Size)),
        # 'nwQuery': getParam(args, NwParams.NwQuery),
        'where': getParam(args, NwParams.Where),
        'meta': argToList(getParam(args, NwParams.Meta)),
        'values': argToList(getParam(args, NwParams.Meta)),
        'op': getattr(NwQueryOperator, getParam(args, NwParams.Operation)),
        'must': (getParam(args, NwParams.Must) == 'True'),
        # 'searchAll': (getParam(args, NwParams.SearchAll) == 'True'),
        'pivotMeta': re.split(r'(?<!\\),', getParam(args, NwParams.PivotMeta)),
        'searchString': getParam(args, NwParams.MSearch),
        # 'searchRaw': (getParam(args, NwParams.SearchInPackets) == 'True'),
        # 'regEx': (getParam(args, NwParams.SearchAsRegEx) == 'True'),
        # 'caseInsensitive': (getParam(args, NwParams.CaseInSensitive) == 'True'),
        # 'maxSession': int(getParam(args, NwParams.MaxSessionsToScan)),
        'sessionIds': re.split(r'(?<!\\),', getParam(args, NwParams.SessionIds)),
        'renderType': int(getattr(NwSessionRenderType, getParam(args, NwParams.DetailType))),
        'params': json.loads(getParam(args, NwParams.Params)),
        'exportType': getParam(args, NwParams.ExportType).split(r'(?<!\\),'),
        'startTimeEpoch': -1,
        'endTimeEpoch': -1,
    }

    # Collect Time Parameter
    start_time, end_time = get_time_range(
        time_frame=getParam(args, NwParams.TimeFrame),
        start_time=getParam(args, NwParams.StartTime),
        end_time=getParam(args, NwParams.EndTime),
    )
    demisto.info(f'new - date params: {start_time} - {end_time}')
    if start_time and end_time:
            p.update({
                'startTimeEpoch': start_time,
                'endTimeEpoch': end_time,
            })
    t_param = getParam(args, NwParams.Time)
    if t_param:
        start_time, end_time = utilParseTimeRange(t_param, client.getTimeRange()[1])
        demisto.info(f'old - date params: {start_time} - {end_time}')
        # if start_time and end_time:
        #     p.update({
        #         'startTimeEpoch': start_time,
        #         'endTimeEpoch': end_time,
        #     })

    return p


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


# #=====================================================================================================================
# # EVENT SEARCH API FOR NETWTTNESS.
# # This API will search for Events in Netwitness and will return the matching sessions for the Query Fired
# #=====================================================================================================================
def nw_events_search_command(client: NwCoreClient, args):

    if hasParam(args, NwParams.IpSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['IP'],
            'values': re.split(r'(?<!\\),', getParam(args, NwParams.IpSearch)),
        })
        results = client.searchByMeta(**args)

    elif hasParam(args, NwParams.UserSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['USER'],
            'values': re.split(r'(?<!\\),', getParam(args, NwParams.UserSearch)),
        })
        results = client.searchByMeta(**args)

    elif hasParam(args, NwParams.HostSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['HOST'],
            'values': re.split(r'(?<!\\),', getParam(args, NwParams.HostSearch)),
        })
        results = client.searchByMeta(**args)

    elif hasParam(args, NwParams.DomainSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['DOMAIN'],
            'values': re.split(r'(?<!\\),', getParam(args, NwParams.DomainSearch)),
        })
        results = client.searchByMeta(**args)

    elif hasParam(args, NwParams.Where):
        results = client.searchByNwQueryAndTime(**args)

    elif hasParam(args, NwParams.MSearch):
        results = client.mSearchEventsByNwQueryAndTime(**args)

    elif hasParam(args, NwParams.Meta) and hasParam(args, NwParams.Values):
        if hasParam(args, NwParams.MSearch):
            results = client.mSearchEventsByMeta(**args)
        else:
            results = client.searchByMeta(**args)

    else:
        results = client.searchByNwQueryAndTime(**args)

    # Show results
    if results is not None:
        response = results.asSDKQueryResponse()
        processed_results = []
        for record in response.values():
            processed_record = {}
            for key, value in record.items():
                new_key = key.replace('.', '_')
                processed_record[new_key] = value

            processed_results.append(processed_record)

        return CommandResults(
            readable_output=tableToMarkdown(
                'Sessions',
                processed_results,
                metadata=f'Total Number Of Sessions Fetched : {len(processed_results)}',
                headers=['sessionid', 'time', 'event_source', 'event_desc'],
                headerTransform=string_to_table_header,
            ),
            outputs=processed_results,
            outputs_prefix='NetwitnessSessions',
            outputs_key_field='sessionid',
            raw_response=response,
        )
    else:
        return 'No Data Returned from the Query.'


# #
# #=====================================================================================================================
# # PRINT SUMMARY OF THE CORE SERVICE AS PROVIDED BY THE SDK SUMMARY CALL
# #=====================================================================================================================
def nw_events_info_command(client: NwCoreClient, args):
    # Get information
    c2_sid = client.getSessionIdRange()
    c2_mid = client.getMetaIdRange()
    c2_time = client.getTimeRange()
    c2_meta = client.getMetaInformation()

    range_summary = [
        # Add Session Ids
        {
            'Range': 'Range of Session Ids',
            'Start Range': c2_sid[0],
            'End Range': c2_sid[1],
        },
        # Add Meta Ids
        {
            'Range': 'Range of Meta Ids',
            'Start Range': c2_mid[0],
            'End Range': c2_mid[1],
        },
        # Add Time Range in Epoch
        {
            'Range': 'Range of Time (seconds since Epoch)',
            'Start Range': c2_time[0],
            'End Range': c2_time[1],
        },
        # Add Time Range Human Readable
        {
            'Range': 'Range of Time (GMT)',
            'Start Range': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(c2_time[0])),
            'End Range': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(c2_time[1])),
        },
    ]

    indexed_meta = []
    indexed_key_meta = []
    unindexed_meta = []
    for _m, _meta in c2_meta.items():
        if _meta.getIndexLevel() == NwIndexLevel.INDEX_VALUE:
            indexed_meta.append(_m)
        elif _meta.getIndexLevel() == NwIndexLevel.INDEX_KEY or _meta.getIndexLevel() == NwIndexLevel.INDEX_KEY_FILTER:
            indexed_key_meta.append(_m)
        else:
            unindexed_meta.append(_m)

    # Sort
    indexed_meta.sort()
    indexed_key_meta.sort()
    unindexed_meta.sort()

    # Add Meta Information
    performance_summary = [
        {
            'Range Type': 'Meta Not Indexed',
            'Description': 'These Meta are Slow to Search',
            'Count': len(unindexed_meta),
            'Meta': unindexed_meta,
        },
        {
            'Range Type': 'Meta Indexed By Keys',
            'Description': 'These Meta are Faster to Search',
            'Count': len(indexed_key_meta),
            'Meta': indexed_key_meta,
        },
        {
            'Range Type': 'Meta Indexed By Values',
            'Description': 'These Meta are Fastest to Search',
            'Count': len(indexed_meta),
            'Meta': indexed_meta,
        },
    ]

    # Show results
    return [
        CommandResults(
            readable_output=tableToMarkdown('', range_summary, headers=['Range', 'Start Range', 'End Range']),
            raw_response=range_summary,
        ),
        CommandResults(
            readable_output=tableToMarkdown('', performance_summary, headers=['Range Type', 'Description', 'Count', 'Meta']),
            raw_response=performance_summary,
        ),
    ]


# #
# #=====================================================================================================================
# # VALUES SEARCH API FOR NETWTTNESS.
# # This API will look up for the Top Values for any Meta under specific criteria and time range
# #=====================================================================================================================
def nw_events_values_command(client, args):
    if hasParam(args, NwParams.IpSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['IP'],
            'values': re.split(r'(?<!\\),', getParam(args, NwParams.IpSearch)),
        })
        c3_results = client.topValuesByMeta(**args)
    elif hasParam(args, NwParams.UserSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['USER'],
            'values': re.split(r'(?<!\\),', getParam(args, NwParams.UserSearch)),
        })
        c3_results = client.topValuesByMeta(**args)
    elif hasParam(args, NwParams.HostSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['HOST'],
            'values': re.split(r'(?<!\\),', getParam(args, NwParams.HostSearch)),
        })
        c3_results = client.topValuesByMeta(**args)
    elif hasParam(args, NwParams.DomainSearch):
        args.update({
            'meta': NwQueryMetaMappingConfig['DOMAIN'],
            'values': re.split(r'(?<!\\),', getParam(args, NwParams.DomainSearch)),
        })
        c3_results = client.topValuesByMeta(**args)
    elif hasParam(args, NwParams.Where):
        c3_results = client.topValuesByNwQueryAndTime(**args)
    else:
        c3_results = client.topValuesByNwQueryAndTime(**args)

    for p in c3_results:
        demisto.log(r'Total Number Of Unique Values Fetched for Key [{p}] is {len(c3_results[p])}')

    # Show results
    return CommandResults(raw_response=c3_results)
    # return {'ContentsFormat': formats['json'], 'Type': entryTypes['note'], 'Contents': c3_results}


# #
# #=====================================================================================================================
# # SESSION API FOR NETWITNESS.
# # These APIs will act on specific sessions to get details about the session
# #=====================================================================================================================
def nw_events_details_command(client: NwCoreClient, args):

    if hasParam(args, NwParams.SessionIds):
        c4_results = client.renderSessions(**args)
    else:
        return 'Need at least one SessionId to execute this command.'

    # Create zip file!
    _zip_bytes = io.BytesIO(bytearray())
    _zip_file = zipfile.ZipFile(_zip_bytes, mode='w')

    # Create directory!
    _zip_dir = tempfile.mkdtemp()

    # Files Written already!
    _zipInfo = []

    for _r in c4_results:

        # Get RAW Content
        _b_data = c4_results[_r]
        # putFileOnWarRoom = (getParam(args, NwParams.ExtractFileToWarRoom) == 'True')

        if isinstance(_b_data, Exception):

            # See if it is an Exception
            demisto.log(f'Error occurred while fetching the content for Session [ {_r} ] {_b_data}')

        else:

            # Check the Render Option Taken
            if getParam(args, NwParams.DetailType) in ['RAW', 'CSV', 'XML', 'TXT']:

                demisto.log("Collected RAW Bytes for Session [ " + _r + " ] of length : " + str(len(_b_data)))
                _fn = 'nw-content-' + _r + '.' + getParam(args, NwParams.DetailType).lower()
                return_results(fileResult(_fn, _b_data))

            elif ('FILE' == getParam(args, NwParams.DetailType)):

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

                    return [
                        f'Collected Files for Session [{_r}] with Count {nwcfr.filecount}',
                        file_results,
                    ]
                except Exception as exc:
                    demisto.log(f'Error occurred while parsing file data for Session [{_r}] {exc}')

            else:
                demisto.log("Render Option Not Supported for Session [ " + _r + " ] " + getParam(args, NwParams.DetailType))

    if 'ZIP' in args['exportType']:
        demisto.results(fileResult(data=_zip_bytes.getvalue(), filename='data.zip'))


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
            params.get('hostname'),
            params.get('port'),
            params.get('credentials', {}).get('identifier'),
            params.get('credentials', {}).get('password'),
            handle_proxy(),
            params.get('ssl'),
            params.get('secure'),
        )
        # Attempt Login
        client.doLogin()
        processed_args = process_args(client, args)

        demisto.info(f'\n\ndates:\n{client.getTimeRange()}\n\n')

        if command in commands:
            command_func = commands[command]
            return_results(command_func(client, processed_args))

    except Exception as exc:
        return_error(f'Failed to run the {command} command. Error:\n{exc}', error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
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
