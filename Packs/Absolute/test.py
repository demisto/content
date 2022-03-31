import sys, hashlib, hmac, urllib
import requests  # pip install requests
from datetime import datetime

# ************* REQUEST VALUES *************
method = 'GET'
service = 'abs1'
host = 'api.absolute.com'
region = 'cadc'
endpoint = 'https://api.absolute.com'
request_parameters = "$filter=substringof('e93f2464-2766-4a6b-8f00-66c8fb13e23a'," \
                     "deviceUid)&$select=id,esn,domain,lastConnectedUtc,systemName," \
                     "systemModel,systemType,fullSystemName,agentStatus,os.name,os.version,os.currentBuild,os.architecture,os.installDate,os.productKey,os.serialNumber,os.lastBootTime,systemManufacturer,serial,localIp,publicIp,username,espInfo.encryptionStatus,bios.id,bios.serialNumber,bios.version,bios.versionDate,bios.smBiosVersion,policyGroupUid,policyGroupName,isStolen,deviceStatus.type,deviceStatus.reported,networkAdapters.networkSSID"
canonical_querystring = ""


# Key derivation functions.
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp):
    kDate = sign(('ABS1' + key).encode('utf-8'), dateStamp)
    kSigning = sign(kDate, 'abs1_request')
    return kSigning


# Best practice is NOT to embed credentials in code.
access_key = 'c83693ad-06b0-45b9-a232-825f2ba1ea54'
secret_key = 'dnNv/Fzl7uGwv73meEue/wWJTtYy1cqf0FKKk7DXNiB3gItsCefWrZDssilxeYhc+VFN+i2D4fo/6s84GbQ1eQ=='

if access_key is None or secret_key is None:
    print('No access key is available.')
    sys.exit()

# Create a date for headers and the credential string
t = datetime.utcnow()
absdate = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

# ************* TASK 1: CREATE A CANONICAL REQUEST *************

# Step 1 is to define the verb (GET, POST, etc.)
# Already done with "Method" set to GET above.


# Step 2: Create canonical URI--the part of the URI from domain to query
# string (use '/' if no path)
canonical_uri = '/v2/reporting/devices'
endpoint = endpoint + canonical_uri

# Step 3: Create the canonical query string. In this example (a GET request),
# request parameters are in the query string. Query string values must
# be URL-encoded (space=%20). The parameters must be sorted by name.
# For this example, the query string is pre-formatted in the request_parameters variable.
canonical_querystring = urllib.parse.quote(request_parameters, safe='=&')

# Step 4: Create the canonical headers and signed headers. Header names
# must be trimmed and lowercase, and sorted in code point order from
# low to high. Note that there is a trailing \n.
canonical_headers = 'host:' + host + '\n' + 'content-type:application/json' + '\n' + 'x-abs-date:' + absdate

# Step 5: Create the list of signed headers. This lists the headers
# in the canonical_headers list, delimited with ";" and in alpha order.
# Note: The request can include any headers; canonical_headers and
# signed_headers lists those that you want to be included in the
# hash of the request. "Host" and "x-amz-date" are always required.
signed_headers = 'host;content-type;x-abs-date'


# Step 6: Create payload hash (hash of the request body content). For GET
# requests, the payload is an empty string ("").
# payload = [{'deviceUid': device_id} for device_id in device_ids]
# payload = json.dumps([{'deviceUid': 'e93f2464-2766-4a6b-8f00-66c8fb13e23a'}])
payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()

# Step 7: Combine elements to create canonical request
canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + payload_hash

# ************* TASK 2: CREATE THE STRING TO SIGN*************
# Match the algorithm to the hashing algorithm you use, either SHA-1 or
# SHA-256 (recommended)
algorithm = 'ABS1-HMAC-SHA-256'
credential_scope = datestamp + '/' + region + '/' + service
string_to_sign = algorithm + '\n' + absdate + '\n' + credential_scope + '\n' + hashlib.sha256(
    canonical_request.encode('utf-8')).hexdigest()

# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Create the signing key using the function defined above.
signing_key = getSignatureKey(secret_key, datestamp)

# Sign the string_to_sign using the signing_key
signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
# The signing information can be either in a query string value or in
# a header named Authorization. This code shows how to use a header.
# Create authorization header and add to request headers
authorization_header = algorithm + ' ' + 'Credential=' + access_key\
                       + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers\
                       + ', ' + 'Signature=' + signature

# The request can include any headers, but MUST include "host", "x-abs-date",
# and (for this scenario) "Authorization". "host" and "x-abs-date" must
# be included in the canonical_headers and signed_headers, as noted
# earlier. Order here is not significant.
# Python note: The 'host' header is added automatically by the Python 'requests' library.
headers = {'x-abs-date': absdate, 'content-type': 'application/json', 'Authorization': authorization_header}

# ************* SEND THE REQUEST *************
request_url = endpoint + '?' + canonical_querystring

print('Canonical Headers')
print(canonical_headers)
print('\n')
print('Canonical Request')
print(canonical_request)
print('\n')
print('Request URL')
print(request_url)
print('\n')
print('Signed Headers')
print(signed_headers)
print('\n')
print('String to Sign')
print(string_to_sign)
print('\n')
print('Headers')
print(headers)
r = requests.get(request_url, headers=headers, verify=False)

print('Response code: %d\n' % r.status_code)
print(r.json())
