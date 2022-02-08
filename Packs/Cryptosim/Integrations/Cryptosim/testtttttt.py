from Cryptosim import Client
import base64

authorization ="admin:admin"
auth_byte= authorization.encode('utf-8')
base64_byte = base64.b64encode(auth_byte)
base64_auth = base64_byte.decode('utf-8')
authValue = "Basic " + base64_auth 

headers = {
    "Content-Type": "application/json",
    'Authorization': authValue
}
aa = Client.correlations(Client("http://172.17.6.41/api/service",headers=headers,verify=False, proxy=False))

print(aa.get("Data"))