import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
SecureHealthFirewallAPI to command and control SecureHealth devices
Copyright 2020 © Seth Piezas

AUTOMATION COMMAND TO
    email to IT to unprovision device
    create command to firewall to disable network for device
    create command to unprovision device, send device message and set timeout for device unprovision
    create command to firewall to block ioc
"""


class Client(BaseClient):

    def unprovision_location(self, location: str, email: str) -> str:
        results = self._http_request(
            method='GET',
            url_suffix='/api/unprovision_location',
            params={
                'location': location,
                'email': email
            }
        )
        data = results.get('data', [])
        return f'{data}'

    def unprovision_device_uuid(self, uuid: str) -> str:
        results = self._http_request(
            method='GET',
            url_suffix='/api/unprovision_device_uuid',
            params={
                'uuid': uuid
            }
        )
        data = results.get('data', [])
        return f'{data}'

    def notify_device_uuid(self, uuid: str) -> str:
        results = self._http_request(
            method='GET',
            url_suffix='/api/notify_device_uuid',
            params={
                'uuid': uuid
            }
        )
        data = results.get('data', [])
        return f'{data}'

    def block_ioc(self, ioc: str) -> str:
        results = self._http_request(
            method='GET',
            url_suffix='/api/block_ioc',
            params={
                'ioc': ioc
            }
        )
        data = results.get('data', [])
        return f'{data}'


args = demisto.args()
msgs = "# SECUREHEALTH FIREWALL ACTIONS\n"
try:
    headers = {
        'Authorization': f'Bearer 23498534098845934865984'
    }
    client = Client(
        base_url="https://us-central1-bynextmonday-4ffc3.cloudfunctions.net/securehealth/",
        headers=headers)
except:
    msgs += "error unknown"
if "unprovision_location" in args and "unprovision_email" in args:
    location = args["unprovision_location"]
    email = args["unprovision_email"]
    data = client.unprovision_location(location, email)
    msgs += f'{data}\n'
if "unprovision_device_uuid" in args:
    uuid = args["unprovision_device_uuid"]
    data = client.unprovision_device_uuid(uuid)
    msgs += f'{data}\n'
if "notify_device_uuid" in args:
    uuid = args["notify_device_uuid"]
    data = client.notify_device_uuid(uuid)
    msgs += f'{data}\n'
if "block_ioc" in args:
    ioc = args["block_ioc"]
    data = client.block_ioc(ioc)
    msgs += f'{data}\n'

demisto.log(msgs)
