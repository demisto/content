import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client:
    def __init__(self, base_url, verify, proxies):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies

    def http_request(self, method, url_suffix, data=None, headers=None):
        server = self.base_url + url_suffix
        res = requests.request(
            method,
            server,
            verify=self.verify,
            json=data,
            headers=headers,
            proxies=self.proxies
        )
        if res.status_code == 408:
            raise ValueError(f'Tesla is sleeping. Try to wake it up first!')
        elif res.status_code != 200:
            raise ValueError(f'Error in API call to Tesla {res.status_code}. Reason: {res.text}')
        try:
            return res.json()
        except Exception:
            raise ValueError(f"Failed to parse http response to JSON format. Original response body: \n{res.text}")


def results_return(titletoreturn, thingtoreturn, datapointtoreturnat):
    finaldata = {'Tesla': {datapointtoreturnat: thingtoreturn}}
    return demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': thingtoreturn,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(titletoreturn, thingtoreturn, removeNull=True),
        'EntryContext': finaldata
    })


def test_module(client, data):
    response = client.http_request('GET', '/api/1/products', data=None, headers=data)
    # test was successful
    if response['response']:
        return 'ok'
    else:
        return 'Failure, Response was' + str(response)


def get_data(client, data, suffix, title, repath):
    response = client.http_request('GET', suffix, data=None, headers=data)
    if response:
        results_return(title, response['response'], repath)
    else:
        return demisto.results("Error in command: " + suffix + " response from server was: " + str(response))


def post_data(client, data, suffix, title, repath):
    response = client.http_request('POST', suffix, data=None, headers=data)
    if response:
        results_return(title, response['response'], repath)
    else:
        return demisto.results("Error in command: " + suffix + " response from server was: " + str(response))


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    email = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = 'https://owner-api.teslamotors.com'
    basedata = {'email': email,
                'password': password,
                'client_secret': 'c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3',
                'client_id': '81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384',
                'grant_type': 'password'}
    headers = {'Content-Type': 'application/json'}

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(base_url, verify_certificate, proxy)
        response = client.http_request('POST', '/oauth/token', basedata, headers)
        newdata = {'Authorization': 'Bearer ' + response['access_token']}
        if demisto.command() == 'test-module':
            return_outputs(test_module(client, newdata))
        elif demisto.command() == 'tesla-list-all-vehicles':
            get_data(client, newdata, '/api/1/vehicles', 'All Vehicles', 'Vehicles')
        elif demisto.command() == 'tesla-get-vehicle-data':
            get_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/vehicle_data',
                     'Get Vehicle Data', 'VehicleData')
        elif demisto.command() == 'tesla-get-service-data':
            get_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/service_data',
                     'Get Service Data', 'ServiceData')
        elif demisto.command() == 'tesla-get-a-vehicle-details':
            get_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'],
                     'Get Vehicle Details', 'Vehicle')
        elif demisto.command() == 'tesla-get-charge-state':
            get_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/data_request/charge_state',
                     'Get Charge State', 'Charge')
        elif demisto.command() == 'tesla-get-climate-state':
            get_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/data_request/climate_state',
                     'Get Climate State', 'Climate')
        elif demisto.command() == 'tesla-get-drive-state':
            get_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/data_request/drive_state',
                     'Get Drive State', 'Drive')
        elif demisto.command() == 'tesla-get-gui-settings':
            get_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/data_request/gui_settings',
                     'Get GUI Settings', 'GUISettings')
        elif demisto.command() == 'tesla-wake-up':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/wake_up',
                      'Wake up Tesla', 'Wake-up')
        elif demisto.command() == 'tesla-honk-horn':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/command/honk_horn',
                      'HONK HONK', 'HonkHorn')
        elif demisto.command() == 'tesla-flash-lights':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/command/flash_lights',
                      'FLASH', 'FlashLights')
        elif demisto.command() == 'tesla-hvac-start':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/command/auto_conditioning_start',
                      'HVAC-Start', 'HVACStart')
        elif demisto.command() == 'tesla-hvac-stop':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/command/auto_conditioning_stop',
                      'HVAC-Stop', 'HVACStop')
        elif demisto.command() == 'tesla-charge-start':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/command/charge_start',
                      'Charge-start', 'ChargeStart')
        elif demisto.command() == 'tesla-charge-stop':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/command/charge_stop',
                      'Charge-start', 'ChargeStart')
        elif demisto.command() == 'tesla-unlock-doors':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/command/door_unlock',
                      'Unlock Doors', 'UnlockDoors')
        elif demisto.command() == 'tesla-lock-doors':
            post_data(client, newdata, '/api/1/vehicles/' + demisto.args()['id'] + '/command/door_lock',
                      'Lock Doors', 'LockDoors')
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
