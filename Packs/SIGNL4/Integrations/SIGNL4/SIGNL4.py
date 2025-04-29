from CommonServerPython import *


class Client(BaseClient):

    def send_signl4_alert(self, **kwargs):

        payload = {
            "Title": kwargs.get('json_data').get('title'),
            "Message": kwargs.get('json_data').get('message'),
            "X-S4-ExternalID": kwargs.get('json_data').get('s4_external_id'),
            "X-S4-Status": "new",
            "X-S4-Service": kwargs.get('json_data').get('s4_service'),
            "X-S4-Location": kwargs.get('json_data').get('s4_location'),
            "X-S4-AlertingScenario": kwargs.get('json_data').get('s4_alerting_scenario'),
            "X-S4-Filtering": kwargs.get('json_data').get('s4_filtering'),
            "X-S4-SourceSystem": "CortexXSOAR"
        }

        return self._http_request(method='POST', json_data=payload)

    def close_signl4_alert(self, **kwargs):

        payload = {
            "X-S4-ExternalID": kwargs.get('json_data').get('s4_external_id'),
            "X-S4-Status": "resolved",
            "X-S4-SourceSystem": "CortexXSOAR"
        }

        return self._http_request(method='POST', json_data=payload)


def test_module(client):
    """
    Performs basic get request to get item samples
    """
    payload = {
        "title": "Test Alert from Cortex XSOAR",
        "X-S4-SourceSystem": "CortexXSOAR"
    }
    result = client.send_signl4_alert(method='POST', json_data=payload)
    if 'eventId' in result:
        demisto.results("ok")
    else:
        error_code = result['error_code']
        description = result['description']
        demisto.results(f'{error_code} {description}')


def send_signl4_alert(client, **kwargs):
    result = client.send_signl4_alert(**kwargs)
    return result


def close_signl4_alert(client, **kwargs):
    result = client.close_signl4_alert(**kwargs)
    return result


def main():

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    secret = params.get('secret', {}).get('password')

    if not secret:
        raise DemistoException('Team or integration secret must be provided.')
    LOG(f'Command is {demisto.command()}')

    try:
        # Remove proxy if not set to true in params
        handle_proxy()
        proxy = params.get('proxy', False)

        client = Client(
            base_url='https://connect.signl4.com/webhook/{}'.format(secret),
            proxy=proxy
        )

        if command == 'test-module':
            test_module(client)
        elif command == 'signl4_alert':
            return_results(send_signl4_alert(client, method='POST', json_data=args))
        elif command == 'signl4_close':
            return_results(close_signl4_alert(client, method='POST', json_data=args))

    except Exception as ex:
        return_error(str(ex))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

