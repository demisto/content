from CommonServerPython import *


class Client(BaseClient):

    def send_signl4_alert(self, json_data):

        payload = {
            "Title": json_data.get('title'),
            "Message": json_data.get('message'),
            "X-S4-ExternalID": json_data.get('s4_external_id'),
            "X-S4-Status": "new",
            "X-S4-Service": json_data.get('s4_service'),
            "X-S4-Location": json_data.get('s4_location'),
            "X-S4-AlertingScenario": json_data.get('s4_alerting_scenario'),
            "X-S4-Filtering": json_data.get('s4_filtering'),
            "X-S4-SourceSystem": "CortexXSOAR"
        }

        return self._http_request(method='POST', json_data=payload)

    def close_signl4_alert(self, json_data):

        payload = {
            "X-S4-ExternalID": json_data.get('s4_external_id'),
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
    result = client.send_signl4_alert(json_data=payload)
    if 'eventId' in result:
        demisto.results("ok")
    else:
        error_code = result['error_code']
        description = result['description']
        demisto.results(f'{error_code} {description}')


def send_signl4_alert(client, json_data):
    result = client.send_signl4_alert(json_data)

    r = CommandResults(
        outputs_prefix="SIGNL4.AlertCreated",
        outputs_key_field='eventId',
        outputs=result,
        readable_output=tableToMarkdown("SIGNL4 alert created", result),
        raw_response=result
    )
    return r


def close_signl4_alert(client, json_data):
    result = client.close_signl4_alert(json_data)
    
    r = CommandResults(
        outputs_prefix="SIGNL4.AlertClosed",
        outputs_key_field='eventId',
        outputs=result,
        readable_output=tableToMarkdown("SIGNL4 alert closed", result),
        raw_response=result
    )
    return r


def main():

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    secret = params.get('secret')

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
            return_results(send_signl4_alert(client, json_data=args))
        elif command == 'signl4_close_alert':
            return_results(close_signl4_alert(client, json_data=args))

    except Exception as ex:
        return_error(str(ex))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

