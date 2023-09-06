import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def extract_aws_info(event):
    arn = event.get('userIdentity', {}).get('arn')
    access_key_id = event.get('userIdentity', {}).get('accessKeyId')
    resource_name = event.get('userIdentity', {}).get('instanceId')
    source_ip = event.get('sourceIPAddress')
    username = event.get('userIdentity', {}).get('sessionContext', {}).get('sessionIssuer', {}).get('userName')
    event_name = event.get('eventName')
    user_agent = event.get('userAgent')

    return arn, access_key_id, resource_name, source_ip, username, event_name, user_agent


def extract_gcp_info(event):
    resource_name = event.get('protoPayload', {}).get('resourceName')
    source_ip = event.get('protoPayload', {}).get('requestMetadata', {}).get('callerIp')
    username = event.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail')
    event_name = event.get('protoPayload', {}).get('methodName')
    user_agent = event.get('protoPayload', {}).get('requestMetadata', {}).get('callerSuppliedUserAgent')

    return resource_name, source_ip, username, event_name, user_agent


def extract_event_info(event):
    if event.get('eventSource') and 'amazonaws.com' in event.get('eventSource'):
        return "AWS", extract_aws_info(event)
    elif event.get('logName', '').startswith('projects/'):
        return "GCP", extract_gcp_info(event)
    else:
        raise ValueError("Unknown event type")


def main():  # pragma: no cover
    try:
        args = demisto.args()
        json_data = args.get("json_data")
        data = json.loads(json_data) if isinstance(json_data, str) else json_data
        results = None

        # Extract information from AWS event
        event_type, event_info = extract_event_info(data)
        if event_type == "AWS":
            results = CommandResults(
                outputs_prefix='CloudIndicators',
                outputs={'arn': event_info[0], 'access_key_id': event_info[1], 'resource_name': event_info[2],
                         'source_ip': event_info[3], 'username': event_info[4], 'event_name': event_info[5],
                         'user_agent': event_info[6]}
            )

        # Extract information from GCP event
        elif event_type == "GCP":
            results = CommandResults(
                outputs_prefix='CloudIndicators',
                outputs={'resource_name': event_info[0], 'source_ip': event_info[1], 'username': event_info[2],
                         'event_name': event_info[3], 'user_agent': event_info[4]}
            )

        return_results(results)

    except Exception as e:
        return_error(f"An error occurred: {str(e)}")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
