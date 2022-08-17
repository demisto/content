from datetime import datetime, date
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

SERVICE = 'guardduty'

class AWSGuardDutyGetEvents(IntegrationGetEvents):
    client: AWSClient
    aws_gd_severity: str

    def __init__(self, client: AWSClient, options: IntegrationOptions):
        super().__init__(client=client, options=options)

    @staticmethod
    def get_last_run(events: list) -> dict:
        return {'from': events[-1]['__time__']}

    def call(self):
        try:
            events = []
            response = self.client.list_detectors()
            detector = response['DetectorIds']

            list_findings = self.client.list_findings(
                DetectorId=detector[0], FindingCriteria={
                    'Criterion': {
                        'service.archived': {'Eq': ['false', 'false']},
                        'severity': {'Gt': gd_severity_mapping(self.aws_gd_severity)}
                    }
                }
            )

            get_findings = self.client.get_findings(DetectorId=detector[0], FindingIds=list_findings['FindingIds'])

            for finding in get_findings['Findings']:
                event = parse_event_from_finding(finding)
                events.append(event)

            if events is not None:
                # Archive findings
                self.client.archive_findings(DetectorId=detector[0], FindingIds=list_findings['FindingIds'])

        except Exception as e:
            return raise_error(e)

    def _iter_events(self):
        self.client.prepare_request()
        response = self.call()
        events: list = response.json()
        events.sort(key=lambda k: k.get('__time__'))

        if not events:
            return []

        while True:
            yield events

            last = events[-1]
            self.client.set_request_filter(last['__time__'])
            self.client.prepare_request()
            response = self.call()

            events = response.json()
            events.sort(key=lambda k: k.get('__time__'))

            if not events:
                break


def main():
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('access_key')
    aws_secret_access_key = params.get('secret_key')
    aws_gd_severity = params.get('gs_severity', '')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout') or 1
    retries = params.get('retries') or 5

        try:
            options = IntegrationOptions.parse_obj(params)
            validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                            aws_secret_access_key)

            aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                                   aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate,
                                   timeout, retries)

            region = demisto.args().get('region')
            client = aws_client.aws_session(service=SERVICE, region=region)

            get_events = AWSGuardDutyGetEvents(client, options)

            # The command demisto.command() holds the command sent from the user.
            command = demisto.command()
            if command == 'test-module':
                get_events.options.limit = 1
                get_events.run()
                return_results('ok')

            elif command in ('aws-guard-duty-get-events', 'fetch-events'):
                events = get_events.run()

                if command == 'fetch-events':
                    send_events_to_xsiam(events, 'AWSGuardDuty', params.get('product'))
                    demisto.setLastRun(AWSGuardDutyGetEvents.get_last_run(events))

                elif command == 'aws-guard-duty-get-events':
                    command_results = CommandResults(
                        readable_output=tableToMarkdown('AWSGuardDuty Logs', events, headerTransform=pascalToSpace),
                        outputs_prefix='AWSGuardDuty.Logs',
                        outputs_key_field='event.eventid',  # TODO: check.
                        outputs=events,
                        raw_response=events,
                    )
                    return_results(command_results)

                    if should_push_events:
                        send_events_to_xsiam(events, 'AWSGuardDuty', params.get('product'))

        except Exception as e:
            return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
