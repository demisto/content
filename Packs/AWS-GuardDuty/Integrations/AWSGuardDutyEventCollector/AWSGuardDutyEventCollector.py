import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from SiemApiModule import *  # noqa: E402
from AWSApiModule import *  # noqa: E402

import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

SERVICE = 'guardduty'


class AWSGuardDutyGetEvents(IntegrationGetEvents):

    def __init__(self, client, options, collect_from):
        super().__init__(options=options)
        self.aws_client = client
        self.collect_from = collect_from if collect_from else 0
        self.last_run_time = collect_from if collect_from else 0

    @staticmethod
    def get_last_run(events):
        return {'from': events[-1]['updatedAt']}

    def call(self):
        try:
            events = []
            response = self.aws_client.list_detectors()
            detector_ids = response['DetectorIds']

            for detector_id in detector_ids:
                list_findings = self.aws_client.list_findings(
                    DetectorId=detector_id, FindingCriteria={
                        'Criterion': {
                            'service.archived': {'Eq': ['false', 'false']},
                            'updatedAt': {'Gt': self.last_run_time}
                        }
                    },
                    SortCriteria={
                        'attributeName': 'updatedAt',
                        'orderBy': 'ASC'
                    }
                )

                get_findings = self.aws_client.get_findings(DetectorId=detector_id, FindingIds=list_findings['FindingIds'])

                for finding in get_findings['Findings']:
                    # event = parse_event_from_finding(finding)
                    events.append(finding)

                # TODO: if not archive, add checking mechanism for gte and last id.
                # if events is not None:
                    # Archive findings
                    # self.client.archive_findings(DetectorId=detector_id, FindingIds=list_findings['FindingIds'])

            return events

        except Exception as e:
            raise e

    def _iter_events(self):
        # self.client.prepare_request()
        response = self.call()
        events = response
        # events.sort(key=lambda k: k.get('updatedAt'))

        if not events:
            yield None

        else:
            while True:
                yield events

                last = events[-1]
                self.last_run_time = last['updatedAt']
                # self.client.prepare_request()
                response = self.call()

                events = response  # TODO: check this, it is fishy
                # events.sort(key=lambda k: k.get('updatedAt'))

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
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout') or 1
    retries = params.get('retries') or 5
    should_push_events = argToBoolean(demisto.args().get('should_push_events', 'false'))
    collect_from = params.get('collect_from')

    try:
        options = IntegrationOptions.parse_obj(params)
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate,
                               timeout, retries)

        region = demisto.args().get('region')
        client = aws_client.aws_session(service=SERVICE, region=region)

        get_events = AWSGuardDutyGetEvents(client, options, collect_from)

        # The command demisto.command() holds the command sent from the user.
        command = demisto.command()
        if command == 'test-module':
            get_events.options.limit = 1
            get_events.run()
            return_results('ok')

        elif command in ('aws-gd-get-events', 'fetch-events'):
            events = get_events.run()

            if command == 'fetch-events':
                send_events_to_xsiam(events, 'AWSGuardDuty', params.get('product'))
                demisto.setLastRun(AWSGuardDutyGetEvents.get_last_run(events))

            elif command == 'aws-gd-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('AWSGuardDuty Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='AWSGuardDuty.Logs',
                    outputs_key_field='event.id',  # TODO: check.
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
